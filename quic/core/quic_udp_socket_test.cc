// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/quic_udp_socket.h"

#include "net/third_party/quiche/src/quic/core/quic_constants.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"

namespace quic {
namespace test {

class QuicUdpSocketTest : public QuicTest {
 protected:
  void SetUp() override {
    // Try creating AF_INET socket, if it fails because of unsupported address
    // family then tests are being run under IPv6-only environment, initialize
    // address family to use for running the test under as AF_INET6 otherwise
    // initialize it as AF_INET.
    address_family_ = AF_INET;
    fd_client_ =
        api_.Create(address_family_,
                    /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
                    /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
    if (fd_client_ == kQuicInvalidSocketFd) {
      address_family_ = AF_INET6;
      fd_client_ =
          api_.Create(address_family_,
                      /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
                      /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
    }
    ASSERT_NE(fd_client_, kQuicInvalidSocketFd);

    fd_server_ =
        api_.Create(address_family_,
                    /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
                    /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
    ASSERT_NE(fd_server_, kQuicInvalidSocketFd);

    ASSERT_TRUE(
        api_.Bind(fd_server_, QuicSocketAddress(Loopback(), /*port=*/0)));

    ASSERT_EQ(0, server_address_.FromSocket(fd_server_));

    QUIC_LOG(INFO) << "Testing under IP"
                   << std::string((address_family_ == AF_INET) ? "v4" : "v6");
  }

  ~QuicUdpSocketTest() {
    api_.Destroy(fd_client_);
    api_.Destroy(fd_server_);
  }

  QuicIpAddress Loopback() const {
    return (address_family_ == AF_INET) ? QuicIpAddress::Loopback4()
                                        : QuicIpAddress::Loopback6();
  }

  // Client sends the first |packet_size| bytes in |client_packet_buffer_| to
  // server.
  WriteResult SendPacketFromClient(size_t packet_size) {
    EXPECT_LE(packet_size, sizeof(client_packet_buffer_));
    QuicUdpPacketInfo packet_info;
    packet_info.SetPeerAddress(server_address_);
    return api_.WritePacket(fd_client_, client_packet_buffer_, packet_size,
                            packet_info);
  }

  WriteResult SendPacketFromClientWithTtl(size_t packet_size, int ttl) {
    EXPECT_LE(packet_size, sizeof(client_packet_buffer_));
    QuicUdpPacketInfo packet_info;
    packet_info.SetPeerAddress(server_address_);
    packet_info.SetTtl(ttl);
    return api_.WritePacket(fd_client_, client_packet_buffer_, packet_size,
                            packet_info);
  }

  // Server waits for an incoming packet and reads it into
  // |server_packet_buffer_|.
  QuicUdpSocketApi::ReadPacketResult ReadPacketFromServer(
      BitMask64 packet_info_interested) {
    EXPECT_TRUE(
        api_.WaitUntilReadable(fd_server_, QuicTime::Delta::FromSeconds(5)));
    memset(server_packet_buffer_, 0, sizeof(server_packet_buffer_));
    QuicUdpSocketApi::ReadPacketResult result;
    result.packet_buffer = {server_packet_buffer_,
                            sizeof(server_packet_buffer_)};
    result.control_buffer = {server_control_buffer_,
                             sizeof(server_control_buffer_)};
    api_.ReadPacket(fd_server_, packet_info_interested, &result);
    return result;
  }

  int ComparePacketBuffers(size_t packet_size) {
    return memcmp(client_packet_buffer_, server_packet_buffer_, packet_size);
  }

  QuicUdpSocketApi api_;
  QuicUdpSocketFd fd_client_;
  QuicUdpSocketFd fd_server_;
  QuicSocketAddress server_address_;
  int address_family_;
  char client_packet_buffer_[kEthernetMTU] = {0};
  char server_packet_buffer_[kDefaultMaxPacketSize] = {0};
  char server_control_buffer_[512] = {0};
};

TEST_F(QuicUdpSocketTest, ReadPacketOnly) {
  const size_t kPacketSize = 512;
  memset(client_packet_buffer_, '-', kPacketSize);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));

  QuicUdpSocketApi::ReadPacketResult read_result =
      ReadPacketFromServer(/*packet_info_interested=*/BitMask64());
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
}

TEST_F(QuicUdpSocketTest, ReadTruncated) {
  const size_t kPacketSize = kDefaultMaxPacketSize + 1;
  memset(client_packet_buffer_, '*', kPacketSize);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));

  QuicUdpSocketApi::ReadPacketResult read_result =
      ReadPacketFromServer(/*packet_info_interested=*/BitMask64());
  ASSERT_FALSE(read_result.ok);
}

TEST_F(QuicUdpSocketTest, ReadDroppedPackets) {
  const size_t kPacketSize = kDefaultMaxPacketSize;
  memset(client_packet_buffer_, '-', kPacketSize);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));

  // Read the first packet without enabling DROPPED_PACKETS.
  QuicUdpSocketApi::ReadPacketResult read_result =
      ReadPacketFromServer(BitMask64(QuicUdpPacketInfoBit::DROPPED_PACKETS));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  ASSERT_FALSE(
      read_result.packet_info.HasValue(QuicUdpPacketInfoBit::DROPPED_PACKETS));

  // Enable DROPPED_PACKETS and read the second packet.
  if (!api_.EnableDroppedPacketCount(fd_server_)) {
    QUIC_LOG(INFO) << "DROPPED_PACKETS is not supported";
    return;
  }
  read_result =
      ReadPacketFromServer(BitMask64(QuicUdpPacketInfoBit::DROPPED_PACKETS));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  if (read_result.packet_info.HasValue(QuicUdpPacketInfoBit::DROPPED_PACKETS)) {
    EXPECT_EQ(0u, read_result.packet_info.dropped_packets());
  }
}

TEST_F(QuicUdpSocketTest, ReadSelfIp) {
  const QuicUdpPacketInfoBit self_ip_bit =
      (address_family_ == AF_INET) ? QuicUdpPacketInfoBit::V4_SELF_IP
                                   : QuicUdpPacketInfoBit::V6_SELF_IP;

  const size_t kPacketSize = 512;
  memset(client_packet_buffer_, '&', kPacketSize);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));

  QuicUdpSocketApi::ReadPacketResult read_result =
      ReadPacketFromServer(BitMask64(self_ip_bit));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  ASSERT_TRUE(read_result.packet_info.HasValue(self_ip_bit));
  EXPECT_EQ(Loopback(), (address_family_ == AF_INET)
                            ? read_result.packet_info.self_v4_ip()
                            : read_result.packet_info.self_v6_ip());
}

TEST_F(QuicUdpSocketTest, ReadReceiveTimestamp) {
  const size_t kPacketSize = kDefaultMaxPacketSize;
  memset(client_packet_buffer_, '-', kPacketSize);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClient(kPacketSize));

  // Read the first packet without enabling RECV_TIMESTAMP.
  QuicUdpSocketApi::ReadPacketResult read_result =
      ReadPacketFromServer(BitMask64(QuicUdpPacketInfoBit::RECV_TIMESTAMP));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  ASSERT_FALSE(
      read_result.packet_info.HasValue(QuicUdpPacketInfoBit::RECV_TIMESTAMP));

  // Enable RECV_TIMESTAMP and read the second packet.
  if (!api_.EnableReceiveTimestamp(fd_server_)) {
    QUIC_LOG(INFO) << "RECV_TIMESTAMP is not supported";
    return;
  }
  read_result =
      ReadPacketFromServer(BitMask64(QuicUdpPacketInfoBit::RECV_TIMESTAMP));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  ASSERT_TRUE(
      read_result.packet_info.HasValue(QuicUdpPacketInfoBit::RECV_TIMESTAMP));
  QuicWallTime recv_timestamp = read_result.packet_info.receive_timestamp();
  // 1577836800 is the unix seconds for 2020-01-01
  EXPECT_TRUE(
      QuicWallTime::FromUNIXSeconds(1577836800).IsBefore(recv_timestamp));
}

TEST_F(QuicUdpSocketTest, Ttl) {
  const size_t kPacketSize = 512;
  memset(client_packet_buffer_, '$', kPacketSize);
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClientWithTtl(kPacketSize, 13));
  ASSERT_EQ(WriteResult(WRITE_STATUS_OK, kPacketSize),
            SendPacketFromClientWithTtl(kPacketSize, 13));

  // Read the first packet without enabling ttl reporting.
  QuicUdpSocketApi::ReadPacketResult read_result =
      ReadPacketFromServer(BitMask64(QuicUdpPacketInfoBit::TTL));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  ASSERT_FALSE(read_result.packet_info.HasValue(QuicUdpPacketInfoBit::TTL));

  // Enable ttl reporting and read the second packet.
  if (!((address_family_ == AF_INET)
            ? api_.EnableReceiveTtlForV4(fd_server_)
            : api_.EnableReceiveTtlForV6(fd_server_))) {
    QUIC_LOG(INFO) << "TTL is not supported for address family "
                   << address_family_;
    return;
  }

  read_result = ReadPacketFromServer(BitMask64(QuicUdpPacketInfoBit::TTL));
  ASSERT_TRUE(read_result.ok);
  ASSERT_EQ(kPacketSize, read_result.packet_buffer.buffer_len);
  ASSERT_EQ(0, ComparePacketBuffers(kPacketSize));
  ASSERT_TRUE(read_result.packet_info.HasValue(QuicUdpPacketInfoBit::TTL));
  EXPECT_EQ(13, read_result.packet_info.ttl());
}

}  // namespace test
}  // namespace quic
