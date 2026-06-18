// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/tun_device_packet_exchanger.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/uio.h>

#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/bonnet/mock_packet_exchanger_stats_interface.h"
#include "quiche/quic/qbone/mock_qbone_client.h"
#include "quiche/quic/qbone/platform/mock_kernel.h"
#include "quiche/quic/qbone/platform/mock_netlink.h"
#include "quiche/quic/qbone/qbone_constants.h"

namespace quic::test {
namespace {

const size_t kMtu = 1000;
const int kReadFd = 15;
const int kWriteFd = 16;

using ::testing::_;
using ::testing::StrEq;
using ::testing::StrictMock;

class MockVisitor : public QbonePacketExchanger::Visitor {
 public:
  MOCK_METHOD(void, OnReadError, (const std::string&), (override));
  MOCK_METHOD(void, OnWriteError, (const std::string&), (override));
  MOCK_METHOD(absl::Status, OnWrite, (absl::string_view), (override));
};

class TunDevicePacketExchangerTest : public QuicTest {
 protected:
  TunDevicePacketExchangerTest()
      : exchanger_(kMtu, &mock_kernel_, nullptr, &mock_visitor_, false,
                   &mock_stats_, absl::string_view()) {
    exchanger_.set_read_file_descriptor(kReadFd);
    exchanger_.set_write_file_descriptor(kWriteFd);
  }

  ~TunDevicePacketExchangerTest() override = default;

  MockKernel mock_kernel_;
  StrictMock<MockVisitor> mock_visitor_;
  StrictMock<MockQboneClient> mock_client_;
  StrictMock<MockPacketExchangerStatsInterface> mock_stats_;
  TunDevicePacketExchanger exchanger_;
};

TEST_F(TunDevicePacketExchangerTest, WritePacketReturnsFalseOnError) {
  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, write(kWriteFd, _, packet.size()))
      .WillOnce([](int fd, const void* buf, size_t count) {
        errno = ECOMM;
        return -1;
      });

  EXPECT_CALL(mock_visitor_, OnWriteError(_));
  EXPECT_CALL(mock_visitor_, OnWrite(StrEq(packet))).Times(1);
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());
}

TEST_F(TunDevicePacketExchangerTest,
       WritePacketReturnFalseAndBlockedOnBlockedTunnel) {
  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, write(kWriteFd, _, packet.size()))
      .WillOnce([](int fd, const void* buf, size_t count) {
        errno = EAGAIN;
        return -1;
      });

  EXPECT_CALL(mock_stats_, OnWriteError(_)).Times(1);
  EXPECT_CALL(mock_visitor_, OnWrite(StrEq(packet))).Times(1);
  EXPECT_CALL(mock_visitor_, OnWriteError(_)).Times(1);
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());
}

TEST_F(TunDevicePacketExchangerTest, WritePacketReturnsTrueOnSuccessfulWrite) {
  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, write(kWriteFd, _, packet.size()))
      .WillOnce([packet](int fd, const void* buf, size_t count) {
        EXPECT_THAT(reinterpret_cast<const char*>(buf), StrEq(packet));
        return count;
      });

  EXPECT_CALL(mock_stats_, OnPacketWritten(_, _)).Times(1);
  EXPECT_CALL(mock_visitor_, OnWrite(StrEq(packet))).Times(1);
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());
}

TEST_F(TunDevicePacketExchangerTest, ReadPacketReturnsNullOnError) {
  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        errno = ECOMM;
        return -1;
      });
  EXPECT_CALL(mock_visitor_, OnReadError(_));
  exchanger_.ReadAndDeliverPacket(&mock_client_);
}

TEST_F(TunDevicePacketExchangerTest, ReadPacketReturnsNullOnBlockedRead) {
  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        errno = EAGAIN;
        return -1;
      });
  EXPECT_CALL(mock_stats_, OnReadError(_)).Times(1);
  EXPECT_CALL(mock_visitor_, OnReadError(_)).Times(1);
  EXPECT_FALSE(exchanger_.ReadAndDeliverPacket(&mock_client_));
}

TEST_F(TunDevicePacketExchangerTest,
       ReadPacketReturnsThePacketOnSuccessfulRead) {
  std::string packet = "fake_packet";
  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([packet](int fd, const struct iovec* iov, int iovcnt) {
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(iov[1].iov_len, kMtu);
        memcpy(iov[1].iov_base, packet.data(), packet.size());
        return packet.size();
      });
  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(packet)));
  EXPECT_CALL(mock_stats_, OnPacketRead(_, _)).Times(1);
  EXPECT_TRUE(exchanger_.ReadAndDeliverPacket(&mock_client_));
}

class TunDevicePacketExchangerTapTest : public QuicTest {
 protected:
  TunDevicePacketExchangerTapTest()
      : exchanger_(kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, true,
                   &mock_stats_, "tap0") {
    exchanger_.set_read_file_descriptor(kReadFd);
    exchanger_.set_write_file_descriptor(kWriteFd);
  }

  ~TunDevicePacketExchangerTapTest() override = default;

  MockKernel mock_kernel_;
  StrictMock<MockNetlink> mock_netlink_;
  StrictMock<MockVisitor> mock_visitor_;
  StrictMock<MockQboneClient> mock_client_;
  StrictMock<MockPacketExchangerStatsInterface> mock_stats_;
  TunDevicePacketExchanger exchanger_;
};

TEST_F(TunDevicePacketExchangerTapTest, ReadPacketTapSuccess) {
  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = 59;    // No next header

  std::string l3_payload = "hello";
  std::string l3_packet =
      std::string(reinterpret_cast<char*>(&ip_hdr), sizeof(ip_hdr)) +
      l3_payload;

  ethhdr eth_hdr{};
  eth_hdr.h_proto = absl::ghtons(ETH_P_IPV6);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce(
          [eth_hdr, l3_packet](int fd, const struct iovec* iov, int iovcnt) {
            EXPECT_EQ(iov[0].iov_len, ETH_HLEN);
            EXPECT_EQ(iov[1].iov_len, kMtu);
            memcpy(iov[0].iov_base, &eth_hdr, ETH_HLEN);
            memcpy(iov[1].iov_base, l3_packet.data(), l3_packet.size());
            return ETH_HLEN + l3_packet.size();
          });

  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(l3_packet)));
  EXPECT_CALL(mock_stats_, OnPacketRead(l3_packet.size(), _)).Times(1);
  EXPECT_TRUE(exchanger_.ReadAndDeliverPacket(&mock_client_));
}

TEST_F(TunDevicePacketExchangerTapTest, ReadPacketTapInvalidL2) {
  ethhdr eth_hdr{};
  eth_hdr.h_proto = absl::ghtons(ETH_P_ARP);  // Non-IPv6

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([eth_hdr](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[0].iov_base, &eth_hdr, ETH_HLEN);
        return ETH_HLEN + 10;  // Read some bytes
      });

  EXPECT_CALL(mock_visitor_, OnReadError(""));
  EXPECT_FALSE(exchanger_.ReadAndDeliverPacket(&mock_client_));
}

TEST_F(TunDevicePacketExchangerTapTest, ReadPacketTapNeighborSolicitation) {
  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = IPPROTO_ICMPV6;
  inet_pton(AF_INET6, "fe80::2", &ip_hdr.ip6_src);
  inet_pton(AF_INET6, "fe80::1", &ip_hdr.ip6_dst);

  icmp6_hdr icmp_hdr{};
  icmp_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;

  in6_addr target_address = QboneConstants::GatewayAddress()->GetIPv6();

  std::string l3_packet =
      std::string(reinterpret_cast<char*>(&ip_hdr), sizeof(ip_hdr)) +
      std::string(reinterpret_cast<char*>(&icmp_hdr), sizeof(icmp_hdr)) +
      std::string(reinterpret_cast<char*>(&target_address),
                  sizeof(target_address));

  ethhdr eth_hdr{};
  eth_hdr.h_proto = absl::ghtons(ETH_P_IPV6);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce(
          [eth_hdr, l3_packet](int fd, const struct iovec* iov, int iovcnt) {
            memcpy(iov[0].iov_base, &eth_hdr, ETH_HLEN);
            memcpy(iov[1].iov_base, l3_packet.data(), l3_packet.size());
            return ETH_HLEN + l3_packet.size();
          });

  // Expect GetLinkInfo to populate ethhdr on writing neighbor solicit response.
  EXPECT_CALL(mock_netlink_, GetLinkInfo("tap0", _))
      .WillOnce(
          [](const std::string& ifname, NetlinkInterface::LinkInfo* link_info) {
            memset(link_info->hardware_address, 0x12, ETH_ALEN);
            return true;
          });

  // Expect neighbor solicitation response to be written out.
  EXPECT_CALL(mock_kernel_, write(kWriteFd, _, _))
      .WillOnce([](int fd, const void* buf, size_t count) { return count; });
  EXPECT_CALL(mock_stats_, OnPacketWritten(_, _)).Times(1);

  // ReadAndDeliverPacket should return false because packet was handled
  // internally (Neighbor Discovery).
  EXPECT_CALL(mock_visitor_, OnReadError(""));
  EXPECT_FALSE(exchanger_.ReadAndDeliverPacket(&mock_client_));
}

}  // namespace
}  // namespace quic::test
