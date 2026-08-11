// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/tun_device_packet_exchanger.h"

#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/uio.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/bonnet/mock_qbone_client_packet_exchanger.h"
#include "quiche/quic/qbone/bonnet/qbone_client_packet_exchanger.h"
#include "quiche/quic/qbone/mock_qbone_client.h"
#include "quiche/quic/qbone/platform/mock_kernel.h"
#include "quiche/quic/qbone/platform/mock_netlink.h"
#include "quiche/quic/qbone/platform/netlink_interface.h"
#include "quiche/quic/qbone/qbone_constants.h"
#include "quiche/common/quiche_endian.h"

namespace quic::test {
namespace {

const size_t kMtu = 1000;
const int kReadFd = 15;
const int kWriteFd = 16;

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::quiche::QuicheEndian;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Field;
using ::testing::Ne;
using ::testing::SizeIs;
using ::testing::StrEq;
using ::testing::StrictMock;

class TunDevicePacketExchangerTest : public QuicTest {
 protected:
  TunDevicePacketExchangerTest()
      : exchanger_(kMtu, &mock_kernel_, nullptr, &mock_visitor_, false,
                   absl::string_view()) {}

  ~TunDevicePacketExchangerTest() override = default;

  MockKernel mock_kernel_;
  StrictMock<MockQboneClientPacketExchanger::MockVisitor> mock_visitor_;
  StrictMock<MockQboneClient> mock_client_;
  TunDevicePacketExchanger exchanger_;
};

TEST_F(TunDevicePacketExchangerTest, WritePacketError) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) -> ssize_t {
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_THAT(reinterpret_cast<const char*>(iov[1].iov_base),
                    testing::StrEq("fake packet"));
        EXPECT_EQ(iov[1].iov_len, 11);
        errno = ECOMM;
        return -1;
      });

  EXPECT_CALL(mock_visitor_, OnWrite(StatusIs(Ne(absl::StatusCode::kOk))));
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, RestartExchanger) {
  exchanger_.Start(kReadFd, kWriteFd);
  exchanger_.Stop();

  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce(
          [&packet](int fd, const struct iovec* iov, int iovcnt) -> ssize_t {
            EXPECT_EQ(iov[0].iov_base, nullptr);
            EXPECT_EQ(iov[0].iov_len, 0);
            EXPECT_THAT(reinterpret_cast<const char*>(iov[1].iov_base),
                        StrEq(packet));
            EXPECT_EQ(iov[1].iov_len, packet.size());
            return packet.size();
          });

  EXPECT_CALL(
      mock_visitor_,
      OnWrite(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::WriteResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))))
      .Times(1);
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, WritePacketBlocked) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) -> ssize_t {
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_THAT(reinterpret_cast<const char*>(iov[1].iov_base),
                    testing::StrEq("fake packet"));
        EXPECT_EQ(iov[1].iov_len, 11);
        errno = EAGAIN;
        return -1;
      });

  EXPECT_CALL(mock_visitor_, OnWrite(StatusIs(Ne(absl::StatusCode::kOk))));
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, WritePacketSuccessfulWrite) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce(
          [&packet](int fd, const struct iovec* iov, int iovcnt) -> ssize_t {
            EXPECT_EQ(iov[0].iov_base, nullptr);
            EXPECT_EQ(iov[0].iov_len, 0);
            EXPECT_THAT(reinterpret_cast<const char*>(iov[1].iov_base),
                        StrEq(packet));
            EXPECT_EQ(iov[1].iov_len, packet.size());
            return packet.size();
          });

  EXPECT_CALL(
      mock_visitor_,
      OnWrite(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::WriteResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))))
      .Times(1);
  exchanger_.WritePacketToNetwork(packet.data(), packet.size());

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, TapWritePacketSuccessful) {
  StrictMock<MockKernel> mock_kernel;
  StrictMock<MockNetlink> mock_netlink;
  StrictMock<MockQboneClientPacketExchanger::MockVisitor> mock_visitor;
  TunDevicePacketExchanger tap_exchanger(kMtu, &mock_kernel, &mock_netlink,
                                         &mock_visitor, /*is_tap=*/true,
                                         "tap0");
  tap_exchanger.Start(kReadFd, kWriteFd);

  std::string packet = "fake packet";

  // Expectations on Netlink to get the hardware address when writing the
  // first packet
  EXPECT_CALL(mock_netlink, GetLinkInfo("tap0", _))
      .WillOnce([](const std::string& ifname,
                   NetlinkInterface::LinkInfo* link_info) -> bool {
        uint8_t mac[ETH_ALEN] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        memcpy(link_info->hardware_address, mac, ETH_ALEN);
        return true;
      });

  // iov[0] should contain the Ethernet header populated by InitializeEthHdr
  EXPECT_CALL(mock_kernel, writev(kWriteFd, _, 2))
      .WillOnce([&packet](int fd, const struct iovec* iov,
                          int iovcnt) -> ssize_t {
        EXPECT_NE(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, ETH_HLEN);

        const char* first_buffer = static_cast<const char*>(iov[0].iov_base);
        EXPECT_EQ(absl::string_view(first_buffer, ETH_ALEN),
                  absl::string_view("\x00\x11\x22\x33\x44\x55", ETH_ALEN));
        EXPECT_EQ(absl::string_view(first_buffer + ETH_ALEN, ETH_ALEN),
                  absl::string_view("\x00\x11\x22\x33\x44\x55", ETH_ALEN));

        uint16_t proto;
        memcpy(&proto, first_buffer + 2 * ETH_ALEN, 2);
        EXPECT_EQ(proto, QuicheEndian::HostToNet16(ETH_P_IPV6));

        EXPECT_EQ(absl::string_view(static_cast<const char*>(iov[1].iov_base),
                                    iov[1].iov_len),
                  "fake packet");
        return ETH_HLEN + packet.length();
      });

  EXPECT_CALL(
      mock_visitor,
      OnWrite(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::WriteResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))));

  tap_exchanger.WritePacketToNetwork(packet.data(), packet.size());

  tap_exchanger.Stop();
}

TEST_F(TunDevicePacketExchangerTest, ReadPacketError) {
  exchanger_.Start(kReadFd, kWriteFd);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        errno = ECOMM;
        return -1;
      });
  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(Ne(absl::StatusCode::kOk))));
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/1,
                                              &mock_client_),
            0);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, ReadPacketBlocked) {
  exchanger_.Start(kReadFd, kWriteFd);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        errno = EAGAIN;
        return -1;
      });
  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(Ne(absl::StatusCode::kOk))));
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/1,
                                              &mock_client_),
            0);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, ReadPacketSuccessfulRead) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet = "fake_packet";
  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([packet](int fd, const struct iovec* iov, int iovcnt) {
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(iov[1].iov_len, kMtu);
        memcpy(iov[1].iov_base, packet.data(), packet.size());
        return packet.size();
      });
  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(packet)));
  EXPECT_CALL(
      mock_visitor_,
      OnRead(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::ReadResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))));
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/1,
                                              &mock_client_),
            1);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, MultipleReadsMoreAvailableThanMax) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet1 = "fake_packet_1";
  std::string packet2 = "fake_packet_2";

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([packet1](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[1].iov_base, packet1.data(), packet1.size());
        return packet1.size();
      })
      .WillOnce([packet2](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[1].iov_base, packet2.data(), packet2.size());
        return packet2.size();
      });

  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(packet1)));
  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(packet2)));

  EXPECT_CALL(
      mock_visitor_,
      OnRead(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::ReadResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet1.data()),
                           packet1.size()))))));
  EXPECT_CALL(
      mock_visitor_,
      OnRead(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::ReadResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet2.data()),
                           packet2.size()))))));

  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/2,
                                              &mock_client_),
            2);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, MultipleReadsBlockedBeforeMax) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string packet1 = "fake_packet_1";

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([packet1](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[1].iov_base, packet1.data(), packet1.size());
        return packet1.size();
      })
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        errno = EAGAIN;
        return -1;
      });

  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(packet1)));

  // Expect no error callbacks from the blocked read. In this scenario, the
  // blocked socket is just a signal that there are no more packets to be read,
  // rather than an actual error.

  EXPECT_CALL(
      mock_visitor_,
      OnRead(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::ReadResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet1.data()),
                           packet1.size()))))));

  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/5,
                                              &mock_client_),
            1);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest, MultiReadInvalidSizeHuge) {
  exchanger_.Start(kReadFd, kWriteFd);

  std::string valid_packet = "valid_packet";

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        return kMtu + 1;  // Invalid size
      })
      .WillOnce([valid_packet](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[1].iov_base, valid_packet.data(), valid_packet.size());
        return valid_packet.size();
      });

  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(absl::StatusCode::kInternal)));

  // Expect subsequent packet to still be read and processed after the invalid
  // packet.
  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(valid_packet)));
  EXPECT_CALL(mock_visitor_,
              OnRead(IsOkAndHolds(ElementsAre(Field(
                  &QboneClientPacketExchanger::ReadResult::packet,
                  ElementsAreArray(
                      reinterpret_cast<const std::byte*>(valid_packet.data()),
                      valid_packet.size()))))));

  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/2,
                                              &mock_client_),
            2);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTest,
       ReadPacketBlockedOnFirstWithMaxMoreThanOne) {
  exchanger_.Start(kReadFd, kWriteFd);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        errno = EAGAIN;
        return -1;
      });
  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(Ne(absl::StatusCode::kOk))));
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/2,
                                              &mock_client_),
            0);

  exchanger_.Stop();
}

class TunDevicePacketExchangerTapTest : public QuicTest {
 protected:
  TunDevicePacketExchangerTapTest()
      : exchanger_(kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, true,
                   "tap0") {}

  ~TunDevicePacketExchangerTapTest() override = default;

  MockKernel mock_kernel_;
  StrictMock<MockNetlink> mock_netlink_;
  StrictMock<MockQboneClientPacketExchanger::MockVisitor> mock_visitor_;
  StrictMock<MockQboneClient> mock_client_;
  TunDevicePacketExchanger exchanger_;
};

TEST_F(TunDevicePacketExchangerTapTest, ReadPacketTapSuccess) {
  exchanger_.Start(kReadFd, kWriteFd);

  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = 59;    // No next header

  std::string l3_payload = "hello";
  std::string l3_packet =
      std::string(reinterpret_cast<char*>(&ip_hdr), sizeof(ip_hdr)) +
      l3_payload;

  ethhdr eth_hdr{};
  eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);

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
  EXPECT_CALL(
      mock_visitor_,
      OnRead(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::ReadResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(l3_packet.data()),
                           l3_packet.size()))))));
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/1,
                                              &mock_client_),
            1);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTapTest, ReadPacketTapInvalidL2) {
  exchanger_.Start(kReadFd, kWriteFd);

  ethhdr eth_hdr{};
  eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_ARP);  // Non-IPv6

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([eth_hdr](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[0].iov_base, &eth_hdr, ETH_HLEN);
        return ETH_HLEN + 10;  // Read some bytes
      });

  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(Ne(absl::StatusCode::kOk))));
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/1,
                                              &mock_client_),
            1);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTapTest, ReadPacketTapNeighborSolicitation) {
  exchanger_.Start(kReadFd, kWriteFd);

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
  eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);

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
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) -> ssize_t {
        return iov[0].iov_len + iov[1].iov_len;
      });
  EXPECT_CALL(mock_visitor_, OnWrite(IsOkAndHolds(SizeIs(1))));

  // OnReadFromNetworkReady should return 1 because packet was handled
  // internally (Neighbor Discovery) but still read from network.
  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/1,
                                              &mock_client_),
            1);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTapTest, MultiReadInvalidSizeShort) {
  exchanger_.Start(kReadFd, kWriteFd);

  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = 59;    // No next header

  std::string l3_payload = "hello";
  std::string valid_l3_packet =
      std::string(reinterpret_cast<char*>(&ip_hdr), sizeof(ip_hdr)) +
      l3_payload;

  ethhdr valid_eth_hdr{};
  valid_eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([](int fd, const struct iovec* iov, int iovcnt) {
        return ETH_HLEN - 1;  // Invalid size (too short to contain L3 packet)
      })
      .WillOnce([valid_eth_hdr, valid_l3_packet](
                    int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[0].iov_base, &valid_eth_hdr, ETH_HLEN);
        memcpy(iov[1].iov_base, valid_l3_packet.data(), valid_l3_packet.size());
        return ETH_HLEN + valid_l3_packet.size();
      });

  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(absl::StatusCode::kInternal)));

  // Expect subsequent packet to still be read and processed after the invalid
  // packet.
  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(valid_l3_packet)));
  EXPECT_CALL(mock_visitor_,
              OnRead(IsOkAndHolds(ElementsAre(
                  Field(&QboneClientPacketExchanger::ReadResult::packet,
                        ElementsAreArray(reinterpret_cast<const std::byte*>(
                                             valid_l3_packet.data()),
                                         valid_l3_packet.size()))))));

  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/2,
                                              &mock_client_),
            2);

  exchanger_.Stop();
}

TEST_F(TunDevicePacketExchangerTapTest, MultiReadInvalidL2) {
  exchanger_.Start(kReadFd, kWriteFd);

  ethhdr invalid_eth_hdr{};
  invalid_eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_ARP);  // Non-IPv6

  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = 59;    // No next header

  std::string l3_payload = "hello";
  std::string valid_l3_packet =
      std::string(reinterpret_cast<char*>(&ip_hdr), sizeof(ip_hdr)) +
      l3_payload;

  ethhdr valid_eth_hdr{};
  valid_eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([invalid_eth_hdr](int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[0].iov_base, &invalid_eth_hdr, ETH_HLEN);
        return ETH_HLEN + 10;
      })
      .WillOnce([valid_eth_hdr, valid_l3_packet](
                    int fd, const struct iovec* iov, int iovcnt) {
        memcpy(iov[0].iov_base, &valid_eth_hdr, ETH_HLEN);
        memcpy(iov[1].iov_base, valid_l3_packet.data(), valid_l3_packet.size());
        return ETH_HLEN + valid_l3_packet.size();
      });

  EXPECT_CALL(mock_visitor_,
              OnRead(StatusIs(absl::StatusCode::kInvalidArgument)));

  // Expect subsequent packet to still be read and processed after the invalid
  // packet.
  EXPECT_CALL(mock_client_, ProcessPacketFromNetwork(StrEq(valid_l3_packet)));
  EXPECT_CALL(mock_visitor_,
              OnRead(IsOkAndHolds(ElementsAre(
                  Field(&QboneClientPacketExchanger::ReadResult::packet,
                        ElementsAreArray(reinterpret_cast<const std::byte*>(
                                             valid_l3_packet.data()),
                                         valid_l3_packet.size()))))));

  EXPECT_EQ(exchanger_.OnReadFromNetworkReady(/*max_packets_to_read=*/2,
                                              &mock_client_),
            2);

  exchanger_.Stop();
}

}  // namespace
}  // namespace quic::test
