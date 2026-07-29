// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/tun_device_packet_exchanger.h"

#include <netinet/icmp6.h>
#include <netinet/ip6.h>
#include <sys/uio.h>

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/macros.h"
#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/time/clock.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/qbone/platform/icmp_packet.h"
#include "quiche/quic/qbone/platform/kernel_interface.h"
#include "quiche/quic/qbone/platform/netlink_interface.h"
#include "quiche/quic/qbone/qbone_client_interface.h"
#include "quiche/quic/qbone/qbone_constants.h"
#include "quiche/common/quiche_endian.h"

namespace quic {

using ::quiche::QuicheEndian;

TunDevicePacketExchanger::TunDevicePacketExchanger(
    size_t mtu, KernelInterface* kernel, NetlinkInterface* netlink,
    Visitor* absl_nullable visitor, bool is_tap, StatsInterface* stats,
    absl::string_view ifname)
    : kernel_(kernel),
      netlink_(netlink),
      visitor_(visitor),
      ifname_(ifname),
      // Reading on a TUN device returns a packet at a time. If the packet is
      // longer than the buffer, it's truncated.
      read_buffer_(mtu),
      is_tap_(is_tap),
      stats_(stats) {}

bool TunDevicePacketExchanger::ReadAndDeliverPacket(
    QboneClientInterface* qbone_client) {
  if (read_fd_ < 0) {
    absl::Status error = absl::InternalError(
        absl::StrCat("Invalid file descriptor of the TUN device: ", read_fd_));
    QUIC_LOG_EVERY_N_SEC(ERROR, 60) << "Packet read failed: " << error;
    stats_->OnReadError(absl::StrCat(absl::StatusCodeToString(error.code()),
                                     ": ", error.message()));
    if (visitor_) {
      visitor_->OnRead(std::move(error));
    }
    return false;
  }

  ethhdr eth_header;
  struct iovec iov[2];

  iov[0].iov_base = is_tap_ ? &eth_header : nullptr;
  iov[0].iov_len = is_tap_ ? ETH_HLEN : 0;
  iov[1].iov_base = read_buffer_.data();
  iov[1].iov_len = read_buffer_.size();

  absl::Status status = absl::OkStatus();
  absl::Time start = absl::Now();
  int result = kernel_->readv(read_fd_, iov, ABSL_ARRAYSIZE(iov));
  if (result < 0) {
    status = absl::ErrnoToStatus(errno, "Read from the TUN device failed.");
  } else if (result == 0) {
    // Note that 0 means end of file, but we're talking about a TUN device -
    // there is no end of file. Therefore 0 also indicates error.
    status = absl::InternalError(
        "Read from the TUN device returned unexpected 0 (EOF).");
  }
  absl::Duration latency = std::max(absl::Now() - start, absl::ZeroDuration());

  if (!status.ok()) {
    QUIC_LOG_EVERY_N_SEC(ERROR, 60) << "Packet read failed: " << status;
    stats_->OnReadError(absl::StrCat(absl::StatusCodeToString(status.code()),
                                     ": ", status.message()));
    if (visitor_) {
      visitor_->OnRead(std::move(status));
    }
    return false;
  }

  int l3_packet_size = is_tap_ ? result - ETH_HLEN : result;
  if (l3_packet_size <= 0 || l3_packet_size > read_buffer_.size()) {
    absl::Status error =
        absl::InternalError(absl::StrCat("Invalid packet size."));
    QUIC_LOG_EVERY_N_SEC(ERROR, 60) << "Packet read failed: " << error;
    stats_->OnReadError(absl::StrCat(absl::StatusCodeToString(error.code()),
                                     ": ", error.message()));
    if (visitor_) {
      visitor_->OnRead(std::move(error));
    }
    return false;
  }
  absl::Span<const std::byte> l3_packet =
      absl::MakeSpan(read_buffer_.data(), l3_packet_size);

  if (is_tap_) {
    switch (ValidateL2Headers(eth_header, l3_packet)) {
      case L2ValidationResult::kInvalid: {
        absl::Status error = absl::InvalidArgumentError("Invalid L2 headers.");
        stats_->OnReadError(absl::StrCat(absl::StatusCodeToString(error.code()),
                                         ": ", error.message()));
        if (visitor_) {
          visitor_->OnRead(std::move(error));
        }
        return false;
      }
      case L2ValidationResult::kValidLinkLocal:
        // TODO(b/535980431): This returns false to match the behavior of a
        // previous implementation because no packet is forwarded to the tunnel,
        // but consider changing this to true. A link-local packet does not mean
        // there are no more packets to read from the TUN device.
        return false;
      case L2ValidationResult::kValidNormal:
        // Packet is valid and should be forwarded to the tunnel. Fall through
        // to normal processing.
        break;
    }
  }

  if (visitor_) {
    visitor_->OnRead(std::vector<ReadResult>{
        ReadResult{.packet = l3_packet, .latency = latency}});
  }
  stats_->OnPacketRead(l3_packet.size(), latency);
  qbone_client->ProcessPacketFromNetwork(absl::string_view(
      reinterpret_cast<const char*>(l3_packet.data()), l3_packet.size()));
  return true;
}

void TunDevicePacketExchanger::WritePacketToNetwork(const char* packet,
                                                    size_t size) {
  if (write_fd_ < 0) {
    absl::Status error = absl::InternalError(
        absl::StrCat("Invalid file descriptor of the TUN device: ", write_fd_));
    QUIC_LOG_EVERY_N_SEC(ERROR, 60) << "Packet write failed: " << error;
    stats_->OnWriteError(absl::StrCat(absl::StatusCodeToString(error.code()),
                                      ": ", error.message()));
    if (visitor_) {
      visitor_->OnWrite(std::move(error));
    }
    return;
  }

  if (is_tap_ && !eth_hdr_initialized_) {
    InitializeEthHdr();
  }
  struct iovec iov[2];
  iov[0].iov_base = is_tap_ ? &eth_hdr_ : nullptr;
  iov[0].iov_len = is_tap_ ? ETH_HLEN : 0;
  iov[1].iov_base = const_cast<char*>(packet);
  iov[1].iov_len = size;

  absl::Status status = absl::OkStatus();
  absl::Time start = absl::Now();
  int result = kernel_->writev(write_fd_, iov, ABSL_ARRAYSIZE(iov));
  if (result < 0) {
    status = absl::ErrnoToStatus(errno, "Write to the TUN device failed.");
  }
  absl::Duration latency = std::max(absl::Now() - start, absl::ZeroDuration());

  if (!status.ok()) {
    QUIC_LOG_EVERY_N_SEC(ERROR, 60) << "Packet write failed: " << status;
    stats_->OnWriteError(absl::StrCat(absl::StatusCodeToString(status.code()),
                                      ": ", status.message()));
    if (visitor_) {
      visitor_->OnWrite(std::move(status));
    }
    return;
  }

  if (visitor_) {
    visitor_->OnWrite(std::vector<WriteResult>{WriteResult{
        .packet =
            absl::MakeSpan(reinterpret_cast<const std::byte*>(packet), size),
        .latency = latency}});
  }
  stats_->OnPacketWritten(result, latency);
}

void TunDevicePacketExchanger::set_read_file_descriptor(int fd) {
  read_fd_ = fd;
}
void TunDevicePacketExchanger::set_write_file_descriptor(int fd) {
  write_fd_ = fd;
}

const TunDevicePacketExchanger::StatsInterface*
TunDevicePacketExchanger::stats_interface() const {
  return stats_;
}

void TunDevicePacketExchanger::InitializeEthHdr() {
  if (!eth_hdr_initialized_) {
    NetlinkInterface::LinkInfo link_info{};
    if (netlink_->GetLinkInfo(ifname_, &link_info)) {
      // Set src & dst to my own address
      memcpy(&eth_hdr_.h_dest, link_info.hardware_address, ETH_ALEN);
      memcpy(&eth_hdr_.h_source, link_info.hardware_address, ETH_ALEN);
      // Assume ipv6 for now
      // TODO(b/195113643): Support additional protocols.
      eth_hdr_.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);
      eth_hdr_initialized_ = true;
    } else {
      QUIC_LOG_EVERY_N_SEC(ERROR, 30)
          << "Unable to get link info for: " << ifname_;
    }
  }
}

TunDevicePacketExchanger::L2ValidationResult
TunDevicePacketExchanger::ValidateL2Headers(
    const ethhdr& eth_header, absl::Span<const std::byte> packet) {
  if (eth_header.h_proto != QuicheEndian::HostToNet16(ETH_P_IPV6)) {
    return L2ValidationResult::kInvalid;
  }
  constexpr auto kIp6PrefixLen = sizeof(ip6_hdr);
  constexpr auto kIcmp6PrefixLen = kIp6PrefixLen + sizeof(icmp6_hdr);
  if (packet.length() < kIp6PrefixLen) {
    // Packet is too short to be ipv6. Drop it.
    return L2ValidationResult::kInvalid;
  }
  auto* ip_hdr = reinterpret_cast<const ip6_hdr*>(packet.data());
  const bool is_icmp = ip_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_ICMPV6;

  bool is_neighbor_solicit = false;
  if (is_icmp) {
    if (packet.length() < kIcmp6PrefixLen) {
      // Packet is too short to be icmp6. Drop it.
      return L2ValidationResult::kInvalid;
    }
    is_neighbor_solicit =
        reinterpret_cast<const icmp6_hdr*>(packet.subspan(kIp6PrefixLen).data())
            ->icmp6_type == ND_NEIGHBOR_SOLICIT;
  }

  if (is_neighbor_solicit) {
    // We need the local interface MAC address to respond.
    if (!eth_hdr_initialized_) {
      InitializeEthHdr();
    }
    // If we've received a neighbor solicitation, craft an advertisement to
    // respond with and write it back to the local interface.
    absl::Span<const std::byte> icmp6_payload = packet.subspan(kIcmp6PrefixLen);

    if (icmp6_payload.size() < sizeof(in6_addr)) {
      // Packet is too short to contain a valid ICMPv6 payload. Drop it.
      return L2ValidationResult::kInvalid;
    }

    QuicIpAddress target_address(
        *reinterpret_cast<const in6_addr*>(icmp6_payload.data()));
    if (target_address != *QboneConstants::GatewayAddress()) {
      // Only respond to solicitations for our gateway address
      return L2ValidationResult::kValidLinkLocal;
    }

    // Neighbor Advertisement crafted per:
    // https://datatracker.ietf.org/doc/html/rfc4861#section-4.4
    //
    // Using the Target link-layer address option defined at:
    // https://datatracker.ietf.org/doc/html/rfc4861#section-4.6.1
    constexpr size_t kIcmpv6OptionSize = 8;
    const int payload_size = sizeof(in6_addr) + kIcmpv6OptionSize;
    auto payload = std::make_unique<char[]>(payload_size);
    // Place the solicited IPv6 address at the beginning of the response payload
    memcpy(payload.get(), icmp6_payload.data(), sizeof(in6_addr));
    // Setup the Target link-layer address option:
    //      0                   1                   2                   3
    //  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    // |     Type      |    Length     |    Link-Layer Address ...
    // +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    int pos = sizeof(in6_addr);
    payload[pos++] = ND_OPT_TARGET_LINKADDR;  // Type
    payload[pos++] = 1;                       // Length in units of 8 octets
    memcpy(&payload[pos], eth_hdr_.h_source,
           ETH_ALEN);  // This interfaces' MAC address

    // Populate the ICMPv6 header
    icmp6_hdr response_hdr{};
    response_hdr.icmp6_type = ND_NEIGHBOR_ADVERT;
    // Set the solicited bit to true
    response_hdr.icmp6_dataun.icmp6_un_data8[0] = 64;
    // Craft the full ICMPv6 packet and then ship it off to WritePacket
    // to have it frame it with L2 headers and send it back to the requesting
    // neighbor.
    CreateIcmpPacket(ip_hdr->ip6_src, ip_hdr->ip6_src, response_hdr,
                     absl::string_view(payload.get(), payload_size),
                     [this](absl::string_view packet) {
                       WritePacketToNetwork(packet.data(), packet.size());
                     });
    return L2ValidationResult::kValidLinkLocal;
  }

  return L2ValidationResult::kValidNormal;
}

}  // namespace quic
