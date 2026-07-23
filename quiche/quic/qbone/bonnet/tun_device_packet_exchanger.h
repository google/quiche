// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QBONE_BONNET_TUN_DEVICE_PACKET_EXCHANGER_H_
#define QUICHE_QUIC_QBONE_BONNET_TUN_DEVICE_PACKET_EXCHANGER_H_

#include <linux/if_ether.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/base/attributes.h"
#include "absl/base/nullability.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/qbone/bonnet/qbone_client_packet_exchanger.h"
#include "quiche/quic/qbone/platform/kernel_interface.h"
#include "quiche/quic/qbone/platform/netlink_interface.h"
#include "quiche/quic/qbone/qbone_client_interface.h"

namespace quic {

class TunDevicePacketExchanger : public QboneClientPacketExchanger {
 public:
  class StatsInterface {
   public:
    StatsInterface() = default;

    StatsInterface(const StatsInterface&) = delete;
    StatsInterface& operator=(const StatsInterface&) = delete;

    StatsInterface(StatsInterface&&) = delete;
    StatsInterface& operator=(StatsInterface&&) = delete;

    virtual ~StatsInterface() = default;

    virtual void OnPacketRead(size_t length, absl::Duration latency) = 0;
    virtual void OnPacketWritten(size_t length, absl::Duration latency) = 0;
    virtual void OnReadError(absl::string_view error) = 0;
    virtual void OnWriteError(absl::string_view error) = 0;

    ABSL_MUST_USE_RESULT virtual int64_t PacketsRead() const = 0;
    ABSL_MUST_USE_RESULT virtual int64_t PacketsWritten() const = 0;
  };

  // |mtu| is the mtu of the TUN device.
  // |kernel| is not owned but should out live objects of this class.
  // |visitor| is not owned but should out live objects of this class.
  // |stats| is notified about packet read/write statistics. It is not owned,
  // but should outlive objects of this class.
  TunDevicePacketExchanger(
      size_t mtu, KernelInterface* kernel, NetlinkInterface* netlink,
      QboneClientPacketExchanger::Visitor* absl_nullable visitor
          ABSL_ATTRIBUTE_LIFETIME_BOUND,
      bool is_tap, StatsInterface* stats, absl::string_view ifname);

  void set_read_file_descriptor(int fd);
  void set_write_file_descriptor(int fd);

  ABSL_MUST_USE_RESULT const StatsInterface* stats_interface() const;

  // QboneClientPacketExchanger:
  bool ReadAndDeliverPacket(QboneClientInterface* qbone_client) override;
  void WritePacketToNetwork(const char* packet, size_t size) override;

 private:
  enum class L2ValidationResult {
    // Headers are invalid. Packet should be dropped.
    kInvalid,

    // Headers are valid, and the packet should be forwarded to the tunnel.
    kValidNormal,

    // Headers are valid, and the packet is a recognized link-local packet. The
    // packet should not be forwarded to the tunnel. An appropriate response has
    // already been sent back to the network.
    kValidLinkLocal
  };

  void InitializeEthHdr();

  L2ValidationResult ValidateL2Headers(const ethhdr& eth_header,
                                       const QuicData& packet);

  int read_fd_ = -1;
  int write_fd_ = -1;
  size_t mtu_;
  KernelInterface* kernel_;
  NetlinkInterface* netlink_;
  QboneClientPacketExchanger::Visitor* const absl_nullable visitor_;
  const std::string ifname_;

  const bool is_tap_;
  ethhdr eth_hdr_;
  bool eth_hdr_initialized_ = false;

  StatsInterface* stats_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_QBONE_BONNET_TUN_DEVICE_PACKET_EXCHANGER_H_
