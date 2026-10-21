// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QBONE_BONNET_TUN_DEVICE_PACKET_EXCHANGER_H_
#define QUICHE_QUIC_QBONE_BONNET_TUN_DEVICE_PACKET_EXCHANGER_H_

#include <linux/if_ether.h>

#include <cstddef>
#include <memory>
#include <optional>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/base/nullability.h"
#include "absl/types/span.h"
#include "quiche/quic/qbone/bonnet/qbone_client_packet_exchanger.h"
#include "quiche/quic/qbone/platform/kernel_interface.h"

namespace quic {

// Exchanger implementation that does read and write operations synchronously in
// the calling thread, invoking visitor callbacks on that same thread. Safe to
// use separate threads for reading and writing as long as all writes occur on
// the same thread and all reads occur on the same thread.
class TunDevicePacketExchanger : public QboneClientPacketExchanger {
 public:
  TunDevicePacketExchanger(size_t mtu, KernelInterface* absl_nonnull kernel,
                           QboneClientPacketExchanger::Visitor* absl_nonnull
                               visitor ABSL_ATTRIBUTE_LIFETIME_BOUND);

  ~TunDevicePacketExchanger() override;

  // QboneClientPacketExchanger:
  void Start(int read_fd, int write_fd,
             QboneClientPacketExchanger* absl_nullable exchanger,
             std::optional<ethhdr> eth_hdr = std::nullopt) override;
  void Stop() override;
  int OnReadFromNetworkReady(int max_packets_to_read) override;
  void WritePacketToNetwork(absl::Span<const std::byte> packet) override;

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

  // Returns true if more packets may be available to read.
  bool ReadAndExchangeSinglePacket(bool exchange_blocked_error);

  L2ValidationResult ValidateL2Headers(const ethhdr& eth_header,
                                       absl::Span<const std::byte> packet);

  KernelInterface* kernel_;
  QboneClientPacketExchanger::Visitor& visitor_;

  std::vector<std::byte> read_buffer_;

  bool is_tap_ = false;
  ethhdr eth_hdr_ = {};

  // -1/nullptr before Start() or after Stop().
  int read_fd_ = -1;
  int write_fd_ = -1;
  QboneClientPacketExchanger* absl_nullable exchanger_ = nullptr;
};

}  // namespace quic

#endif  // QUICHE_QUIC_QBONE_BONNET_TUN_DEVICE_PACKET_EXCHANGER_H_
