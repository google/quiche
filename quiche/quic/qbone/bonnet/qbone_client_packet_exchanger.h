// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QBONE_QBONE_PACKET_EXCHANGER_H_
#define QUICHE_QUIC_QBONE_QBONE_PACKET_EXCHANGER_H_

#include <cstddef>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "quiche/quic/qbone/qbone_client_interface.h"

namespace quic {

// Handles reading and writing on the local network and exchange packets between
// the local network with a QBONE connection.
class QboneClientPacketExchanger {
 public:
  struct ReadResult {
    absl::Span<const std::byte> packet;
    absl::Duration latency;
  };

  struct WriteResult {
    absl::Span<const std::byte> packet;
    absl::Duration latency;
  };

  class Visitor {
   public:
    virtual ~Visitor() = default;

    virtual void OnRead(absl::StatusOr<std::vector<ReadResult>> results) = 0;
    virtual void OnWrite(absl::StatusOr<std::vector<WriteResult>> results) = 0;
  };

  virtual ~QboneClientPacketExchanger() = default;

  // Reads a packet from the local network and delivers the packet to
  // qbone_client. Returns true if there may be more packets to read.
  virtual bool ReadAndDeliverPacket(QboneClientInterface* qbone_client) = 0;

  // Writes a packet to the local network. If the write would be blocked, the
  // packet is dropped.
  virtual void WritePacketToNetwork(const char* packet, size_t size) = 0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_QBONE_QBONE_PACKET_EXCHANGER_H_
