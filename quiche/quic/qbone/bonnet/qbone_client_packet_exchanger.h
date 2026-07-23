// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QBONE_QBONE_PACKET_EXCHANGER_H_
#define QUICHE_QUIC_QBONE_QBONE_PACKET_EXCHANGER_H_

#include <cstddef>
#include <memory>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/qbone/qbone_client_interface.h"

namespace quic {

// Handles reading and writing on the local network and exchange packets between
// the local network with a QBONE connection.
class QboneClientPacketExchanger {
 public:
  // The owner might want to receive notifications when read or write fails.
  // TODO(b/535980431): Simplify and make more generally useful, so that this
  // can serve as the primary mechanism for passing out async results.
  class Visitor {
   public:
    virtual ~Visitor() {}
    virtual void OnReadError(const std::string& error) {}
    virtual void OnWriteError(const std::string& error) {}
    virtual absl::Status OnWrite(absl::string_view packet) {
      return absl::OkStatus();
    }
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
