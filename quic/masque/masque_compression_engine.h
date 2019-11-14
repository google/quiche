// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_PROTOCOL_H_
#define QUICHE_QUIC_MASQUE_MASQUE_PROTOCOL_H_

#include "net/third_party/quiche/src/quic/core/quic_connection_id.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"

namespace quic {

// MASQUE compression engine used by client and servers.
// This class allows converting QUIC packets into a compressed form suitable
// for sending over QUIC DATAGRAM frames. It leverages a flow identifier at the
// start of each datagram to indicate which compression context was used to
// compress this packet, or to create new compression contexts.
class QUIC_EXPORT_PRIVATE MasqueCompressionEngine {
 public:
  explicit MasqueCompressionEngine(QuicSession* masque_session);

  // Compress packet and send it over a MASQUE session.
  void CompressAndSendPacket(QuicStringPiece packet,
                             QuicConnectionId client_connection_id,
                             QuicConnectionId server_connection_id,
                             const QuicSocketAddress& server_socket_address);

  // Decompress received message and place it in |packet|.
  bool DecompressMessage(QuicStringPiece message,
                         QuicConnectionId* client_connection_id,
                         QuicConnectionId* server_connection_id,
                         QuicSocketAddress* server_socket_address,
                         std::string* packet,
                         bool* version_present);

  // Clear all entries referencing |client_connection_id| the from
  // compression table.
  void UnregisterClientConnectionId(QuicConnectionId client_connection_id);

  // Disallow default constructor, copy, and assign.
  MasqueCompressionEngine() = delete;
  MasqueCompressionEngine(const MasqueCompressionEngine&) = delete;
  MasqueCompressionEngine& operator=(const MasqueCompressionEngine&) = delete;

 private:
  struct QUIC_EXPORT_PRIVATE MasqueCompressionContext {
    QuicConnectionId client_connection_id;
    QuicConnectionId server_connection_id;
    QuicSocketAddress server_socket_address;
    bool validated = false;
  };

  // Generate a new datagram flow ID.
  QuicDatagramFlowId GetNextFlowId();

  QuicSession* masque_session_;  // Unowned.
  QuicUnorderedMap<QuicDatagramFlowId, MasqueCompressionContext> contexts_;
  QuicDatagramFlowId next_flow_id_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_PROTOCOL_H_
