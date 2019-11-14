// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_DISPATCHER_H_
#define QUICHE_QUIC_MASQUE_MASQUE_DISPATCHER_H_

#include "net/third_party/quiche/src/quic/masque/masque_server_backend.h"
#include "net/third_party/quiche/src/quic/masque/masque_server_session.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/tools/quic_simple_dispatcher.h"

namespace quic {

// QUIC dispatcher that handles MASQUE requests.
class QUIC_EXPORT_PRIVATE MasqueDispatcher
    : public QuicSimpleDispatcher,
      public MasqueServerSession::Visitor {
 public:
  MasqueDispatcher(
      const QuicConfig* config,
      const QuicCryptoServerConfig* crypto_config,
      QuicVersionManager* version_manager,
      std::unique_ptr<QuicConnectionHelperInterface> helper,
      std::unique_ptr<QuicCryptoServerStream::Helper> session_helper,
      std::unique_ptr<QuicAlarmFactory> alarm_factory,
      MasqueServerBackend* masque_server_backend,
      uint8_t expected_server_connection_id_length);

  // From QuicSimpleDispatcher.
  QuicServerSessionBase* CreateQuicSession(
      QuicConnectionId connection_id,
      const QuicSocketAddress& client_address,
      QuicStringPiece alpn,
      const ParsedQuicVersion& version) override;

  bool OnFailedToDispatchPacket(const ReceivedPacketInfo& packet_info) override;

  // From MasqueServerSession::Visitor.
  void RegisterClientConnectionId(
      QuicConnectionId client_connection_id,
      MasqueServerSession* masque_server_session) override;

  void UnregisterClientConnectionId(
      QuicConnectionId client_connection_id) override;

  // Disallow default constructor, copy, and assign.
  MasqueDispatcher() = delete;
  MasqueDispatcher(const MasqueDispatcher&) = delete;
  MasqueDispatcher& operator=(const MasqueDispatcher&) = delete;

 private:
  MasqueServerBackend* masque_server_backend_;  // Unowned.
  QuicUnorderedMap<QuicConnectionId, MasqueServerSession*, QuicConnectionIdHash>
      client_connection_id_registrations_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_DISPATCHER_H_
