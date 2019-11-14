// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_CLIENT_SESSION_H_
#define QUICHE_QUIC_MASQUE_MASQUE_CLIENT_SESSION_H_

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_client_session.h"
#include "net/third_party/quiche/src/quic/masque/masque_compression_engine.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"

namespace quic {

// QUIC client session for connection to MASQUE proxy.
class QUIC_EXPORT_PRIVATE MasqueClientSession : public QuicSpdyClientSession {
 public:
  // Visitor interface meant to be implemented by the owner of the
  // MasqueClientSession instance.
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    virtual ~Visitor() {}

    // Notifies the visitor that the client connection ID is no longer in use.
    virtual void SendClientConnectionIdUnregister(
        QuicConnectionId client_connection_id) = 0;
  };
  // Interface meant to be implemented by encapsulated client sessions.
  class QUIC_EXPORT_PRIVATE EncapsulatedClientSession {
   public:
    virtual ~EncapsulatedClientSession() {}

    // Process packet that was just decapsulated.
    virtual void ProcessPacket(QuicStringPiece packet,
                               QuicSocketAddress server_socket_address) = 0;
  };

  MasqueClientSession(const QuicConfig& config,
                      const ParsedQuicVersionVector& supported_versions,
                      QuicConnection* connection,
                      const QuicServerId& server_id,
                      QuicCryptoClientConfig* crypto_config,
                      QuicClientPushPromiseIndex* push_promise_index,
                      Visitor* owner);

  // From QuicSession.
  void OnMessageReceived(QuicStringPiece message) override;

  void OnMessageAcked(QuicMessageId message_id,
                      QuicTime receive_timestamp) override;

  void OnMessageLost(QuicMessageId message_id) override;

  // Send encapsulated packet.
  void SendPacket(QuicConnectionId client_connection_id,
                  QuicConnectionId server_connection_id,
                  QuicStringPiece packet,
                  const QuicSocketAddress& server_socket_address);

  // Register encapsulated client.
  void RegisterConnectionId(
      QuicConnectionId client_connection_id,
      EncapsulatedClientSession* encapsulated_client_session);

  // Unregister encapsulated client.
  void UnregisterConnectionId(QuicConnectionId client_connection_id);

  // Disallow default constructor, copy, and assign.
  MasqueClientSession() = delete;
  MasqueClientSession(const MasqueClientSession&) = delete;
  MasqueClientSession& operator=(const MasqueClientSession&) = delete;

 private:
  QuicUnorderedMap<QuicConnectionId,
                   EncapsulatedClientSession*,
                   QuicConnectionIdHash>
      client_connection_id_registrations_;
  Visitor* owner_;  // Unowned;
  MasqueCompressionEngine compression_engine_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_CLIENT_SESSION_H_
