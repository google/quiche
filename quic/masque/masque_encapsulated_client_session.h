// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_ENCAPSULATED_CLIENT_SESSION_H_
#define QUICHE_QUIC_MASQUE_MASQUE_ENCAPSULATED_CLIENT_SESSION_H_

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_client_session.h"
#include "net/third_party/quiche/src/quic/masque/masque_client_session.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"

namespace quic {

// QUIC client session for QUIC encapsulated in MASQUE.
class QUIC_EXPORT_PRIVATE MasqueEncapsulatedClientSession
    : public QuicSpdyClientSession,
      public MasqueClientSession::EncapsulatedClientSession {
 public:
  MasqueEncapsulatedClientSession(
      const QuicConfig& config,
      const ParsedQuicVersionVector& supported_versions,
      QuicConnection* connection,
      const QuicServerId& server_id,
      QuicCryptoClientConfig* crypto_config,
      QuicClientPushPromiseIndex* push_promise_index,
      MasqueClientSession* masque_client_session);

  // From MasqueClientSession::EncapsulatedClientSession.
  void ProcessPacket(QuicStringPiece packet,
                     QuicSocketAddress server_socket_address) override;

  // From QuicSession.
  void OnConnectionClosed(const QuicConnectionCloseFrame& frame,
                          ConnectionCloseSource source) override;

  // Disallow default constructor, copy, and assign.
  MasqueEncapsulatedClientSession() = delete;
  MasqueEncapsulatedClientSession(const MasqueEncapsulatedClientSession&) =
      delete;
  MasqueEncapsulatedClientSession& operator=(
      const MasqueEncapsulatedClientSession&) = delete;

 private:
  MasqueClientSession* masque_client_session_;  // Unowned.
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_ENCAPSULATED_CLIENT_SESSION_H_
