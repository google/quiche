// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_client_session.h"

#include <memory>

#include "url/gurl.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"

namespace quic {

const char* kQuicTransportAlpn = "wq-draft01";

namespace {
// ProofHandler is primarily used by QUIC crypto to persist QUIC server configs
// and perform some of related debug logging.  QuicTransport does not support
// QUIC crypto, so those methods are not called.
class DummyProofHandler : public QuicCryptoClientStream::ProofHandler {
 public:
  void OnProofValid(
      const QuicCryptoClientConfig::CachedState& /*cached*/) override {}
  void OnProofVerifyDetailsAvailable(
      const ProofVerifyDetails& /*verify_details*/) override {}
};
}  // namespace

QuicTransportClientSession::QuicTransportClientSession(
    QuicConnection* connection,
    Visitor* owner,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    url::Origin origin)
    : QuicSession(connection,
                  owner,
                  config,
                  supported_versions,
                  /*num_expected_unidirectional_static_streams*/ 0),
      origin_(origin) {
  for (const ParsedQuicVersion& version : supported_versions) {
    QUIC_BUG_IF(version.handshake_protocol != PROTOCOL_TLS1_3)
        << "QuicTransport requires TLS 1.3 handshake";
  }
  // ProofHandler API is not used by TLS 1.3.
  static DummyProofHandler* proof_handler = new DummyProofHandler();
  crypto_stream_ = std::make_unique<QuicCryptoClientStream>(
      server_id, this, crypto_config->proof_verifier()->CreateDefaultContext(),
      crypto_config, proof_handler);
}

void QuicTransportClientSession::OnCryptoHandshakeEvent(
    CryptoHandshakeEvent event) {
  QuicSession::OnCryptoHandshakeEvent(event);
  if (event != HANDSHAKE_CONFIRMED) {
    return;
  }

  auto it = config()->received_custom_transport_parameters().find(
      WebAcceptedOriginsParameter());
  if (it == config()->received_custom_transport_parameters().end()) {
    connection()->CloseConnection(
        QUIC_HANDSHAKE_FAILED,
        "QuicTransport requires web_accepted_origins transport parameter",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }

  QUIC_DLOG(INFO) << "QuicTransport using origin: " << origin_.Serialize();
  QUIC_DLOG(INFO) << "QuicTransport origins offered: " << it->second;

  if (CheckOrigin(it->second)) {
    is_origin_valid_ = true;
  } else {
    QUIC_DLOG(ERROR) << "Origin check failed for " << origin_
                     << ", allowed origin list: " << it->second;
    connection()->CloseConnection(
        QUIC_HANDSHAKE_FAILED, "QuicTransport origin check failed",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
  }
}

bool QuicTransportClientSession::CheckOrigin(
    QuicStringPiece raw_accepted_origins) {
  if (raw_accepted_origins == "*") {
    return true;
  }

  std::vector<QuicStringPiece> accepted_origins =
      QuicTextUtils::Split(raw_accepted_origins, ',');
  for (QuicStringPiece raw_origin : accepted_origins) {
    url::Origin accepted_origin =
        url::Origin::Create(GURL(std::string(raw_origin)));
    QUIC_DVLOG(1) << "QuicTransport offered origin normalized: "
                  << accepted_origin.Serialize();
    if (accepted_origin.IsSameOriginWith(origin_)) {
      return true;
    }
  }
  return false;
}

}  // namespace quic
