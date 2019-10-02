// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_SESSION_H_
#define QUICHE_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_SESSION_H_

#include <cstdint>
#include <memory>

#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_client_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"

namespace quic {

// The web_accepted_origins transport parameter ID.
constexpr TransportParameters::TransportParameterId
WebAcceptedOriginsParameter() {
  return static_cast<TransportParameters::TransportParameterId>(0xffc8);
}

// The ALPN used by QuicTransport.
QUIC_EXPORT extern const char* kQuicTransportAlpn;

// A client session for the QuicTransport protocol.
class QUIC_EXPORT QuicTransportClientSession : public QuicSession {
 public:
  QuicTransportClientSession(QuicConnection* connection,
                             Visitor* owner,
                             const QuicConfig& config,
                             const ParsedQuicVersionVector& supported_versions,
                             const QuicServerId& server_id,
                             QuicCryptoClientConfig* crypto_config,
                             url::Origin origin);

  std::vector<std::string> GetAlpnsToOffer() const override {
    return std::vector<std::string>({kQuicTransportAlpn});
  }

  void CryptoConnect() { crypto_stream_->CryptoConnect(); }

  bool ShouldKeepConnectionAlive() const override { return true; }

  QuicCryptoStream* GetMutableCryptoStream() override {
    return crypto_stream_.get();
  }
  const QuicCryptoStream* GetCryptoStream() const override {
    return crypto_stream_.get();
  }

  bool IsSessionReady() const {
    return IsCryptoHandshakeConfirmed() && is_origin_valid_;
  }

  void OnCryptoHandshakeEvent(CryptoHandshakeEvent event) override;

 protected:
  // Accepts the list of accepted origins in a format specified in
  // <https://tools.ietf.org/html/draft-vvv-webtransport-quic-00#section-3.2>,
  // and verifies that at least one of them matches |origin_|.
  bool CheckOrigin(QuicStringPiece raw_accepted_origins);

  std::unique_ptr<QuicCryptoClientStream> crypto_stream_;
  url::Origin origin_;
  bool is_origin_valid_ = false;
};

}  // namespace quic

#endif  // QUICHE_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_SESSION_H_
