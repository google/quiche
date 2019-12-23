// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/quic_crypto_server_stream.h"

#include <memory>
#include <string>
#include <utility>

#include "net/third_party/quiche/src/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_utils.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_random.h"
#include "net/third_party/quiche/src/quic/core/proto/cached_network_parameters_proto.h"
#include "net/third_party/quiche/src/quic/core/quic_config.h"
#include "net/third_party/quiche/src/quic/core/quic_crypto_server_handshaker.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/tls_server_handshaker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flag_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"

namespace quic {

QuicCryptoServerStreamBase::QuicCryptoServerStreamBase(QuicSession* session)
    : QuicCryptoStream(session) {}

QuicCryptoServerStream::QuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicSession* session,
    Helper* helper)
    : QuicCryptoServerStream(crypto_config,
                             compressed_certs_cache,
                             session,
                             helper,
                             /*handshaker*/ nullptr) {}

QuicCryptoServerStream::QuicCryptoServerStream(
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    QuicSession* session,
    Helper* helper,
    std::unique_ptr<HandshakerInterface> handshaker)
    : QuicCryptoServerStreamBase(session),
      handshaker_(std::move(handshaker)),
      create_handshaker_in_constructor_(
          GetQuicReloadableFlag(quic_create_server_handshaker_in_constructor)),
      crypto_config_(crypto_config),
      compressed_certs_cache_(compressed_certs_cache),
      helper_(helper) {
  DCHECK_EQ(Perspective::IS_SERVER, session->connection()->perspective());
  if (create_handshaker_in_constructor_ && !handshaker_) {
    switch (session->connection()->version().handshake_protocol) {
      case PROTOCOL_QUIC_CRYPTO:
        handshaker_ = std::make_unique<QuicCryptoServerHandshaker>(
            crypto_config_, this, compressed_certs_cache_, session, helper_);
        break;
      case PROTOCOL_TLS1_3:
        handshaker_ = std::make_unique<TlsServerHandshaker>(
            this, session, crypto_config_->ssl_ctx(),
            crypto_config_->proof_source());
        break;
      case PROTOCOL_UNSUPPORTED:
        QUIC_BUG << "Attempting to create QuicCryptoServerStream for unknown "
                    "handshake protocol";
    }
  }
}

QuicCryptoServerStream::~QuicCryptoServerStream() {}

void QuicCryptoServerStream::CancelOutstandingCallbacks() {
  if (handshaker_) {
    handshaker_->CancelOutstandingCallbacks();
  }
}

bool QuicCryptoServerStream::GetBase64SHA256ClientChannelID(
    std::string* output) const {
  return handshaker_->GetBase64SHA256ClientChannelID(output);
}

void QuicCryptoServerStream::SendServerConfigUpdate(
    const CachedNetworkParameters* cached_network_params) {
  handshaker_->SendServerConfigUpdate(cached_network_params);
}

uint8_t QuicCryptoServerStream::NumHandshakeMessages() const {
  return handshaker_->NumHandshakeMessages();
}

uint8_t QuicCryptoServerStream::NumHandshakeMessagesWithServerNonces() const {
  return handshaker_->NumHandshakeMessagesWithServerNonces();
}

int QuicCryptoServerStream::NumServerConfigUpdateMessagesSent() const {
  return handshaker_->NumServerConfigUpdateMessagesSent();
}

const CachedNetworkParameters*
QuicCryptoServerStream::PreviousCachedNetworkParams() const {
  return handshaker_->PreviousCachedNetworkParams();
}

bool QuicCryptoServerStream::ZeroRttAttempted() const {
  return handshaker_->ZeroRttAttempted();
}

void QuicCryptoServerStream::SetPreviousCachedNetworkParams(
    CachedNetworkParameters cached_network_params) {
  handshaker_->SetPreviousCachedNetworkParams(cached_network_params);
}

bool QuicCryptoServerStream::ShouldSendExpectCTHeader() const {
  return handshaker_->ShouldSendExpectCTHeader();
}

bool QuicCryptoServerStream::encryption_established() const {
  if (!handshaker_) {
    return false;
  }
  return handshaker_->encryption_established();
}

bool QuicCryptoServerStream::handshake_confirmed() const {
  if (!handshaker_) {
    return false;
  }
  return handshaker_->handshake_confirmed();
}

const QuicCryptoNegotiatedParameters&
QuicCryptoServerStream::crypto_negotiated_params() const {
  return handshaker_->crypto_negotiated_params();
}

CryptoMessageParser* QuicCryptoServerStream::crypto_message_parser() {
  return handshaker_->crypto_message_parser();
}

void QuicCryptoServerStream::OnPacketDecrypted(EncryptionLevel level) {
  handshaker_->OnPacketDecrypted(level);
}

size_t QuicCryptoServerStream::BufferSizeLimitForLevel(
    EncryptionLevel level) const {
  return handshaker_->BufferSizeLimitForLevel(level);
}

void QuicCryptoServerStream::OnSuccessfulVersionNegotiation(
    const ParsedQuicVersion& version) {
  DCHECK_EQ(version, session()->connection()->version());
  if (create_handshaker_in_constructor_) {
    return;
  }
  CHECK(!handshaker_);
  switch (session()->connection()->version().handshake_protocol) {
    case PROTOCOL_QUIC_CRYPTO:
      handshaker_ = std::make_unique<QuicCryptoServerHandshaker>(
          crypto_config_, this, compressed_certs_cache_, session(), helper_);
      break;
    case PROTOCOL_TLS1_3:
      handshaker_ = std::make_unique<TlsServerHandshaker>(
          this, session(), crypto_config_->ssl_ctx(),
          crypto_config_->proof_source());
      break;
    case PROTOCOL_UNSUPPORTED:
      QUIC_BUG << "Attempting to create QuicCryptoServerStream for unknown "
                  "handshake protocol";
  }
}

void QuicCryptoServerStream::set_handshaker(
    std::unique_ptr<QuicCryptoServerStream::HandshakerInterface> handshaker) {
  CHECK(!handshaker_);
  handshaker_ = std::move(handshaker);
}

QuicCryptoServerStream::HandshakerInterface*
QuicCryptoServerStream::handshaker() const {
  return handshaker_.get();
}

const QuicCryptoServerConfig* QuicCryptoServerStream::crypto_config() const {
  return crypto_config_;
}

QuicCompressedCertsCache* QuicCryptoServerStream::compressed_certs_cache()
    const {
  return compressed_certs_cache_;
}

QuicCryptoServerStream::Helper* QuicCryptoServerStream::helper() const {
  return helper_;
}

}  // namespace quic
