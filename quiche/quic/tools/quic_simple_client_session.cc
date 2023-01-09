// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_simple_client_session.h"

#include <utility>

#include "quiche/quic/core/quic_path_validator.h"

namespace quic {

namespace {

class ServerPreferredAddressResultDelegateWithWriter
    : public QuicPathValidator::ResultDelegate {
 public:
  explicit ServerPreferredAddressResultDelegateWithWriter(
      QuicConnection* connection)
      : connection_(connection) {}

  // Overridden to transfer the ownership of the new writer.
  void OnPathValidationSuccess(
      std::unique_ptr<QuicPathValidationContext> /*context*/,
      QuicTime /*start_time*/) override {
    // TODO(danzh) hand over the ownership of the released writer to client and
    // call the connection to migrate.
  }

  void OnPathValidationFailure(
      std::unique_ptr<QuicPathValidationContext> context) override {
    connection_->OnPathValidationFailureAtClient(/*is_multi_port=*/false,
                                                 *context);
  }

 private:
  QuicConnection* connection_ = nullptr;
};

}  // namespace

QuicSimpleClientSession::QuicSimpleClientSession(
    const QuicConfig& config, const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection, QuicClientBase::NetworkHelper* network_helper,
    const QuicServerId& server_id, QuicCryptoClientConfig* crypto_config,
    QuicClientPushPromiseIndex* push_promise_index, bool drop_response_body,
    bool enable_web_transport)
    : QuicSpdyClientSession(config, supported_versions, connection, server_id,
                            crypto_config, push_promise_index),
      network_helper_(network_helper),
      drop_response_body_(drop_response_body),
      enable_web_transport_(enable_web_transport) {}

std::unique_ptr<QuicSpdyClientStream>
QuicSimpleClientSession::CreateClientStream() {
  return std::make_unique<QuicSimpleClientStream>(
      GetNextOutgoingBidirectionalStreamId(), this, BIDIRECTIONAL,
      drop_response_body_);
}

bool QuicSimpleClientSession::ShouldNegotiateWebTransport() {
  return enable_web_transport_;
}

HttpDatagramSupport QuicSimpleClientSession::LocalHttpDatagramSupport() {
  return enable_web_transport_ ? HttpDatagramSupport::kDraft04
                               : HttpDatagramSupport::kNone;
}

std::unique_ptr<QuicPathValidationContext>
QuicSimpleClientSession::CreateContextForMultiPortPath() {
  if (!network_helper_ || connection()->multi_port_stats() == nullptr) {
    return nullptr;
  }
  auto self_address = connection()->self_address();
  auto server_address = connection()->peer_address();
  if (!network_helper_->CreateUDPSocketAndBind(
          server_address, self_address.host(), self_address.port() + 1)) {
    return nullptr;
  }
  QuicPacketWriter* writer = network_helper_->CreateQuicPacketWriter();
  if (writer == nullptr) {
    return nullptr;
  }
  return std::make_unique<PathMigrationContext>(
      std::unique_ptr<QuicPacketWriter>(writer),
      network_helper_->GetLatestClientAddress(), peer_address());
}

void QuicSimpleClientSession::OnServerPreferredAddressAvailable(
    const QuicSocketAddress& server_preferred_address) {
  const auto self_address = connection()->self_address();
  if (network_helper_ == nullptr ||
      !network_helper_->CreateUDPSocketAndBind(server_preferred_address,
                                               self_address.host(), 0)) {
    return;
  }
  QuicPacketWriter* writer = network_helper_->CreateQuicPacketWriter();
  if (writer == nullptr) {
    return;
  }
  connection()->ValidatePath(
      std::make_unique<PathMigrationContext>(
          std::unique_ptr<QuicPacketWriter>(writer),
          network_helper_->GetLatestClientAddress(), server_preferred_address),
      std::make_unique<ServerPreferredAddressResultDelegateWithWriter>(
          connection()));
}

}  // namespace quic
