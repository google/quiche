// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_client_session.h"

#include <memory>

#include "url/gurl.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
namespace {

using testing::_;
using testing::ElementsAre;

const char* kTestOrigin = "https://test-origin.test";
const char* kTestOriginInsecure = "http://test-origin.test";
url::Origin GetTestOrigin() {
  GURL origin_url(kTestOrigin);
  return url::Origin::Create(origin_url);
}

ParsedQuicVersionVector GetVersions() {
  return {ParsedQuicVersion{PROTOCOL_TLS1_3, QUIC_VERSION_99}};
}

class TestClientSession : public QuicTransportClientSession {
 public:
  using QuicTransportClientSession::QuicTransportClientSession;

  class Stream : public QuicStream {
   public:
    using QuicStream::QuicStream;
    void OnDataAvailable() override {}
  };

  QuicStream* CreateIncomingStream(QuicStreamId id) override {
    auto stream = std::make_unique<Stream>(
        id, this, /*is_static=*/false,
        QuicUtils::GetStreamType(id, connection()->perspective(),
                                 /*peer_initiated=*/true));
    QuicStream* result = stream.get();
    ActivateStream(std::move(stream));
    return result;
  }

  QuicStream* CreateIncomingStream(PendingStream* /*pending*/) override {
    QUIC_NOTREACHED();
    return nullptr;
  }
};

class QuicTransportClientSessionTest : public QuicTest {
 protected:
  QuicTransportClientSessionTest()
      : connection_(&helper_,
                    &alarm_factory_,
                    Perspective::IS_CLIENT,
                    GetVersions()),
        server_id_("test.example.com", 443),
        crypto_config_(crypto_test_utils::ProofVerifierForTesting()) {
    SetQuicReloadableFlag(quic_supports_tls_handshake, true);
    session_ = std::make_unique<TestClientSession>(
        &connection_, nullptr, DefaultQuicConfig(), GetVersions(), server_id_,
        &crypto_config_, GetTestOrigin());
    session_->Initialize();
    crypto_stream_ = static_cast<QuicCryptoClientStream*>(
        session_->GetMutableCryptoStream());
  }

  void ConnectWithOriginList(std::string accepted_origins) {
    session_->CryptoConnect();
    QuicConfig server_config = DefaultQuicConfig();
    server_config
        .custom_transport_parameters_to_send()[WebAcceptedOriginsParameter()] =
        accepted_origins;
    crypto_test_utils::HandshakeWithFakeServer(
        &server_config, &helper_, &alarm_factory_, &connection_, crypto_stream_,
        kQuicTransportAlpn);
  }

  MockAlarmFactory alarm_factory_;
  MockQuicConnectionHelper helper_;

  PacketSavingConnection connection_;
  QuicServerId server_id_;
  QuicCryptoClientConfig crypto_config_;
  std::unique_ptr<TestClientSession> session_;
  QuicCryptoClientStream* crypto_stream_;
};

TEST_F(QuicTransportClientSessionTest, HasValidAlpn) {
  EXPECT_THAT(session_->GetAlpnsToOffer(), ElementsAre(kQuicTransportAlpn));
}

TEST_F(QuicTransportClientSessionTest, SuccessfulConnection) {
  ConnectWithOriginList(GetTestOrigin().Serialize());
  EXPECT_TRUE(session_->IsSessionReady());
}

TEST_F(QuicTransportClientSessionTest, SuccessfulConnectionManyOrigins) {
  ConnectWithOriginList(
      QuicStrCat("http://example.org,", kTestOrigin, ",https://example.com"));
  EXPECT_TRUE(session_->IsSessionReady());
}

TEST_F(QuicTransportClientSessionTest, SuccessfulConnectionWildcardOrigin) {
  ConnectWithOriginList("*");
  EXPECT_TRUE(session_->IsSessionReady());
}

TEST_F(QuicTransportClientSessionTest, OriginMismatch) {
  EXPECT_CALL(connection_,
              CloseConnection(_, "QuicTransport origin check failed", _));
  ConnectWithOriginList("https://obviously-wrong-website.test");
  EXPECT_FALSE(session_->IsSessionReady());
}

TEST_F(QuicTransportClientSessionTest, OriginSchemaMismatch) {
  EXPECT_CALL(connection_,
              CloseConnection(_, "QuicTransport origin check failed", _));
  ConnectWithOriginList(kTestOriginInsecure);
  EXPECT_FALSE(session_->IsSessionReady());
}

TEST_F(QuicTransportClientSessionTest, OriginListMissing) {
  EXPECT_CALL(
      connection_,
      CloseConnection(
          _, "QuicTransport requires web_accepted_origins transport parameter",
          _));
  session_->CryptoConnect();
  QuicConfig server_config = DefaultQuicConfig();
  crypto_test_utils::HandshakeWithFakeServer(
      &server_config, &helper_, &alarm_factory_, &connection_, crypto_stream_,
      kQuicTransportAlpn);
  EXPECT_FALSE(session_->IsSessionReady());
}

TEST_F(QuicTransportClientSessionTest, OriginListEmpty) {
  EXPECT_CALL(connection_,
              CloseConnection(_, "QuicTransport origin check failed", _));
  ConnectWithOriginList("");
  EXPECT_FALSE(session_->IsSessionReady());
}

}  // namespace
}  // namespace test
}  // namespace quic
