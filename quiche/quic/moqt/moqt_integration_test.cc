// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_compressed_certs_cache.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_generic_session.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/test_harness.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::test {
namespace {

using ::quic::simulator::Simulator;
using ::testing::_;
using ::testing::Assign;

class ClientEndpoint : public quic::simulator::QuicEndpointWithConnection {
 public:
  ClientEndpoint(Simulator* simulator, const std::string& name,
                 const std::string& peer_name, MoqtVersion version)
      : QuicEndpointWithConnection(simulator, name, peer_name,
                                   quic::Perspective::IS_CLIENT,
                                   quic::GetQuicVersionsForGenericSession()),
        crypto_config_(
            quic::test::crypto_test_utils::ProofVerifierForTesting()),
        quic_session_(connection_.get(), false, nullptr, quic::QuicConfig(),
                      "test.example.com", 443, "moqt", &session_,
                      /*visitor_owned=*/false, nullptr, &crypto_config_),
        session_(
            &quic_session_,
            MoqtSessionParameters{.version = version,
                                  .perspective = quic::Perspective::IS_CLIENT,
                                  .using_webtrans = false},
            established_callback_.AsStdFunction(),
            terminated_callback_.AsStdFunction()) {
    quic_session_.Initialize();
  }

  MoqtSession* session() { return &session_; }
  quic::QuicGenericClientSession* quic_session() { return &quic_session_; }
  testing::MockFunction<void()>& established_callback() {
    return established_callback_;
  }
  testing::MockFunction<void(absl::string_view)>& terminated_callback() {
    return terminated_callback_;
  }

 private:
  testing::MockFunction<void()> established_callback_;
  testing::MockFunction<void(absl::string_view)> terminated_callback_;
  quic::QuicCryptoClientConfig crypto_config_;
  quic::QuicGenericClientSession quic_session_;
  MoqtSession session_;
};

class ServerEndpoint : public quic::simulator::QuicEndpointWithConnection {
 public:
  ServerEndpoint(Simulator* simulator, const std::string& name,
                 const std::string& peer_name, MoqtVersion version)
      : QuicEndpointWithConnection(simulator, name, peer_name,
                                   quic::Perspective::IS_SERVER,
                                   quic::GetQuicVersionsForGenericSession()),
        compressed_certs_cache_(
            quic::QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        crypto_config_(quic::QuicCryptoServerConfig::TESTING,
                       quic::QuicRandom::GetInstance(),
                       quic::test::crypto_test_utils::ProofSourceForTesting(),
                       quic::KeyExchangeSource::Default()),
        quic_session_(connection_.get(), false, nullptr, quic::QuicConfig(),
                      "moqt", &session_,
                      /*visitor_owned=*/false, nullptr, &crypto_config_,
                      &compressed_certs_cache_),
        session_(
            &quic_session_,
            MoqtSessionParameters{.version = version,
                                  .perspective = quic::Perspective::IS_SERVER,
                                  .using_webtrans = false},
            established_callback_.AsStdFunction(),
            terminated_callback_.AsStdFunction()) {
    quic_session_.Initialize();
  }

  MoqtSession* session() { return &session_; }
  testing::MockFunction<void()>& established_callback() {
    return established_callback_;
  }
  testing::MockFunction<void(absl::string_view)>& terminated_callback() {
    return terminated_callback_;
  }

 private:
  testing::MockFunction<void()> established_callback_;
  testing::MockFunction<void(absl::string_view)> terminated_callback_;
  quic::QuicCompressedCertsCache compressed_certs_cache_;
  quic::QuicCryptoServerConfig crypto_config_;
  quic::QuicGenericServerSession quic_session_;
  MoqtSession session_;
};

class MoqtIntegrationTest : public quiche::test::QuicheTest {
 public:
  void CreateDefaultEndpoints() {
    client_ = std::make_unique<ClientEndpoint>(
        &test_harness_.simulator(), "Client", "Server", MoqtVersion::kDraft01);
    server_ = std::make_unique<ServerEndpoint>(
        &test_harness_.simulator(), "Server", "Client", MoqtVersion::kDraft01);
    test_harness_.set_client(client_.get());
    test_harness_.set_server(server_.get());
  }

  void WireUpEndpoints() { test_harness_.WireUpEndpoints(); }

 protected:
  quic::simulator::TestHarness test_harness_;

  std::unique_ptr<ClientEndpoint> client_;
  std::unique_ptr<ServerEndpoint> server_;
};

TEST_F(MoqtIntegrationTest, Handshake) {
  CreateDefaultEndpoints();
  WireUpEndpoints();

  client_->quic_session()->CryptoConnect();
  bool client_established = false;
  bool server_established = false;
  EXPECT_CALL(client_->established_callback(), Call())
      .WillOnce(Assign(&client_established, true));
  EXPECT_CALL(server_->established_callback(), Call())
      .WillOnce(Assign(&server_established, true));
  bool success = test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return client_established && server_established; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, VersionMismatch) {
  client_ = std::make_unique<ClientEndpoint>(
      &test_harness_.simulator(), "Client", "Server",
      MoqtVersion::kUnrecognizedVersionForTests);
  server_ = std::make_unique<ServerEndpoint>(
      &test_harness_.simulator(), "Server", "Client", MoqtVersion::kDraft01);
  test_harness_.set_client(client_.get());
  test_harness_.set_server(server_.get());
  WireUpEndpoints();

  client_->quic_session()->CryptoConnect();
  bool client_terminated = false;
  bool server_terminated = false;
  EXPECT_CALL(client_->established_callback(), Call()).Times(0);
  EXPECT_CALL(server_->established_callback(), Call()).Times(0);
  EXPECT_CALL(client_->terminated_callback(), Call(_))
      .WillOnce(Assign(&client_terminated, true));
  EXPECT_CALL(server_->terminated_callback(), Call(_))
      .WillOnce(Assign(&server_terminated, true));
  bool success = test_harness_.RunUntilWithDefaultTimeout(
      [&]() { return client_terminated && server_terminated; });
  EXPECT_TRUE(success);
}

}  // namespace
}  // namespace moqt::test
