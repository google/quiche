// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdint>
#include <memory>
#include <optional>
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
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/test_harness.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::test {

namespace {

using ::quic::simulator::Simulator;
using ::testing::_;
using ::testing::Assign;
using ::testing::Return;

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
                                  .using_webtrans = false,
                                  .deliver_partial_objects = false},
            callbacks_.AsSessionCallbacks()) {
    quic_session_.Initialize();
  }

  MoqtSession* session() { return &session_; }
  quic::QuicGenericClientSession* quic_session() { return &quic_session_; }
  testing::MockFunction<void()>& established_callback() {
    return callbacks_.session_established_callback;
  }
  testing::MockFunction<void(absl::string_view)>& terminated_callback() {
    return callbacks_.session_terminated_callback;
  }
  MockSessionCallbacks& callbacks() { return callbacks_; }

 private:
  MockSessionCallbacks callbacks_;
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
                                  .using_webtrans = false,
                                  .deliver_partial_objects = false},
            callbacks_.AsSessionCallbacks()) {
    quic_session_.Initialize();
  }

  MoqtSession* session() { return &session_; }
  testing::MockFunction<void()>& established_callback() {
    return callbacks_.session_established_callback;
  }
  testing::MockFunction<void(absl::string_view)>& terminated_callback() {
    return callbacks_.session_terminated_callback;
  }
  MockSessionCallbacks& callbacks() { return callbacks_; }

 private:
  MockSessionCallbacks callbacks_;
  quic::QuicCompressedCertsCache compressed_certs_cache_;
  quic::QuicCryptoServerConfig crypto_config_;
  quic::QuicGenericServerSession quic_session_;
  MoqtSession session_;
};

class MoqtIntegrationTest : public quiche::test::QuicheTest {
 public:
  void CreateDefaultEndpoints() {
    client_ = std::make_unique<ClientEndpoint>(
        &test_harness_.simulator(), "Client", "Server", MoqtVersion::kDraft03);
    server_ = std::make_unique<ServerEndpoint>(
        &test_harness_.simulator(), "Server", "Client", MoqtVersion::kDraft03);
    test_harness_.set_client(client_.get());
    test_harness_.set_server(server_.get());
  }

  void WireUpEndpoints() { test_harness_.WireUpEndpoints(); }

  void EstablishSession() {
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
    QUICHE_CHECK(success);
  }

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
      &test_harness_.simulator(), "Server", "Client", MoqtVersion::kDraft03);
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

TEST_F(MoqtIntegrationTest, AnnounceSuccess) {
  EstablishSession();
  EXPECT_CALL(server_->callbacks().incoming_announce_callback, Call("foo"))
      .WillOnce(Return(std::nullopt));
  testing::MockFunction<void(
      absl::string_view track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_callback;
  client_->session()->Announce("foo", announce_callback.AsStdFunction());
  bool matches = false;
  EXPECT_CALL(announce_callback, Call(_, _))
      .WillOnce([&](absl::string_view track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        matches = true;
        EXPECT_EQ(track_namespace, "foo");
        EXPECT_FALSE(error.has_value());
      });
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return matches; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, AnnounceSuccessSubscribeInResponse) {
  EstablishSession();
  EXPECT_CALL(server_->callbacks().incoming_announce_callback, Call("foo"))
      .WillOnce(Return(std::nullopt));
  MockRemoteTrackVisitor server_visitor;
  testing::MockFunction<void(
      absl::string_view track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_callback;
  client_->session()->Announce("foo", announce_callback.AsStdFunction());
  bool matches = false;
  EXPECT_CALL(announce_callback, Call(_, _))
      .WillOnce([&](absl::string_view track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        EXPECT_EQ(track_namespace, "foo");
        EXPECT_FALSE(error.has_value());
        server_->session()->SubscribeCurrentGroup(track_namespace, "/catalog",
                                                  &server_visitor);
      });
  EXPECT_CALL(server_visitor, OnReply(_, _)).WillOnce([&]() {
    matches = true;
  });
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return matches; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, AnnounceFailure) {
  EstablishSession();
  testing::MockFunction<void(
      absl::string_view track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_callback;
  client_->session()->Announce("foo", announce_callback.AsStdFunction());
  bool matches = false;
  EXPECT_CALL(announce_callback, Call(_, _))
      .WillOnce([&](absl::string_view track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        matches = true;
        EXPECT_EQ(track_namespace, "foo");
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code,
                  MoqtAnnounceErrorCode::kAnnounceNotSupported);
      });
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return matches; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeAbsoluteOk) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");
  MockLocalTrackVisitor server_visitor;
  MockRemoteTrackVisitor client_visitor;
  server_->session()->AddLocalTrack(
      full_track_name, MoqtForwardingPreference::kObject, &server_visitor);
  std::optional<absl::string_view> expected_reason = std::nullopt;
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeAbsolute(full_track_name.track_namespace,
                                        full_track_name.track_name, 0, 0,
                                        &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeRelativeOk) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");
  MockLocalTrackVisitor server_visitor;
  MockRemoteTrackVisitor client_visitor;
  server_->session()->AddLocalTrack(
      full_track_name, MoqtForwardingPreference::kObject, &server_visitor);
  std::optional<absl::string_view> expected_reason = std::nullopt;
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeRelative(full_track_name.track_namespace,
                                        full_track_name.track_name, 10, 10,
                                        &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeCurrentGroupOk) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");
  MockLocalTrackVisitor server_visitor;
  MockRemoteTrackVisitor client_visitor;
  server_->session()->AddLocalTrack(
      full_track_name, MoqtForwardingPreference::kObject, &server_visitor);
  std::optional<absl::string_view> expected_reason = std::nullopt;
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeCurrentGroup(full_track_name.track_namespace,
                                            full_track_name.track_name,
                                            &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

TEST_F(MoqtIntegrationTest, SubscribeError) {
  EstablishSession();
  FullTrackName full_track_name("foo", "bar");
  MockRemoteTrackVisitor client_visitor;
  std::optional<absl::string_view> expected_reason = "Track does not exist";
  bool received_ok = false;
  EXPECT_CALL(client_visitor, OnReply(full_track_name, expected_reason))
      .WillOnce([&]() { received_ok = true; });
  client_->session()->SubscribeRelative(full_track_name.track_namespace,
                                        full_track_name.track_name, 10, 10,
                                        &client_visitor);
  bool success =
      test_harness_.RunUntilWithDefaultTimeout([&]() { return received_ok; });
  EXPECT_TRUE(success);
}

}  // namespace

}  // namespace moqt::test
