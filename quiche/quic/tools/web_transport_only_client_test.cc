// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/web_transport_only_client.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/deterministic_connection_id_generator.h"
#include "quiche/quic/core/http/web_transport_only_dispatcher.h"
#include "quiche/quic/core/http/web_transport_only_server_session.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/quic_server_io_harness.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_version_manager.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/tools/quic_event_loop_tools.h"
#include "quiche/quic/tools/quic_simple_crypto_server_stream_helper.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_ip_address.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/web_transport.h"

namespace quic::test {
namespace {

class TestSessionVisitor : public webtransport::SessionVisitor {
 public:
  explicit TestSessionVisitor(bool* established, bool* closed)
      : established_(*established), closed_(*closed) {}

  void OnSessionReady() override { established_ = true; }
  void OnSessionClosed(webtransport::SessionErrorCode /*error_code*/,
                       const std::string& /*error_message*/) override {
    closed_ = true;
  }

  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(absl::string_view /*datagram*/) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

 private:
  bool& established_;
  bool& closed_;
};

class WebTransportOnlyTestServer {
 public:
  explicit WebTransportOnlyTestServer(bool* server_established,
                                      bool* server_closed)
      : crypto_config_("secret", QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        version_manager_(CurrentSupportedVersionsWithTls()),
        connection_id_generator_(kQuicDefaultConnectionIdLength),
        event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())),
        dispatcher_(&config_, &crypto_config_, &version_manager_,
                    std::make_unique<QuicDefaultConnectionHelper>(),
                    std::make_unique<QuicSimpleCryptoServerStreamHelper>(),
                    event_loop_->CreateAlarmFactory(),
                    kQuicDefaultConnectionIdLength, connection_id_generator_) {
    dispatcher_.parameters().handler_factory =
        [server_established, server_closed](
            webtransport::Session*, const WebTransportIncomingRequestDetails&)
        -> absl::StatusOr<WebTransportConnectResponse> {
      WebTransportConnectResponse response;
      response.visitor = std::make_unique<TestSessionVisitor>(
          server_established, server_closed);
      return response;
    };
    dispatcher_.parameters().subprotocol_callback =
        [](absl::Span<const absl::string_view> subprotocols) {
          return subprotocols.empty() ? -1 : 0;
        };

    QuicSocketAddress address(quiche::QuicheIpAddress::Loopback6(), /*port=*/0);
    absl::StatusOr<OwnedSocketFd> fd = CreateAndBindServerSocket(address);
    QUICHE_CHECK(fd.ok());
    fd_ = std::move(*fd);

    absl::StatusOr<std::unique_ptr<QuicServerIoHarness>> io =
        QuicServerIoHarness::Create(event_loop_.get(), &dispatcher_, *fd_);
    QUICHE_CHECK(io.ok());
    io_ = std::move(*io);
    io_->InitializeWriter();
  }

  QuicSocketAddress server_address() const { return io_->local_address(); }
  QuicEventLoop* event_loop() { return event_loop_.get(); }

 private:
  QuicConfig config_;
  QuicCryptoServerConfig crypto_config_;
  QuicVersionManager version_manager_;
  DeterministicConnectionIdGenerator connection_id_generator_;
  std::unique_ptr<QuicEventLoop> event_loop_;
  WebTransportOnlyDispatcher dispatcher_;
  OwnedSocketFd fd_;
  std::unique_ptr<QuicServerIoHarness> io_;
};

class WebTransportOnlyClientTest : public QuicTest {};

TEST_F(WebTransportOnlyClientTest, SuccessfulConnection) {
  bool server_established = false;
  bool server_closed = false;
  WebTransportOnlyTestServer server(&server_established, &server_closed);

  bool client_established = false;
  bool client_closed = false;

  auto client = std::make_unique<WebTransportOnlyClient>(
      server.server_address(), QuicServerId("test.example.com", 443),
      CurrentSupportedVersionsWithTls(), QuicConfig(), server.event_loop(),
      /*network_helper=*/nullptr, crypto_test_utils::ProofVerifierForTesting(),
      /*session_cache=*/nullptr);

  // Note: the `ConnectSync` call below implicitly drives both the client and
  // the server, since both use the same event loop.
  absl::Status status =
      client->ConnectSync("/test", [&](webtransport::Session*) {
        return std::make_unique<TestSessionVisitor>(&client_established,
                                                    &client_closed);
      });
  QUICHE_ASSERT_OK(status);

  bool handshake_success = ProcessEventsUntil(server.event_loop(), [&] {
    return client_established && server_established;
  });
  EXPECT_TRUE(handshake_success);
  EXPECT_FALSE(client_closed);
  EXPECT_FALSE(server_closed);

  client->Disconnect();
  EXPECT_TRUE(client_closed);

  bool server_close_success =
      ProcessEventsUntil(server.event_loop(), [&] { return server_closed; });
  EXPECT_TRUE(server_close_success);
  EXPECT_TRUE(server_closed);
}

}  // namespace
}  // namespace quic::test
