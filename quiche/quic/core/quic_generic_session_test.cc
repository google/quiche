// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An integration test that covers interactions between QuicGenericSession
// client and server sessions.

#include "quiche/quic/core/quic_generic_session.h"

#include <memory>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/crypto/quic_crypto_server_config.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_datagram_queue.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simulator/simulator.h"
#include "quiche/quic/test_tools/simulator/test_harness.h"
#include "quiche/quic/test_tools/web_transport_test_tools.h"
#include "quiche/quic/tools/web_transport_test_visitors.h"
#include "quiche/web_transport/web_transport.h"

namespace quic::test {
namespace {

enum ServerType { kDiscardServer, kEchoServer };

using simulator::Simulator;
using testing::_;
using testing::Assign;
using testing::AtMost;
using testing::Eq;

class CountingDatagramObserver : public QuicDatagramQueue::Observer {
 public:
  CountingDatagramObserver(int& total) : total_(total) {}
  void OnDatagramProcessed(absl::optional<MessageStatus>) { ++total_; }

 private:
  int& total_;
};

class ClientEndpoint : public simulator::QuicEndpointWithConnection {
 public:
  ClientEndpoint(Simulator* simulator, const std::string& name,
                 const std::string& peer_name, const QuicConfig& config)
      : QuicEndpointWithConnection(simulator, name, peer_name,
                                   Perspective::IS_CLIENT,
                                   GetQuicVersionsForGenericSession()),
        crypto_config_(crypto_test_utils::ProofVerifierForTesting()),
        session_(connection_.get(), false, nullptr, config, "test.example.com",
                 443, "example_alpn", &visitor_, /*visitor_owned=*/false,
                 std::make_unique<CountingDatagramObserver>(
                     total_datagrams_processed_),
                 &crypto_config_) {
    session_.Initialize();
    EXPECT_CALL(visitor_, OnSessionReady())
        .Times(AtMost(1))
        .WillOnce(Assign(&session_ready_, true));
  }

  QuicGenericClientSession* session() { return &session_; }
  MockWebTransportSessionVisitor* visitor() { return &visitor_; }

  bool session_ready() const { return session_ready_; }
  int total_datagrams_processed() const { return total_datagrams_processed_; }

 private:
  QuicCryptoClientConfig crypto_config_;
  MockWebTransportSessionVisitor visitor_;
  QuicGenericClientSession session_;
  bool session_ready_ = false;
  int total_datagrams_processed_ = 0;
};

class ServerEndpoint : public simulator::QuicEndpointWithConnection {
 public:
  ServerEndpoint(Simulator* simulator, const std::string& name,
                 const std::string& peer_name, const QuicConfig& config,
                 ServerType type)
      : QuicEndpointWithConnection(simulator, name, peer_name,
                                   Perspective::IS_SERVER,
                                   GetQuicVersionsForGenericSession()),
        crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        session_(connection_.get(), false, nullptr, config, "example_alpn",
                 type == kEchoServer
                     ? static_cast<webtransport::SessionVisitor*>(
                           new EchoWebTransportSessionVisitor(
                               &session_,
                               /*open_server_initiated_echo_stream=*/false))
                     : static_cast<webtransport::SessionVisitor*>(
                           new DiscardWebTransportSessionVisitor(&session_)),
                 /*owns_visitor=*/true,
                 /*datagram_observer=*/nullptr, &crypto_config_,
                 &compressed_certs_cache_) {
    session_.Initialize();
  }

  QuicGenericServerSession* session() { return &session_; }

 private:
  QuicCryptoServerConfig crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicGenericServerSession session_;
};

class QuicGenericSessionTest : public QuicTest {
 public:
  void CreateDefaultEndpoints(ServerType server_type) {
    client_ = std::make_unique<ClientEndpoint>(
        &test_harness_.simulator(), "Client", "Server", client_config_);
    server_ =
        std::make_unique<ServerEndpoint>(&test_harness_.simulator(), "Server",
                                         "Client", server_config_, server_type);
    test_harness_.set_client(client_.get());
    test_harness_.set_server(server_.get());
  }

  void WireUpEndpoints() { test_harness_.WireUpEndpoints(); }

  void RunHandshake() {
    client_->session()->CryptoConnect();
    bool result = test_harness_.RunUntilWithDefaultTimeout([this]() {
      return client_->session_ready() ||
             client_->session()->error() != QUIC_NO_ERROR;
    });
    EXPECT_TRUE(result);
  }

 protected:
  QuicConfig client_config_ = DefaultQuicConfig();
  QuicConfig server_config_ = DefaultQuicConfig();

  simulator::TestHarness test_harness_;

  std::unique_ptr<ClientEndpoint> client_;
  std::unique_ptr<ServerEndpoint> server_;
};

TEST_F(QuicGenericSessionTest, SuccessfulHandshake) {
  CreateDefaultEndpoints(kDiscardServer);
  WireUpEndpoints();
  RunHandshake();
  EXPECT_TRUE(client_->session_ready());
}

TEST_F(QuicGenericSessionTest, SendOutgoingStreams) {
  CreateDefaultEndpoints(kDiscardServer);
  WireUpEndpoints();
  RunHandshake();

  std::vector<webtransport::Stream*> streams;
  for (int i = 0; i < 10; i++) {
    webtransport::Stream* stream =
        client_->session()->OpenOutgoingUnidirectionalStream();
    ASSERT_TRUE(stream->Write("test"));
    streams.push_back(stream);
  }
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout([this]() {
    return QuicSessionPeer::GetNumOpenDynamicStreams(server_->session()) == 10;
  }));

  for (webtransport::Stream* stream : streams) {
    ASSERT_TRUE(stream->SendFin());
  }
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout([this]() {
    return QuicSessionPeer::GetNumOpenDynamicStreams(server_->session()) == 0;
  }));
}

TEST_F(QuicGenericSessionTest, EchoBidirectionalStreams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  webtransport::Stream* stream =
      client_->session()->OpenOutgoingBidirectionalStream();
  EXPECT_TRUE(stream->Write("Hello!"));

  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [stream]() { return stream->ReadableBytes() == strlen("Hello!"); }));
  std::string received;
  WebTransportStream::ReadResult result = stream->Read(&received);
  EXPECT_EQ(result.bytes_read, strlen("Hello!"));
  EXPECT_FALSE(result.fin);
  EXPECT_EQ(received, "Hello!");

  EXPECT_TRUE(stream->SendFin());
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout([this]() {
    return QuicSessionPeer::GetNumOpenDynamicStreams(server_->session()) == 0;
  }));
}

TEST_F(QuicGenericSessionTest, EchoUnidirectionalStreams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  // Send two streams, but only send FIN on the second one.
  webtransport::Stream* stream1 =
      client_->session()->OpenOutgoingUnidirectionalStream();
  EXPECT_TRUE(stream1->Write("Stream One"));
  webtransport::Stream* stream2 =
      client_->session()->OpenOutgoingUnidirectionalStream();
  EXPECT_TRUE(stream2->Write("Stream Two"));
  EXPECT_TRUE(stream2->SendFin());

  // Wait until a stream is received.
  bool stream_received = false;
  EXPECT_CALL(*client_->visitor(), OnIncomingUnidirectionalStreamAvailable())
      .Times(2)
      .WillRepeatedly(Assign(&stream_received, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&stream_received]() { return stream_received; }));

  // Receive a reply stream and expect it to be the second one.
  webtransport::Stream* reply =
      client_->session()->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(reply != nullptr);
  std::string buffer;
  WebTransportStream::ReadResult result = reply->Read(&buffer);
  EXPECT_GT(result.bytes_read, 0u);
  EXPECT_TRUE(result.fin);
  EXPECT_EQ(buffer, "Stream Two");

  // Reset reply-related variables.
  stream_received = false;
  buffer = "";

  // Send FIN on the first stream, and expect to receive it back.
  EXPECT_TRUE(stream1->SendFin());
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&stream_received]() { return stream_received; }));
  reply = client_->session()->AcceptIncomingUnidirectionalStream();
  ASSERT_TRUE(reply != nullptr);
  result = reply->Read(&buffer);
  EXPECT_GT(result.bytes_read, 0u);
  EXPECT_TRUE(result.fin);
  EXPECT_EQ(buffer, "Stream One");
}

TEST_F(QuicGenericSessionTest, EchoDatagram) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  client_->session()->SendOrQueueDatagram("test");

  bool datagram_received = false;
  EXPECT_CALL(*client_->visitor(), OnDatagramReceived(Eq("test")))
      .WillOnce(Assign(&datagram_received, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&datagram_received]() { return datagram_received; }));
}

// This test sets the datagram queue to an nearly-infinite queueing time, and
// then sends 1000 datagrams.  We expect to receive most of them back, since the
// datagrams would be paced out by the congestion controller.
TEST_F(QuicGenericSessionTest, EchoALotOfDatagrams) {
  CreateDefaultEndpoints(kEchoServer);
  WireUpEndpoints();
  RunHandshake();

  // Set the datagrams to effectively never expire.
  client_->session()->SetDatagramMaxTimeInQueue(
      (10000 * simulator::TestHarness::kRtt).ToAbsl());
  for (int i = 0; i < 1000; i++) {
    client_->session()->SendOrQueueDatagram(std::string(
        client_->session()->GetGuaranteedLargestMessagePayload(), 'a'));
  }

  size_t received = 0;
  EXPECT_CALL(*client_->visitor(), OnDatagramReceived(_))
      .WillRepeatedly(
          [&received](absl::string_view /*datagram*/) { received++; });
  ASSERT_TRUE(test_harness_.simulator().RunUntilOrTimeout(
      [this]() { return client_->total_datagrams_processed() >= 1000; },
      3 * simulator::TestHarness::kServerBandwidth.TransferTime(
              1000 * kMaxOutgoingPacketSize)));
  // Allow extra round-trips for the final flight of datagrams to arrive back.
  test_harness_.simulator().RunFor(2 * simulator::TestHarness::kRtt);

  EXPECT_GT(received, 500u);
  EXPECT_LT(received, 1000u);
}

TEST_F(QuicGenericSessionTest, OutgoingStreamFlowControlBlocked) {
  server_config_.SetMaxUnidirectionalStreamsToSend(4);
  CreateDefaultEndpoints(kDiscardServer);
  WireUpEndpoints();
  RunHandshake();

  webtransport::Stream* stream;
  for (int i = 0; i <= 3; i++) {
    ASSERT_TRUE(client_->session()->CanOpenNextOutgoingUnidirectionalStream());
    stream = client_->session()->OpenOutgoingUnidirectionalStream();
    ASSERT_TRUE(stream != nullptr);
    ASSERT_TRUE(stream->SendFin());
  }
  EXPECT_FALSE(client_->session()->CanOpenNextOutgoingUnidirectionalStream());

  // Receiving FINs for the streams we've just opened will cause the server to
  // let us open more streams.
  bool can_create_new_stream = false;
  EXPECT_CALL(*client_->visitor(), OnCanCreateNewOutgoingUnidirectionalStream())
      .WillOnce(Assign(&can_create_new_stream, true));
  ASSERT_TRUE(test_harness_.RunUntilWithDefaultTimeout(
      [&can_create_new_stream]() { return can_create_new_stream; }));
  EXPECT_TRUE(client_->session()->CanOpenNextOutgoingUnidirectionalStream());
}

}  // namespace
}  // namespace quic::test
