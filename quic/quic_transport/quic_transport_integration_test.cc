// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// An integration test that covers interactions between QuicTransport client and
// server sessions.

#include <memory>

#include "url/gurl.h"
#include "url/origin.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_client_config.h"
#include "net/third_party/quiche/src/quic/core/crypto/quic_crypto_server_config.h"
#include "net/third_party/quiche/src/quic/core/quic_connection.h"
#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_client_session.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_server_session.h"
#include "net/third_party/quiche/src/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_transport_test_tools.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/link.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/quic_endpoint_base.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/simulator.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/switch.h"

namespace quic {
namespace test {
namespace {

using simulator::QuicEndpointBase;
using simulator::Simulator;
using testing::_;
using testing::Return;

url::Origin GetTestOrigin() {
  constexpr char kTestOrigin[] = "https://test-origin.test";
  GURL origin_url(kTestOrigin);
  return url::Origin::Create(origin_url);
}

ParsedQuicVersionVector GetVersions() {
  return {ParsedQuicVersion{PROTOCOL_TLS1_3, QUIC_VERSION_99}};
}

class QuicTransportEndpointBase : public QuicEndpointBase {
 public:
  QuicTransportEndpointBase(Simulator* simulator,
                            const std::string& name,
                            const std::string& peer_name,
                            Perspective perspective)
      : QuicEndpointBase(simulator, name, peer_name) {
    connection_ = std::make_unique<QuicConnection>(
        TestConnectionId(0x10), simulator::GetAddressFromName(peer_name),
        simulator, simulator->GetAlarmFactory(), &writer_,
        /*owns_writer=*/false, perspective, GetVersions());
    connection_->SetSelfAddress(simulator::GetAddressFromName(name));

    SetQuicReloadableFlag(quic_supports_tls_handshake, true);
  }
};

class QuicTransportClientEndpoint : public QuicTransportEndpointBase {
 public:
  QuicTransportClientEndpoint(Simulator* simulator,
                              const std::string& name,
                              const std::string& peer_name,
                              url::Origin origin)
      : QuicTransportEndpointBase(simulator,
                                  name,
                                  peer_name,
                                  Perspective::IS_CLIENT),
        crypto_config_(crypto_test_utils::ProofVerifierForTesting()),
        session_(connection_.get(),
                 nullptr,
                 DefaultQuicConfig(),
                 GetVersions(),
                 QuicServerId("test.example.com", 443),
                 &crypto_config_,
                 origin,
                 &visitor_) {
    session_.Initialize();
  }

  QuicTransportClientSession* session() { return &session_; }

 private:
  QuicCryptoClientConfig crypto_config_;
  MockClientVisitor visitor_;
  QuicTransportClientSession session_;
};

class QuicTransportServerEndpoint : public QuicTransportEndpointBase {
 public:
  QuicTransportServerEndpoint(Simulator* simulator,
                              const std::string& name,
                              const std::string& peer_name)
      : QuicTransportEndpointBase(simulator,
                                  name,
                                  peer_name,
                                  Perspective::IS_SERVER),
        crypto_config_(QuicCryptoServerConfig::TESTING,
                       QuicRandom::GetInstance(),
                       crypto_test_utils::ProofSourceForTesting(),
                       KeyExchangeSource::Default()),
        compressed_certs_cache_(
            QuicCompressedCertsCache::kQuicCompressedCertsCacheSize),
        session_(connection_.get(),
                 nullptr,
                 DefaultQuicConfig(),
                 GetVersions(),
                 &crypto_config_,
                 &compressed_certs_cache_,
                 &visitor_) {
    session_.Initialize();
  }

  QuicTransportServerSession* session() { return &session_; }
  MockServerVisitor* visitor() { return &visitor_; }

 private:
  QuicCryptoServerConfig crypto_config_;
  QuicCompressedCertsCache compressed_certs_cache_;
  QuicTransportServerSession session_;
  MockServerVisitor visitor_;
};

constexpr QuicBandwidth kClientBandwidth =
    QuicBandwidth::FromKBitsPerSecond(10000);
constexpr QuicTime::Delta kClientPropagationDelay =
    QuicTime::Delta::FromMilliseconds(2);
constexpr QuicBandwidth kServerBandwidth =
    QuicBandwidth::FromKBitsPerSecond(4000);
constexpr QuicTime::Delta kServerPropagationDelay =
    QuicTime::Delta::FromMilliseconds(50);
const QuicTime::Delta kTransferTime =
    kClientBandwidth.TransferTime(kMaxOutgoingPacketSize) +
    kServerBandwidth.TransferTime(kMaxOutgoingPacketSize);
const QuicTime::Delta kRtt =
    (kClientPropagationDelay + kServerPropagationDelay + kTransferTime) * 2;
const QuicByteCount kBdp = kRtt * kServerBandwidth;

constexpr QuicTime::Delta kHandshakeTimeout = QuicTime::Delta::FromSeconds(3);

class QuicTransportIntegrationTest : public QuicTest {
 public:
  QuicTransportIntegrationTest()
      : switch_(&simulator_, "Switch", 8, 2 * kBdp) {}

  void CreateDefaultEndpoints() {
    client_ = std::make_unique<QuicTransportClientEndpoint>(
        &simulator_, "Client", "Server", GetTestOrigin());
    server_ = std::make_unique<QuicTransportServerEndpoint>(&simulator_,
                                                            "Server", "Client");
    ON_CALL(*server_->visitor(), CheckOrigin(_)).WillByDefault(Return(true));
  }

  void WireUpEndpoints() {
    client_link_ = std::make_unique<simulator::SymmetricLink>(
        client_.get(), switch_.port(1), kClientBandwidth,
        kClientPropagationDelay);
    server_link_ = std::make_unique<simulator::SymmetricLink>(
        server_.get(), switch_.port(2), kServerBandwidth,
        kServerPropagationDelay);
  }

  void RunHandshake() {
    client_->session()->CryptoConnect();
    bool result = simulator_.RunUntilOrTimeout(
        [this]() {
          return IsHandshakeDone(client_->session()) &&
                 IsHandshakeDone(server_->session());
        },
        kHandshakeTimeout);
    EXPECT_TRUE(result);
  }

 protected:
  template <class Session>
  static bool IsHandshakeDone(const Session* session) {
    return session->IsSessionReady() || session->error() != QUIC_NO_ERROR;
  }

  Simulator simulator_;
  simulator::Switch switch_;
  std::unique_ptr<simulator::SymmetricLink> client_link_;
  std::unique_ptr<simulator::SymmetricLink> server_link_;

  std::unique_ptr<QuicTransportClientEndpoint> client_;
  std::unique_ptr<QuicTransportServerEndpoint> server_;
};

TEST_F(QuicTransportIntegrationTest, SuccessfulHandshake) {
  CreateDefaultEndpoints();
  WireUpEndpoints();
  RunHandshake();
  EXPECT_TRUE(client_->session()->IsSessionReady());
  EXPECT_TRUE(server_->session()->IsSessionReady());
}

TEST_F(QuicTransportIntegrationTest, OriginMismatch) {
  CreateDefaultEndpoints();
  WireUpEndpoints();
  EXPECT_CALL(*server_->visitor(), CheckOrigin(_))
      .WillRepeatedly(Return(false));
  RunHandshake();
  // Wait until the client receives CONNECTION_CLOSE.
  simulator_.RunUntilOrTimeout(
      [this]() { return !client_->session()->connection()->connected(); },
      kHandshakeTimeout);
  EXPECT_TRUE(client_->session()->IsSessionReady());
  EXPECT_FALSE(server_->session()->IsSessionReady());
  EXPECT_FALSE(client_->session()->connection()->connected());
  EXPECT_FALSE(server_->session()->connection()->connected());
  EXPECT_EQ(client_->session()->error(),
            QUIC_TRANSPORT_INVALID_CLIENT_INDICATION);
  EXPECT_EQ(server_->session()->error(),
            QUIC_TRANSPORT_INVALID_CLIENT_INDICATION);
}

}  // namespace
}  // namespace test
}  // namespace quic
