// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_simple_client_session.h"

#include <memory>

#include "quiche/quic/core/crypto/quic_crypto_client_config.h"
#include "quiche/quic/core/http/quic_header_list.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/http/http_header_block.h"

namespace quic {
namespace test {
namespace {

class QuicSimpleClientSessionTest
    : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  QuicSimpleClientSessionTest()
      : helper_(),
        connection_(new ::testing::NiceMock<MockQuicConnection>(
            &helper_, &alarm_factory_, Perspective::IS_CLIENT,
            SupportedVersions(GetParam()))),
        crypto_config_(std::make_unique<QuicCryptoClientConfig>(
            crypto_test_utils::ProofVerifierForTesting())),
        session_(QuicConfig(), SupportedVersions(GetParam()), connection_,
                 /*network_helper=*/nullptr, QuicServerId("example.com", 443),
                 crypto_config_.get(),
                 /*drop_response_body=*/false,
                 /*enable_web_transport=*/false) {
    session_.Initialize();
    if (VersionIsIetfQuic(connection_->transport_version())) {
      QuicSessionPeer::SetMaxOpenOutgoingBidirectionalStreams(&session_, 100);
    } else {
      QuicSessionPeer::SetMaxOpenOutgoingStreams(&session_, 100);
    }
  }
  ~QuicSimpleClientSessionTest() override = default;

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;  // Owned by session_
  std::unique_ptr<QuicCryptoClientConfig> crypto_config_;
  QuicSimpleClientSession session_;
};

INSTANTIATE_TEST_SUITE_P(
    Tests, QuicSimpleClientSessionTest,
    ::testing::ValuesIn(CurrentSupportedVersionsForClients()),
    ::testing::PrintToStringParamName());

TEST_P(QuicSimpleClientSessionTest, OnInterimHeaders) {
  auto stream = session_.CreateClientStream();
  quiche::HttpHeaderBlock headers;
  headers[":status"] = "103";
  QuicHeaderList header_list = AsHeaderList(headers);

  bool callback_called = false;
  session_.set_on_interim_headers(
      [&callback_called](const quiche::HttpHeaderBlock& h) {
        callback_called = true;
        auto it = h.find(":status");
        EXPECT_NE(it, h.end());
        if (it != h.end()) {
          EXPECT_EQ(it->second, "103");
        }
      });

  stream->OnStreamHeaderList(/*fin=*/false, 0, header_list);
  EXPECT_TRUE(callback_called);
}

TEST_P(QuicSimpleClientSessionTest, OnInterimHeadersWithoutCallback) {
  auto stream = session_.CreateClientStream();
  quiche::HttpHeaderBlock headers;
  headers[":status"] = "103";
  QuicHeaderList header_list = AsHeaderList(headers);

  // Deliver headers to stream. This should parse status 103, add a preliminary
  // header block, and try to invoke session's interim headers callback.
  // This should not crash even if no callback is registered.
  stream->OnStreamHeaderList(/*fin=*/false, 0, header_list);
}

}  // namespace
}  // namespace test
}  // namespace quic
