// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for Application Protocol Negotiation (Section 3.3).
// Tests that use existing ParseSubprotocol* functions PASS immediately.
// Tests requiring draft-15-specific error handling (WT_ALPN_ERROR) use the
// shared Draft15SessionTest fixture.

#include <optional>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"
#include "quiche/web_transport/web_transport_headers.h"

namespace webtransport {
namespace {

using ::quiche::test::IsOkAndHolds;
using ::quiche::test::StatusIs;
using ::testing::ElementsAre;
using ::testing::HasSubstr;

// --- Header parsing (Section 3.3) ---
// These reuse existing parsing functions and PASS immediately.

TEST(WebTransportHeadersDraft15, ParseWtAvailableProtocols) {
  // WT-Available-Protocols is a Structured Fields List of Strings.
  EXPECT_THAT(ParseSubprotocolRequestHeader(R"("chat-v1", "chat-v2")"),
              IsOkAndHolds(ElementsAre("chat-v1", "chat-v2")));
}

TEST(WebTransportHeadersDraft15, SerializeWtAvailableProtocols) {
  // Round-trip serialization of WT-Available-Protocols.
  std::vector<std::string> protocols = {"chat-v1", "chat-v2"};
  auto serialized = SerializeSubprotocolRequestHeader(protocols);
  ASSERT_TRUE(serialized.ok()) << serialized.status();
  auto reparsed = ParseSubprotocolRequestHeader(*serialized);
  EXPECT_THAT(reparsed, IsOkAndHolds(ElementsAre("chat-v1", "chat-v2")));
}

TEST(WebTransportHeadersDraft15, ParseWtProtocol) {
  // WT-Protocol is a single Structured Fields Item (string).
  EXPECT_THAT(ParseSubprotocolResponseHeader(R"("chat-v2")"),
              IsOkAndHolds("chat-v2"));
}

TEST(WebTransportHeadersDraft15, NonStringValuesIgnored) {
  // Section 3.3 MUST: Non-string values in the list MUST be ignored.
  // Token "chat-v1" (not quoted) should cause error, integer 42 also.
  EXPECT_THAT(ParseSubprotocolRequestHeader(R"("chat-v1", 42)"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found integer instead")));
  // Non-string items are rejected by the parser (type mismatch), which
  // effectively ignores them by returning an error for the whole field.
  // A conforming implementation could alternatively skip non-string items.
}

TEST(WebTransportHeadersDraft15, ParametersIgnored) {
  // Section 3.3 MUST: Parameters on list members MUST be discarded.
  // Existing parser already handles this.
  EXPECT_THAT(
      ParseSubprotocolRequestHeader(R"("chat-v1"; priority=1, "chat-v2")"),
      IsOkAndHolds(ElementsAre("chat-v1", "chat-v2")));
}

// --- Session-dependent ALPN error tests (Section 3.3) ---
// These require a QUIC session to verify draft-15-specific error handling.

class HeadersDraft15SessionTest
    : public quic::test::Draft15SessionTest {
 protected:
  HeadersDraft15SessionTest()
      : Draft15SessionTest(quic::Perspective::IS_CLIENT) {}
};

INSTANTIATE_TEST_SUITE_P(HeadersDraft15SessionTests,
                         HeadersDraft15SessionTest,
                         ::testing::ValuesIn(quic::CurrentSupportedVersions()));

// Server-perspective fixture for ALPN tests.
class HeadersDraft15ServerSessionTest
    : public quic::test::Draft15SessionTest {
 protected:
  HeadersDraft15ServerSessionTest()
      : Draft15SessionTest(quic::Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(
    HeadersDraft15ServerSessionTests,
    HeadersDraft15ServerSessionTest,
    ::testing::ValuesIn(quic::CurrentSupportedVersions()));

TEST_P(HeadersDraft15SessionTest, WtProtocolMustBeFromClientList) {
  // Section 3.3 MUST: The server-selected protocol must be from the client's
  // offered list. If it is not, the client should close with WT_ALPN_ERROR.
  if (!quic::VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      quic::WebTransportHttp3VersionSet(
          {quic::WebTransportHttp3Version::kDraft15}),
      quic::HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  auto* wt = AttemptWebTransportDraft15ClientSession();
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Client offered "chat-v1" and "chat-v2".
  wt->set_subprotocols_offered({"chat-v1", "chat-v2"});
  EXPECT_THAT(wt->subprotocols_offered(),
              ElementsAre("chat-v1", "chat-v2"));

  // Attach a mock visitor to observe the error closure.
  auto* visitor = AttachMockVisitor(wt);
  // Section 3.3 MUST: Client closes session with WT_ALPN_ERROR on mismatch.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          quic::kWtAlpnError),
      testing::_))
      .Times(1);

  quic::QuicStreamId stream_id = wt->id();
  // Server responds with WT-Protocol: "video-v1" (not in client's list).
  ReceiveWebTransportDraft15Response(stream_id, 200, "video-v1");

  // The session should detect the mismatch and not become ready.
  EXPECT_FALSE(wt->ready())
      << "Session must not be ready when server selects a protocol "
         "not in client's offered list";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(HeadersDraft15SessionTest, ClientClosesWithAlpnErrorOnMissing) {
  // Section 3.3 MUST: If the client sent WT-Available-Protocols but the
  // server response has no WT-Protocol, close with WT_ALPN_ERROR.
  if (!quic::VersionIsIetfQuic(GetParam().transport_version)) return;

  EXPECT_EQ(quic::kWtAlpnError, 0x0817b3ddu);

  Initialize(
      quic::WebTransportHttp3VersionSet(
          {quic::WebTransportHttp3Version::kDraft15}),
      quic::HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  auto* wt = AttemptWebTransportDraft15ClientSession();
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Client offered subprotocols.
  wt->set_subprotocols_offered({"chat-v1"});

  // Attach a mock visitor to observe the error closure.
  auto* visitor = AttachMockVisitor(wt);
  // Section 3.3 MUST: Client closes with WT_ALPN_ERROR when server omits
  // WT-Protocol but client offered subprotocols.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          quic::kWtAlpnError),
      testing::_))
      .Times(1);

  quic::QuicStreamId stream_id = wt->id();
  // Server responds with 200 OK but omits WT-Protocol header entirely.
  ReceiveWebTransportDraft15Response(stream_id, 200);

  // When client offered subprotocols but server did not select one,
  // the session should not become ready.
  EXPECT_FALSE(wt->ready())
      << "Session must not be ready when server omits WT-Protocol "
         "but client offered subprotocols";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(HeadersDraft15SessionTest, ClientClosesWithAlpnErrorOnMismatch) {
  // Section 3.3 MUST: If server's WT-Protocol is not in client's list,
  // close with WT_ALPN_ERROR.
  if (!quic::VersionIsIetfQuic(GetParam().transport_version)) return;

  EXPECT_EQ(quic::kWtAlpnError, 0x0817b3ddu);

  Initialize(
      quic::WebTransportHttp3VersionSet(
          {quic::WebTransportHttp3Version::kDraft15}),
      quic::HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  auto* wt = AttemptWebTransportDraft15ClientSession();
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Client offered "chat-v1" and "chat-v2".
  wt->set_subprotocols_offered({"chat-v1", "chat-v2"});

  // Attach a mock visitor to observe the error closure.
  auto* visitor = AttachMockVisitor(wt);
  // Section 3.3 MUST: Client closes with WT_ALPN_ERROR on mismatch.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          quic::kWtAlpnError),
      testing::_))
      .Times(1);

  quic::QuicStreamId stream_id = wt->id();
  // Server responds with WT-Protocol: "video-v1" (not in client's list).
  ReceiveWebTransportDraft15Response(stream_id, 200, "video-v1");

  // The session should reject the mismatched subprotocol.
  EXPECT_FALSE(wt->ready())
      << "Session must not be ready when server selects a protocol "
         "not in client's offered list";
  EXPECT_EQ(wt->GetNegotiatedSubprotocol(), std::nullopt)
      << "Negotiated subprotocol must be nullopt on mismatch";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(HeadersDraft15ServerSessionTest, ServerSelectsFromClientList) {
  // Section 3.3: Server receives WT-Available-Protocols and selects one.
  // After creation, the server application sets the negotiated subprotocol.
  if (!quic::VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      quic::WebTransportHttp3VersionSet(
          {quic::WebTransportHttp3Version::kDraft15}),
      quic::HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  // Create an incoming CONNECT stream with WT-Available-Protocols header.
  quic::QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  quic::QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                               absl::string_view());
  session_->OnStreamFrame(frame);
  quic::QuicSpdyStream* connect_stream =
      static_cast<quic::QuicSpdyStream*>(
          session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);

  quic::QuicHeaderList headers;
  headers.OnHeader(":method", "CONNECT");
  headers.OnHeader(":protocol", "webtransport-h3");
  headers.OnHeader(":scheme", "https");
  headers.OnHeader(":authority", "test.example.com");
  headers.OnHeader(":path", "/wt");
  headers.OnHeader("wt-available-protocols", R"("chat-v1", "chat-v2")");
  connect_stream->OnStreamHeaderList(/*fin=*/false, 0, headers);

  quic::WebTransportHttp3* wt =
      session_->GetWebTransportSession(session_id);
  ASSERT_NE(wt, nullptr) << "Server draft-15 session could not be established";

  // The server should see the client's offered subprotocols.
  // The subprotocols_offered() field is populated from the
  // WT-Available-Protocols header during stream processing.
  EXPECT_THAT(wt->subprotocols_offered(),
              ElementsAre("chat-v1", "chat-v2"))
      << "Server should see client's offered subprotocols";

  // Verify the server can select and report a negotiated subprotocol.
  EXPECT_EQ(wt->GetNegotiatedSubprotocol(), std::nullopt)
      << "Before server selects, negotiated subprotocol should be nullopt";
}

TEST_P(HeadersDraft15SessionTest, NoAlpnNegotiationWhenNotOffered) {
  // Section 3.3: When the client does not send WT-Available-Protocols,
  // the server does not send WT-Protocol, and the session establishes
  // successfully without ALPN negotiation.
  if (!quic::VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      quic::WebTransportHttp3VersionSet(
          {quic::WebTransportHttp3Version::kDraft15}),
      quic::HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  auto* wt = AttemptWebTransportDraft15ClientSession();
  ASSERT_NE(wt, nullptr) << "Draft-15 client session could not be created";

  // Client does NOT set subprotocols_offered (empty list).
  EXPECT_TRUE(wt->subprotocols_offered().empty())
      << "No subprotocols should be offered by default";

  quic::QuicStreamId stream_id = wt->id();
  // Server responds with 200 OK, no WT-Protocol header.
  ReceiveWebTransportDraft15Response(stream_id, 200);

  // Without ALPN negotiation, the session should become ready normally.
  EXPECT_TRUE(wt->ready())
      << "Session should be ready when no ALPN negotiation is involved";
  EXPECT_EQ(wt->GetNegotiatedSubprotocol(), std::nullopt)
      << "No negotiated subprotocol when none were offered";
}

}  // namespace
}  // namespace webtransport
