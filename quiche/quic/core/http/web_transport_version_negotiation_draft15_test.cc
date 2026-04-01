// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for version negotiation (Section 7.1, 9.2).

#include <cstdint>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/quic_header_list.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/capsule.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"

namespace quic {
namespace {

using ::testing::_;

// --- SETTINGS codepoint (Section 9.2) ---

TEST(WebTransportVersionNegotiationDraft15, Draft15Codepoint) {
  // SETTINGS_WT_ENABLED uses codepoint 0x2c7cf000 in draft-15.
  EXPECT_EQ(webtransport::draft15::kSettingsWtEnabled, 0x2c7cf000u);
  // Verify legacy codepoints for comparison.
  EXPECT_EQ(static_cast<uint64_t>(SETTINGS_WEBTRANS_DRAFT00), 0x2b603742u);
  EXPECT_EQ(static_cast<uint64_t>(SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07),
            0xc671706au);
  // Legacy codepoints must match our constants.
  EXPECT_EQ(webtransport::draft15::kSettingsWebtransDraft00,
            static_cast<uint64_t>(SETTINGS_WEBTRANS_DRAFT00));
  EXPECT_EQ(webtransport::draft15::kSettingsWebtransMaxSessionsDraft07,
            static_cast<uint64_t>(SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07));
}

TEST(WebTransportVersionNegotiationDraft15, VersionEnumHasDraft15) {
  // Structural: WebTransportHttp3Version must include a draft-15 value.
  WebTransportHttp3VersionSet versions({WebTransportHttp3Version::kDraft02,
                                        WebTransportHttp3Version::kDraft07,
                                        WebTransportHttp3Version::kDraft15});
  EXPECT_TRUE(versions.IsSet(WebTransportHttp3Version::kDraft02));
  EXPECT_TRUE(versions.IsSet(WebTransportHttp3Version::kDraft07));
  EXPECT_TRUE(versions.IsSet(WebTransportHttp3Version::kDraft15));
}

// --- Session-based version negotiation tests (Section 7.1) ---

class VersionNegotiationDraft15SessionTest : public test::Draft15SessionTest {
 protected:
  VersionNegotiationDraft15SessionTest()
      : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(VersionNegotiationDraft15,
                         VersionNegotiationDraft15SessionTest,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(VersionNegotiationDraft15SessionTest,
       BothEndpointsSendSettingsWtEnabled) {
  // Section 7.1 MUST: Both client and server must emit SETTINGS_WT_ENABLED.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Check that emitted SETTINGS contains SETTINGS_WT_ENABLED.
  // Fails because FillSettingsFrame() has no kDraft15 branch.
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Expected SETTINGS_WT_ENABLED in emitted settings";
}

TEST_P(VersionNegotiationDraft15SessionTest, MultiVersionSupport) {
  // Section 7.1: An endpoint supporting multiple drafts sends
  // SETTINGS_WT_ENABLED for each.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07,
                                   WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Expect both draft-07 and draft-15 settings emitted.
  EXPECT_TRUE(
      session_->settings().values.contains(SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07));
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Expected SETTINGS_WT_ENABLED for draft-15 in multi-version settings";
}

TEST_P(VersionNegotiationDraft15SessionTest, HighestMutuallySupportedWins) {
  // Section 7.1: When both endpoints support draft-07 and draft-15,
  // draft-15 is selected (highest mutually supported).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07,
                                   WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();  // Peer also supports draft-15
  ASSERT_TRUE(session_->SupportsWebTransport())
      << "Draft-15 not yet negotiated";
  EXPECT_EQ(session_->SupportedWebTransportVersion(),
            WebTransportHttp3Version::kDraft15);
}

TEST_P(VersionNegotiationDraft15SessionTest, FallbackWhenMismatch) {
  // Section 7.1: If server supports only draft-15 and client only draft-07,
  // WebTransport is not available.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Verify we emitted draft-15 settings locally
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Local side should emit SETTINGS_WT_ENABLED for draft-15";
  // Peer only supports draft-07
  ReceiveWebTransportDraft07Settings();
  // No mutual version -- WebTransport should not be available
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "No mutual version -- WT should not be available";
}

TEST_P(VersionNegotiationDraft15SessionTest, Draft15OnlyNoLegacySettings) {
  // When only draft-15 is locally supported, the emitted SETTINGS must NOT
  // contain legacy draft-00 or draft-07 codepoints.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // Draft-15 settings should be present.
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Draft-15 only: must emit SETTINGS_WT_ENABLED";

  // Legacy settings must NOT be present when only draft-15 is configured.
  EXPECT_FALSE(
      session_->settings().values.contains(SETTINGS_WEBTRANS_DRAFT00))
      << "Draft-15 only: must NOT emit SETTINGS_WEBTRANS_DRAFT00";
  EXPECT_FALSE(
      session_->settings().values.contains(SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07))
      << "Draft-15 only: must NOT emit SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07";
}

TEST_P(VersionNegotiationDraft15SessionTest, Draft07OnlyNoNewSettings) {
  // When only draft-07 is locally supported, the emitted SETTINGS must NOT
  // contain the draft-15 SETTINGS_WT_ENABLED codepoint.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // Draft-07 settings should be present.
  EXPECT_TRUE(
      session_->settings().values.contains(SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07))
      << "Draft-07 only: must emit SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07";

  // Draft-15 settings must NOT be present when only draft-07 is configured.
  EXPECT_FALSE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Draft-07 only: must NOT emit SETTINGS_WT_ENABLED";
}

// --- Draft-07 compatibility tests ---
// Draft-07 sessions should silently ignore draft-15-only FC capsules.

class Draft07CompatibilityTest : public test::Draft15SessionTest {
 protected:
  Draft07CompatibilityTest() : Draft15SessionTest(Perspective::IS_SERVER) {}

  // Sends a CONNECT request with :protocol = "webtransport" (draft-07 style).
  // Unlike ReceiveWebTransportSession() in quic_spdy_session_test_utils.h,
  // does NOT send fin=true on headers (WT sessions keep the CONNECT stream
  // open).
  WebTransportHttp3* AttemptDraft07Session(QuicStreamId session_id) {
    QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
    session_->OnStreamFrame(frame);
    QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
        session_->GetOrCreateStream(session_id));
    if (connect_stream == nullptr) return nullptr;
    QuicHeaderList headers;
    headers.OnHeader(":method", "CONNECT");
    headers.OnHeader(":protocol", "webtransport");
    connect_stream->OnStreamHeaderList(/*fin=*/false, 0, headers);
    WebTransportHttp3* wt = session_->GetWebTransportSession(session_id);
    if (wt != nullptr) {
      quiche::HttpHeaderBlock header_block;
      wt->HeadersReceived(header_block);
    }
    return wt;
  }
};

INSTANTIATE_TEST_SUITE_P(Draft07Compatibility, Draft07CompatibilityTest,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(Draft07CompatibilityTest, Draft07_IgnoresWtMaxStreamDataCapsule) {
  // In draft-07, WT_MAX_STREAM_DATA is irrelevant (it's a draft-15 /
  // WT-over-HTTP/2 capsule) and should be silently ignored.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft07Settings();

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptDraft07Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-07 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // The session must NOT be closed.
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(0);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Inject a WT_MAX_STREAM_DATA capsule — should be silently ignored.
  InjectCapsuleOnConnectStream(
      session_id,
      quiche::Capsule(quiche::WebTransportMaxStreamDataCapsule{
          /*stream_id=*/0, /*max_stream_data=*/1024}));

  EXPECT_TRUE(connection_->connected())
      << "Draft-07: WT_MAX_STREAM_DATA should be silently ignored.";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(Draft07CompatibilityTest, Draft07_IgnoresWtStreamDataBlockedCapsule) {
  // Same as above but for WT_STREAM_DATA_BLOCKED.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft07Settings();

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptDraft07Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-07 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // The session must NOT be closed.
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(0);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Inject a WT_STREAM_DATA_BLOCKED capsule — should be silently ignored.
  InjectCapsuleOnConnectStream(
      session_id,
      quiche::Capsule(quiche::WebTransportStreamDataBlockedCapsule{
          /*stream_id=*/0, /*stream_data_limit=*/512}));

  EXPECT_TRUE(connection_->connected())
      << "Draft-07: WT_STREAM_DATA_BLOCKED should be silently ignored.";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

}  // namespace
}  // namespace quic
