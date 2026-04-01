// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for session limiting (Section 5.2).

#include <cstdint>

#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"

namespace quic {
namespace {

using ::testing::_;
using ::testing::Not;

class SessionLimitingDraft15Test : public test::Draft15SessionTest {
 protected:
  SessionLimitingDraft15Test() : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(SessionLimitingDraft15, SessionLimitingDraft15Test,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(SessionLimitingDraft15Test,
       Section5_1_ExcessSessionResetWithRequestRejected) {
  // Section 5.1 MUST: "A server that receives more than one session on an
  // underlying transport connection when flow control is not enabled MUST
  // reset the excessive CONNECT streams with a H3_REQUEST_REJECTED status."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/0,
                         /*initial_max_streams_bidi=*/0,
                         /*initial_max_data=*/0);

  // First session succeeds.
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Attempt second session. The CONNECT stream MUST be reset with
  // H3_REQUEST_REJECTED (0x10B).
  EXPECT_CALL(*connection_,
              SendControlFrame(test::IsRstStreamWithIetfCode(
                  static_cast<uint64_t>(QuicHttp3ErrorCode::REQUEST_REJECTED))))
      .Times(testing::AtLeast(1))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_,
              SendControlFrame(
                  Not(test::IsRstStreamWithIetfCode(static_cast<uint64_t>(
                      QuicHttp3ErrorCode::REQUEST_REJECTED)))))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  QuicStreamId second_id = GetNthClientInitiatedBidirectionalId(1);
  auto* wt2 = AttemptWebTransportDraft15Session(second_id);
  EXPECT_EQ(wt2, nullptr)
      << "Server should reject excess sessions";
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(SessionLimitingDraft15Test,
       Section5_1_CanCreateNewSessionAfterPreviousClosed) {
  // Section 5.1: Without FC, at most one session is allowed. After
  // explicitly closing a session, the counter must decrement so a
  // new session can be created.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1);

  QuicStreamId first_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(first_id);
  ASSERT_NE(wt, nullptr);

  // Close the first session.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  wt->CloseSession(0, "done");
  testing::Mock::VerifyAndClearExpectations(writer_);

  // After closing, CanCreateNewWebTransportSession() should return true.
  EXPECT_TRUE(session_->CanCreateNewWebTransportSession())
      << "After closing a session, the session count "
         "should decrement to allow creating a new session";
}

TEST_P(SessionLimitingDraft15Test,
       Section5_1_CanCreateNewSessionAfterPeerClose) {
  // Section 5.1: Without FC, at most one session is allowed. After the
  // PEER closes a session, the counter must decrement so a new session
  // can be created.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1);

  QuicStreamId first_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(first_id);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  wt->OnCloseReceived(0, "bye");
  testing::Mock::VerifyAndClearExpectations(writer_);
  testing::Mock::VerifyAndClearExpectations(connection_);

  EXPECT_TRUE(session_->CanCreateNewWebTransportSession())
      << "After peer closes a session, the session count "
         "should decrement to allow creating a new session";
}

TEST_P(SessionLimitingDraft15Test,
       Section6_8_SessionCountDecrementsAfterPeerClose) {
  // Section 6.8: After a peer-initiated session close, the session count
  // must decrement, allowing a new session to be created (no FC).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1);

  QuicStreamId first_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(first_id);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  wt->OnCloseReceived(0, "done");
  testing::Mock::VerifyAndClearExpectations(writer_);
  testing::Mock::VerifyAndClearExpectations(connection_);

  QuicStreamId second_id = GetNthClientInitiatedBidirectionalId(1);
  auto* wt2 = AttemptWebTransportDraft15Session(second_id);
  EXPECT_NE(wt2, nullptr)
      << "After peer-initiated close, session count should "
         "decrement and a new session should be creatable";
}

TEST_P(SessionLimitingDraft15Test, FCEnabledAllowsMultipleSessions) {
  // With non-zero FC limits, multiple sessions should be allowed.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  // First session.
  auto* wt1 = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt1, nullptr) << "First session should succeed";

  // Second session should also succeed when FC is enabled.
  auto* wt2 = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(1));
  EXPECT_NE(wt2, nullptr)
      << "With FC enabled, multiple sessions should be allowed";
}

}  // namespace
}  // namespace quic
