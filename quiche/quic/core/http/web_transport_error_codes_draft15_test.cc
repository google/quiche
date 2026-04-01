// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for WebTransport error code mapping and new
// error code codepoints (Section 4.4, 9.5).

#include <cstdint>
#include <optional>

#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"

namespace quic {
namespace {

using ::testing::_;
using ::testing::Not;
using ::testing::Optional;

// --- Error code mapping (Section 4.4) ---
// These tests validate the WebTransport <-> HTTP/3 error code mapping algorithm.
// The mapping is the same across drafts, so these PASS immediately.

TEST(WebTransportErrorCodesDraft15, ErrorCodeRangeFirst) {
  // WebTransportErrorToHttp3(0) must equal the first app error codepoint.
  EXPECT_EQ(webtransport::draft15::kWtApplicationErrorFirst,
            WebTransportErrorToHttp3(0x00));
}

TEST(WebTransportErrorCodesDraft15, ErrorCodeRangeLast) {
  // WebTransportErrorToHttp3(0xffffffff) must equal the last app error
  // codepoint.
  EXPECT_EQ(webtransport::draft15::kWtApplicationErrorLast,
            WebTransportErrorToHttp3(0xffffffff));
}

TEST(WebTransportErrorCodesDraft15, GREASESkipping) {
  // The mapping must skip GREASE codepoints (0x1f * N + 0x21).
  // Error 0x1c maps to a non-GREASE value:
  uint64_t mapped_1c = WebTransportErrorToHttp3(0x1c);
  EXPECT_NE(mapped_1c % 0x1f, 0x21 % 0x1f)
      << "Error 0x1c should not map to a GREASE codepoint";

  // Error 0x1d maps to a non-GREASE value:
  uint64_t mapped_1d = WebTransportErrorToHttp3(0x1d);
  EXPECT_NE(mapped_1d % 0x1f, 0x21 % 0x1f)
      << "Error 0x1d should not map to a GREASE codepoint";

  // The codepoint between them (0x52e4a40fa8f9) IS a GREASE codepoint and
  // must not appear in the range of the mapping.
  EXPECT_EQ(Http3ErrorToWebTransport(0x52e4a40fa8f9), std::nullopt)
      << "GREASE codepoint must not reverse-map to a valid error";
}

TEST(WebTransportErrorCodesDraft15, OutsideApplicationErrorRange) {
  // Codes outside the WT_APPLICATION_ERROR range should not map.
  EXPECT_EQ(Http3ErrorToWebTransport(0), std::nullopt);
  EXPECT_EQ(
      Http3ErrorToWebTransport(webtransport::draft15::kWtApplicationErrorFirst -
                               1),
      std::nullopt);
  EXPECT_EQ(
      Http3ErrorToWebTransport(webtransport::draft15::kWtApplicationErrorLast +
                               1),
      std::nullopt);
}

// --- Error code round-trip test (Section 4.4) ---
// Verifies that encoding then decoding produces the original value for
// several representative error codes.

TEST(WebTransportErrorCodesDraft15, ErrorCodeRoundTrip) {
  // For several representative error codes, verify the round-trip:
  // Http3ErrorToWebTransport(WebTransportErrorToHttp3(e)) == e
  const uint32_t test_codes[] = {0, 0xff, 0xffff, 0xffffffff};
  for (uint32_t e : test_codes) {
    uint64_t http3_code = WebTransportErrorToHttp3(e);
    EXPECT_THAT(Http3ErrorToWebTransport(http3_code), Optional(e))
        << "Round-trip failed for error code " << e;
  }
}

// --- SessionGoneOnStreamReset (Section 9.5) ---
// Verifies the kWtSessionGone constant and documents expected behavior.

TEST(WebTransportErrorCodesDraft15, SessionGoneOnStreamReset) {
  // kWtSessionGone (0x170d7b68) is an HTTP/3 error code used to reset
  // streams associated with a terminated WebTransport session.
  // This is a fixed protocol error code, not an application error code,
  // so it should NOT reverse-map via Http3ErrorToWebTransport (which only
  // handles the WT_APPLICATION_ERROR range).
  EXPECT_EQ(webtransport::draft15::kWtSessionGone, 0x170d7b68u);
  EXPECT_EQ(Http3ErrorToWebTransport(webtransport::draft15::kWtSessionGone),
            std::nullopt)
      << "kWtSessionGone is a protocol error code, not an application error; "
         "it should not reverse-map";
}

// --- ResetStreamAtReliableSize (Section 4.4, requires session) ---

class ErrorCodesDraft15SessionTest : public test::Draft15SessionTest {
 protected:
  ErrorCodesDraft15SessionTest() : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(ErrorCodesDraft15SessionTests,
                         ErrorCodesDraft15SessionTest,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(ErrorCodesDraft15SessionTest,
       SessionTerminationAbortsIncomingStreamsWithSessionGone) {
  // Section 6: "the endpoint MUST reset the send side and abort reading on
  // the receive side of all [...] streams [...] using the WT_SESSION_GONE
  // error code." For incoming streams, "abort reading" means STOP_SENDING.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(
      GetNthClientInitiatedBidirectionalId(0),
      /*initial_max_streams_uni=*/10,
      /*initial_max_streams_bidi=*/10,
      /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Receive a peer-initiated unidirectional stream.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(testing::AnyNumber());
  ReceiveWebTransportUnidirectionalStream(
      GetNthClientInitiatedBidirectionalId(0),
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4),
      "data");
  ASSERT_GT(wt->NumberOfAssociatedStreams(), 0u);
  testing::Mock::VerifyAndClearExpectations(connection_);

  // Close the session. The incoming stream must receive STOP_SENDING
  // with kWtSessionGone (0x170d7b68).
  EXPECT_CALL(*connection_,
              SendControlFrame(test::IsStopSendingWithIetfCode(
                  webtransport::draft15::kWtSessionGone)))
      .Times(testing::AtLeast(1))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_,
              SendControlFrame(Not(test::IsStopSendingWithIetfCode(
                  webtransport::draft15::kWtSessionGone))))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(testing::AnyNumber());
  wt->CloseSession(0, "closing");
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(ErrorCodesDraft15SessionTest,
       SessionTerminationResetsOutgoingStreamsWithSessionGone) {
  // Section 6: "the endpoint MUST reset the send side [...] of all [...]
  // streams [...] using the WT_SESSION_GONE error code."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(
      GetNthClientInitiatedBidirectionalId(0),
      /*initial_max_streams_uni=*/10,
      /*initial_max_streams_bidi=*/10,
      /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open an outgoing unidirectional stream and write data.
  webtransport::Stream* stream = wt->OpenOutgoingUnidirectionalStream();
  ASSERT_NE(stream, nullptr);
  EXPECT_TRUE(stream->Write("payload"));
  QuicStreamId stream_id = stream->GetStreamId();
  ASSERT_GT(wt->NumberOfAssociatedStreams(), 0u);

  // Get the underlying QUIC stream before CloseSession destroys it.
  QuicStream* quic_stream = session_->GetActiveStream(stream_id);
  ASSERT_NE(quic_stream, nullptr);

  // Close the session.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(testing::AnyNumber());
  wt->CloseSession(0, "closing");
  EXPECT_EQ(wt->NumberOfAssociatedStreams(), 0u);

  // The stream's error code must be kWtSessionGone on the wire.
  EXPECT_EQ(quic_stream->ietf_application_error(),
            webtransport::draft15::kWtSessionGone);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(ErrorCodesDraft15SessionTest,
       Section4_4_NonWtErrorCodeDeliveredAsZero) {
  // Section 4.4.2 SHOULD: "If an endpoint receives a RESET_STREAM [...]
  // with an error code that is [...] not in the WebTransport application
  // error code range, it SHOULD be treated as a stream reset with no
  // application error provided."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _)).Times(testing::AnyNumber());
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_id, "data");

  WebTransportStream* wt_stream = wt->AcceptIncomingUnidirectionalStream();
  ASSERT_NE(wt_stream, nullptr);

  auto stream_visitor =
      std::make_unique<testing::StrictMock<webtransport::test::MockStreamVisitor>>();
  auto* raw_stream_visitor = stream_visitor.get();
  wt_stream->SetVisitor(std::move(stream_visitor));

  // 0x42 is outside the WT application error range
  // [kWebTransportMappedErrorCodeFirst, ...].
  QuicStreamId quic_stream_id =
      static_cast<QuicStreamId>(wt_stream->GetStreamId());
  QuicRstStreamFrame rst_frame(/*control_frame_id=*/1, quic_stream_id,
                               QUIC_STREAM_CANCELLED, /*bytes_written=*/0);
  rst_frame.ietf_error_code = 0x42;

  EXPECT_CALL(*raw_stream_visitor, OnResetStreamReceived(0))
      .Times(1);
  auto* quic_stream = session_->GetOrCreateStream(quic_stream_id);
  ASSERT_NE(quic_stream, nullptr);
  quic_stream->OnStreamReset(rst_frame);
  testing::Mock::VerifyAndClearExpectations(raw_stream_visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(ErrorCodesDraft15SessionTest,
       Section4_4_ResetAssociatedStreamsUsesResetStreamAt) {
  // Section 4.4 MUST: When a session is terminated and associated streams
  // are reset, RESET_STREAM_AT must be used (not plain RST_STREAM).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0),
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Open a WT stream and write some data so it has a preamble.
  webtransport::Stream* stream = wt->OpenOutgoingUnidirectionalStream();
  ASSERT_NE(stream, nullptr);
  EXPECT_TRUE(stream->Write("hello"));

  // Close the session — ResetAssociatedStreams() should use RESET_STREAM_AT.
  bool got_rst_stream_at = false;
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly([&got_rst_stream_at](const QuicFrame& frame) {
        if (frame.type == RESET_STREAM_AT_FRAME) {
          got_rst_stream_at = true;
        }
        test::ClearControlFrame(frame);
        return true;
      });

  wt->CloseSession(0, "done");

  EXPECT_TRUE(got_rst_stream_at)
      << "ResetAssociatedStreams must use RESET_STREAM_AT, "
         "not plain RST_STREAM, when resetting WT data streams during "
         "session teardown";
  testing::Mock::VerifyAndClearExpectations(writer_);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

// --- Error code value assertions (Section 9.5) ---
// These verify the IANA-registered codepoint values. PASS immediately since
// they only check compile-time constants.

TEST(WebTransportErrorCodesDraft15, WtBufferedStreamRejectedValue) {
  EXPECT_EQ(webtransport::draft15::kWtBufferedStreamRejected, 0x3994bd84u);
}

TEST(WebTransportErrorCodesDraft15, WtSessionGoneValue) {
  EXPECT_EQ(webtransport::draft15::kWtSessionGone, 0x170d7b68u);
}

TEST(WebTransportErrorCodesDraft15, WtFlowControlErrorValue) {
  EXPECT_EQ(kWtFlowControlError, 0x045d4487u);
}

TEST(WebTransportErrorCodesDraft15, WtAlpnErrorValue) {
  EXPECT_EQ(kWtAlpnError, 0x0817b3ddu);
}

TEST(WebTransportErrorCodesDraft15, WtRequirementsNotMetValue) {
  EXPECT_EQ(webtransport::draft15::kWtRequirementsNotMet, 0x212c0d48u);
}

TEST_P(ErrorCodesDraft15SessionTest, Section6_OversizedCloseMessageRejected) {
  // Section 6: "its length MUST NOT exceed 1024 bytes."
  // A WT_CLOSE_SESSION capsule with an error message exceeding 1024 bytes
  // should be treated as a protocol error, NOT accepted as a normal close.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Deliver an oversized CLOSE_WEBTRANSPORT_SESSION.
  std::string oversized_message(2000, 'x');
  wt->OnCloseReceived(/*error_code=*/42, oversized_message);

  // The close should be REJECTED (protocol error), NOT accepted.
  // close_received() returns true only when the close is accepted normally.
  EXPECT_FALSE(wt->close_received())
      << "Oversized error message (>1024 bytes) should be "
         "rejected as a protocol error, not accepted as a normal close";
}

TEST_P(ErrorCodesDraft15SessionTest,
       Section6_OversizedCloseMessageUsesCorrectErrorCode) {
  // Section 9.5: WT_FLOW_CONTROL_ERROR (0x045d4487) is defined as
  // "flow control error". An oversized close message is a framing violation,
  // not a flow control error. The error code should NOT be kWtFlowControlError.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // A mock is necessary here because there's no other way to observe
  // the error code used in the session closure.
  EXPECT_CALL(*visitor, OnSessionClosed(
      Not(static_cast<webtransport::SessionErrorCode>(kWtFlowControlError)),
      _))
      .Times(1);

  std::string oversized(2000, 'x');
  wt->OnCloseReceived(0, oversized);
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(ErrorCodesDraft15SessionTest,
       Section6_CloseSessionTruncatesOversizedMessage) {
  // Section 6 MUST NOT: "its length MUST NOT exceed 1024 bytes."
  // The sending side must truncate oversized error messages.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  std::string long_message(2000, 'x');
  EXPECT_QUICHE_BUG(wt->CloseSession(42, long_message),
                    "exceeds 1024 bytes");
}

}  // namespace
}  // namespace quic
