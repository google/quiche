// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for session-level flow control (Section 5).
// This is the largest test file — 22 tests covering FC negotiation, stream
// limits, data limits, and SETTINGS defaults.

#include <cstdint>
#include <string>
#include <vector>

#include "quiche/common/capsule.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"
#include "quiche/web_transport/web_transport.h"

namespace quic {
namespace {

using ::quiche::Capsule;
using ::quiche::WebTransportMaxDataCapsule;
using ::quiche::WebTransportMaxStreamsCapsule;
using ::testing::_;
using ::testing::Invoke;

class FlowControlDraft15Test : public test::Draft15SessionTest {
 protected:
  FlowControlDraft15Test() : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(FlowControlDraft15, FlowControlDraft15Test,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

// ==========================================================================
// Flow control negotiation (Section 5.1)
// ==========================================================================

TEST_P(FlowControlDraft15Test, FlowControlEnabledBothSendNonZero) {
  // Section 5.1: FC is enabled when both endpoints send at least one
  // non-zero SETTINGS_WT_INITIAL_MAX_* value.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  EXPECT_EQ(webtransport::draft15::kSettingsWtInitialMaxStreamsUni, 0x2b64u);
  EXPECT_EQ(webtransport::draft15::kSettingsWtInitialMaxStreamsBidi, 0x2b65u);
  EXPECT_EQ(webtransport::draft15::kSettingsWtInitialMaxData, 0x2b61u);
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
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // With FC enabled and bidi limit of 10, the first 10 streams should
  // succeed and the 11th should be blocked.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  for (int i = 0; i < 10; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
    EXPECT_NE(stream, nullptr)
        << "Stream " << i << " should succeed (within limit of 10)";
  }
  webtransport::Stream* blocked_stream = wt->OpenOutgoingBidirectionalStream();
  EXPECT_EQ(blocked_stream, nullptr)
      << "11th bidi stream should be blocked by WT-level FC (limit=10)";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, FlowControlDisabledOnlyOneSends) {
  // Section 5.1: FC is not enabled if only one endpoint sends
  // non-zero limits.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Peer sends non-zero FC limits, but local side sends all zeros (default).
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // With FC disabled (only peer sent non-zero), streams should only be
  // limited by QUIC-level limits, not WT-level limits. Opening streams
  // should succeed freely.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  EXPECT_NE(stream, nullptr)
      << "With FC disabled, opening a stream should succeed";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, FlowControlDisabledBothZero) {
  // Section 5.1: All default values (0) = FC not enabled.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Both sides send all-zero FC limits (the default).
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/0,
                         /*initial_max_streams_bidi=*/0,
                         /*initial_max_data=*/0);
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // FC disabled: session is functional, no WT-level FC applies.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  EXPECT_NE(stream, nullptr)
      << "With FC disabled (both zero), stream creation should succeed";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, IgnoreFCCapsulesWhenDisabled) {
  // Section 5.1 MUST: FC capsules are ignored when FC is not enabled.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/0,
                         /*initial_max_streams_bidi=*/0,
                         /*initial_max_data=*/0);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Inject FC capsules on the CONNECT stream. With FC disabled, they should
  // be silently ignored (no crash, no connection close).
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxDataCapsule{/*max_data=*/65536}));
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional, /*max_stream_count=*/10}));

  // Session and connection should still be alive.
  EXPECT_TRUE(connection_->connected());
}

// ==========================================================================
// Stream limits (Section 5.3)
// ==========================================================================

TEST_P(FlowControlDraft15Test, WtMaxStreamsBidiCumulative) {
  // Section 5.3: WT_MAX_STREAMS_BIDI is a cumulative limit including
  // closed streams.
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
                         /*initial_max_streams_bidi=*/3,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open 3 bidi streams (the limit).
  for (int i = 0; i < 3; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
    EXPECT_NE(stream, nullptr) << "Bidi stream " << i << " should succeed";
  }

  // 4th should fail (limit is 3).
  webtransport::Stream* blocked = wt->OpenOutgoingBidirectionalStream();
  EXPECT_EQ(blocked, nullptr)
      << "4th bidi stream should be blocked by WT_MAX_STREAMS_BIDI=3";

  // Raise the limit via capsule to 5.
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional, /*max_stream_count=*/5}));

  // Now 4th should succeed.
  webtransport::Stream* unblocked = wt->OpenOutgoingBidirectionalStream();
  EXPECT_NE(unblocked, nullptr)
      << "4th bidi stream should succeed after WT_MAX_STREAMS raised to 5";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, WtMaxStreamsUnidiCumulative) {
  // Section 5.3: Same for unidirectional streams.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/3,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open 3 uni streams (the limit).
  for (int i = 0; i < 3; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingUnidirectionalStream();
    EXPECT_NE(stream, nullptr) << "Uni stream " << i << " should succeed";
  }

  // 4th should fail.
  webtransport::Stream* blocked = wt->OpenOutgoingUnidirectionalStream();
  EXPECT_EQ(blocked, nullptr)
      << "4th uni stream should be blocked by WT_MAX_STREAMS_UNI=3";

  // Raise limit to 5.
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kUnidirectional, /*max_stream_count=*/5}));

  // 4th should now succeed.
  webtransport::Stream* unblocked = wt->OpenOutgoingUnidirectionalStream();
  EXPECT_NE(unblocked, nullptr)
      << "4th uni stream should succeed after WT_MAX_STREAMS raised to 5";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, ExceedStreamLimitClosesSession) {
  // Section 5.3 MUST: Exceeding stream limit closes the session with
  // WT_FLOW_CONTROL_ERROR.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  EXPECT_EQ(kWtFlowControlError, 0x045d4487u);
  // Local bidi=2 sets our incoming limit; peer values are higher.
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/2,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/2,
                         /*initial_max_streams_bidi=*/2,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // Peer sends 3 incoming bidi streams, exceeding the limit of 2.
  // The session should be closed with WT_FLOW_CONTROL_ERROR.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  // Section 5.3 MUST: Exceeding incoming stream limit closes session.
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          kWtFlowControlError),
      _))
      .Times(1);

  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(1));
  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(2));
  // This 3rd stream exceeds the limit.
  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(3));
}

TEST_P(FlowControlDraft15Test, MaxStreamsCannotExceed2Pow60) {
  // Section 5.6.2 MUST: Max stream count cannot exceed 2^60.
  // "Receipt of a capsule with a Maximum Streams value larger than this
  // limit MUST be treated as an HTTP/3 error of type H3_DATAGRAM_ERROR."
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
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, CloseConnection(_, _, _, _))
      .WillOnce(
          Invoke(connection_, &test::MockQuicConnection::ReallyCloseConnection4));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _))
      .Times(testing::AnyNumber());

  uint64_t too_large = (1ULL << 60) + 1;
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional,
          /*max_stream_count=*/too_large}));
  EXPECT_FALSE(connection_->connected());
}

TEST_P(FlowControlDraft15Test, MaxStreamsCannotExceed2Pow60_Unidi) {
  // Section 5.6.2 MUST: Same requirement for unidirectional streams.
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
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, CloseConnection(_, _, _, _))
      .WillOnce(
          Invoke(connection_, &test::MockQuicConnection::ReallyCloseConnection4));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _))
      .Times(testing::AnyNumber());

  uint64_t too_large = (1ULL << 60) + 1;
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kUnidirectional,
          /*max_stream_count=*/too_large}));
  EXPECT_FALSE(connection_->connected());
}

TEST_P(FlowControlDraft15Test, DecreasingMaxStreamsIsError) {
  // Section 5.6.2 MUST: Receiving a smaller WT_MAX_STREAMS value than
  // previously advertised triggers WT_FLOW_CONTROL_ERROR.
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
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // First, raise to 20.
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional,
          /*max_stream_count=*/20}));

  // Section 5.6.2 MUST: Decreasing WT_MAX_STREAMS triggers
  // WT_FLOW_CONTROL_ERROR.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          kWtFlowControlError),
      _))
      .Times(1);
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional,
          /*max_stream_count=*/15}));
}

TEST_P(FlowControlDraft15Test, StreamsBlockedSentAtLimit) {
  // Section 5.6.3 SHOULD: WT_STREAMS_BLOCKED sent when the stream limit
  // is reached.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/2,
                         /*initial_max_streams_bidi=*/2,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open 2 bidi streams (the limit).
  for (int i = 0; i < 2; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
    EXPECT_NE(stream, nullptr) << "Bidi stream " << i << " should succeed";
  }

  // 3rd should return nullptr (blocked at limit).
  webtransport::Stream* blocked = wt->OpenOutgoingBidirectionalStream();
  EXPECT_EQ(blocked, nullptr)
      << "3rd bidi stream should be blocked at WT_MAX_STREAMS_BIDI=2";
  // Section 5.6.3 SHOULD: A WT_STREAMS_BLOCKED capsule should be sent when
  // the stream limit is reached. This is a SHOULD requirement; verifying the
  // capsule emission requires intercepting CONNECT stream output.
  // The primary assertion is that stream creation correctly returns nullptr.
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, ConnectStreamNotCounted) {
  // Section 5.3: The CONNECT stream used for session establishment is
  // not counted towards stream limits.
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
                         /*initial_max_streams_bidi=*/1,
                         /*initial_max_data=*/65536);
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // The CONNECT stream itself should not count against the bidi limit.
  // With bidi limit=1, we should still be able to open 1 WT bidi stream.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  EXPECT_NE(stream, nullptr)
      << "With bidi limit=1, one WT bidi stream should be allowed "
         "(CONNECT stream not counted)";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

// ==========================================================================
// Data limits (Section 5.4)
// ==========================================================================

TEST_P(FlowControlDraft15Test, WtMaxDataCumulative) {
  // Section 5.4: WT_MAX_DATA is a cumulative byte limit across all streams.
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
                         /*initial_max_data=*/1024);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open a stream and write data up to and beyond the limit.
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream, nullptr);

  // Write 512 bytes -- should succeed (under 1024 limit).
  std::string data_512(512, 'a');
  EXPECT_TRUE(stream->Write(data_512))
      << "Writing 512 bytes should succeed (under 1024 limit)";

  // Write another 512 bytes -- should succeed (exactly at 1024 limit).
  EXPECT_TRUE(stream->Write(data_512))
      << "Writing another 512 bytes should succeed (at 1024 limit)";

  // Section 5.4 MUST: Write beyond WT_MAX_DATA limit must fail.
  std::string data_1(1, 'b');
  EXPECT_FALSE(stream->Write(data_1))
      << "Write beyond 1024-byte WT_MAX_DATA limit must fail";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, StreamHeaderExcluded) {
  // Section 5.4: Stream header bytes (signal/type/session ID) are not
  // counted towards the data limit.
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
                         /*initial_max_data=*/10);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open a uni stream. The stream header (0x54 type byte + session ID varint)
  // should not count towards the 10-byte data limit.
  webtransport::Stream* stream = wt->OpenOutgoingUnidirectionalStream();
  ASSERT_NE(stream, nullptr);

  // If header bytes are excluded from WT_MAX_DATA, writing 10 payload bytes
  // should succeed (exactly at the limit).
  std::string data_10(10, 'x');
  EXPECT_TRUE(stream->Write(data_10))
      << "Writing 10 payload bytes should succeed when header bytes are "
         "excluded from the 10-byte WT_MAX_DATA limit";

  // Section 5.4 MUST: Write beyond WT_MAX_DATA limit must fail.
  std::string data_1(1, 'y');
  EXPECT_FALSE(stream->Write(data_1))
      << "Write beyond 10-byte WT_MAX_DATA limit must fail";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, ExceedDataLimitClosesSession) {
  // Section 5.6.4 MUST: Exceeding the data limit closes the session with
  // WT_FLOW_CONTROL_ERROR.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  // Local data=64 sets our incoming data limit; peer values are higher.
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/64);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/64);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // Peer sends more data than the 64-byte WT_MAX_DATA limit via an
  // incoming uni stream.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  std::string oversized_payload(128, 'x');
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  // Section 5.6.4 MUST: Exceeding data limit closes session.
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          kWtFlowControlError),
      _))
      .Times(1);

  QuicStreamId peer_uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(
      session_id, peer_uni_stream_id, oversized_payload);
}

TEST_P(FlowControlDraft15Test, DecreasingMaxDataIsError) {
  // Section 5.6.4 MUST: Receiving a smaller WT_MAX_DATA value triggers
  // WT_FLOW_CONTROL_ERROR.
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
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // Raise to 128000.
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxDataCapsule{/*max_data=*/128000}));

  // Section 5.6.4 MUST: Decreasing WT_MAX_DATA triggers
  // WT_FLOW_CONTROL_ERROR.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          kWtFlowControlError),
      _))
      .Times(1);
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxDataCapsule{/*max_data=*/64000}));
}

TEST_P(FlowControlDraft15Test, DataBlockedSentWhenLimited) {
  // Section 5.6.5 SHOULD: WT_DATA_BLOCKED sent when the data limit is
  // reached.
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
                         /*initial_max_data=*/128);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open a stream and write up to the data limit.
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream, nullptr);

  // Write exactly 128 bytes (the limit).
  std::string data_128(128, 'a');
  EXPECT_TRUE(stream->Write(data_128))
      << "Writing 128 bytes should succeed (at the WT_MAX_DATA limit)";

  // Section 5.6.5 SHOULD: Write beyond WT_MAX_DATA limit must fail
  // and a WT_DATA_BLOCKED capsule SHOULD be emitted.
  std::string data_1(1, 'b');
  EXPECT_FALSE(stream->Write(data_1))
      << "Write beyond 128-byte WT_MAX_DATA limit must fail";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, ResetStreamCountsInDataLimit) {
  // Section 5.4: When a stream is reset, the final size of the stream
  // counts as consumed flow control credit.
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
                         /*initial_max_data=*/1024);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Open two streams. Write 512 bytes on the first, then reset it.
  // The final size (512 bytes) should count towards the 1024-byte WT_MAX_DATA
  // limit. The second stream should then only be able to write 512 more bytes.
  webtransport::Stream* stream1 = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream1, nullptr);
  std::string data_512(512, 'a');
  EXPECT_TRUE(stream1->Write(data_512))
      << "Writing 512 bytes should succeed";

  // Reset the first stream. Its final size (512) counts as consumed FC credit.
  stream1->ResetWithUserCode(0);

  // Open a second stream.
  webtransport::Stream* stream2 = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream2, nullptr);

  // Write 512 bytes on the second stream (total consumed = 1024 = limit).
  EXPECT_TRUE(stream2->Write(data_512))
      << "Writing 512 bytes on second stream should succeed (total = 1024)";

  // Section 5.4 MUST: Reset stream's final size counts as consumed FC credit.
  // Total consumed = 512 (reset) + 512 (written) = 1024 = limit.
  // Writing 1 more byte must fail.
  std::string data_1(1, 'b');
  EXPECT_FALSE(stream2->Write(data_1))
      << "Reset stream's final size must count towards the WT_MAX_DATA limit";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

// ==========================================================================
// SETTINGS defaults (Section 5.5)
// ==========================================================================

TEST_P(FlowControlDraft15Test, InitialMaxStreamsUniDefault0) {
  // Section 5.5.1: Default value of SETTINGS_WT_INITIAL_MAX_STREAMS_UNI
  // is 0.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  EXPECT_EQ(webtransport::draft15::kSettingsWtInitialMaxStreamsUni, 0x2b64u);
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Check that draft-15 SETTINGS are emitted (fails because no kDraft15
  // branch in FillSettingsFrame).
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Expected SETTINGS_WT_ENABLED in emitted settings for draft-15";
  // The default value for SETTINGS_WT_INITIAL_MAX_STREAMS_UNI should be 0
  // (or absent from SETTINGS).
  auto it = session_->settings().values.find(SETTINGS_WT_INITIAL_MAX_STREAMS_UNI);
  if (it != session_->settings().values.end()) {
    EXPECT_EQ(it->second, 0u)
        << "Default SETTINGS_WT_INITIAL_MAX_STREAMS_UNI should be 0";
  }
}

TEST_P(FlowControlDraft15Test, InitialMaxStreamsBidiDefault0) {
  // Section 5.5.2: Default value of SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI
  // is 0.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  EXPECT_EQ(webtransport::draft15::kSettingsWtInitialMaxStreamsBidi, 0x2b65u);
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Check that draft-15 SETTINGS are emitted.
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Expected SETTINGS_WT_ENABLED in emitted settings for draft-15";
  // The default value for SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI should be 0
  // (or absent).
  auto it = session_->settings().values.find(SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI);
  if (it != session_->settings().values.end()) {
    EXPECT_EQ(it->second, 0u)
        << "Default SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI should be 0";
  }
}

TEST_P(FlowControlDraft15Test, InitialMaxDataDefault0) {
  // Section 5.5.3: Default value of SETTINGS_WT_INITIAL_MAX_DATA is 0.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  EXPECT_EQ(webtransport::draft15::kSettingsWtInitialMaxData, 0x2b61u);
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Check that draft-15 SETTINGS are emitted.
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Expected SETTINGS_WT_ENABLED in emitted settings for draft-15";
  // The default value for SETTINGS_WT_INITIAL_MAX_DATA should be 0
  // (or absent).
  auto it = session_->settings().values.find(SETTINGS_WT_INITIAL_MAX_DATA);
  if (it != session_->settings().values.end()) {
    EXPECT_EQ(it->second, 0u)
        << "Default SETTINGS_WT_INITIAL_MAX_DATA should be 0";
  }
}

TEST_P(FlowControlDraft15Test, NonZeroFCSettingsEmitted) {
  // Section 5.5: When configured with non-zero FC limits, the emitted
  // SETTINGS frame MUST contain the corresponding values.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/42,
      /*local_max_streams_bidi=*/17,
      /*local_max_data=*/100000);
  CompleteHandshake();

  const auto& vals = session_->settings().values;
  ASSERT_TRUE(vals.contains(SETTINGS_WT_INITIAL_MAX_STREAMS_UNI))
      << "Non-zero SETTINGS_WT_INITIAL_MAX_STREAMS_UNI must be emitted";
  EXPECT_EQ(vals.at(SETTINGS_WT_INITIAL_MAX_STREAMS_UNI), 42u);
  ASSERT_TRUE(vals.contains(SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI))
      << "Non-zero SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI must be emitted";
  EXPECT_EQ(vals.at(SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI), 17u);
  ASSERT_TRUE(vals.contains(SETTINGS_WT_INITIAL_MAX_DATA))
      << "Non-zero SETTINGS_WT_INITIAL_MAX_DATA must be emitted";
  EXPECT_EQ(vals.at(SETTINGS_WT_INITIAL_MAX_DATA), 100000u);
}

TEST_P(FlowControlDraft15Test, CumulativeLimitNotConcurrent) {
  // Section 5.6.2: Stream limits are cumulative, not concurrent. Closing
  // streams does NOT free slots. Once 3 streams have been opened (even if
  // all are closed), a 4th should fail with WT_MAX_STREAMS_BIDI=3.
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
                         /*initial_max_streams_bidi=*/3,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open 3 bidi streams and immediately close them by sending FIN.
  for (int i = 0; i < 3; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
    ASSERT_NE(stream, nullptr) << "Bidi stream " << i << " should succeed";
    EXPECT_TRUE(stream->SendFin());
  }

  // Despite all 3 streams being closed, the cumulative limit of 3 has been
  // reached. A 4th stream should be blocked.
  webtransport::Stream* blocked = wt->OpenOutgoingBidirectionalStream();
  EXPECT_EQ(blocked, nullptr)
      << "4th bidi stream should be blocked because stream limits are "
         "cumulative (3 total opened), not concurrent (0 currently open)";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

// ==========================================================================
// Section 5: Asymmetric stream/data limits
// Incoming limits come from local SETTINGS, outgoing from peer SETTINGS.
// ==========================================================================

TEST_P(FlowControlDraft15Test, Section5_OutgoingLimitsFromPeerSettings) {
  // Section 5: Outgoing stream limits are determined by the peer's
  // SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI value, not our local value.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/100,
      /*local_max_streams_bidi=*/100,
      /*local_max_data=*/65536);
  CompleteHandshake();
  // Peer advertises bidi limit of 5 (our outgoing limit).
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/100,
                         /*initial_max_streams_bidi=*/5,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open 5 outgoing bidi streams (peer's limit).
  for (int i = 0; i < 5; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
    EXPECT_NE(stream, nullptr)
        << "Outgoing bidi stream " << i
        << " should succeed (peer allows 5)";
  }

  // 6th should be blocked by peer's limit of 5.
  webtransport::Stream* blocked = wt->OpenOutgoingBidirectionalStream();
  EXPECT_EQ(blocked, nullptr)
      << "6th outgoing bidi stream should be blocked by peer's "
         "SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI=5";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, Section5_IncomingLimitsFromLocalSettings) {
  // Section 5: Incoming stream limits are determined by OUR local
  // SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI, not the peer's value.
  // Peer advertises bidi=100, but our local limit is 3.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/100,
      /*local_max_streams_bidi=*/3,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/100,
                         /*initial_max_streams_bidi=*/100,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());

  // Receive 3 incoming bidi streams (within our local limit of 3).
  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(1));
  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(2));
  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(3));

  // Section 5 MUST: 4th incoming stream exceeds our local limit of 3.
  // Session should be closed with WT_FLOW_CONTROL_ERROR.
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(kWtFlowControlError),
      _))
      .Times(1);
  ReceiveWebTransportBidirectionalStream(
      session_id, GetNthClientInitiatedBidirectionalId(4));
}

TEST_P(FlowControlDraft15Test, Section5_AsymmetricUniStreamLimits) {
  // Section 5: Outgoing uni limit from peer (2), incoming uni limit from
  // local (10). These are independent.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/100,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/2,
                         /*initial_max_streams_bidi=*/100,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnSessionClosed(_, _))
      .Times(testing::AnyNumber());

  // Outgoing: peer allows 2 uni streams.
  for (int i = 0; i < 2; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingUnidirectionalStream();
    EXPECT_NE(stream, nullptr)
        << "Outgoing uni stream " << i << " should succeed (peer allows 2)";
  }
  webtransport::Stream* blocked = wt->OpenOutgoingUnidirectionalStream();
  EXPECT_EQ(blocked, nullptr)
      << "3rd outgoing uni stream should be blocked by peer limit of 2";

  // Incoming: our local limit is 10. Receive 3 streams — this should
  // succeed since 3 < 10. With the buggy implementation, the incoming limit
  // is set to peer's value (2), so the 3rd stream will close the session.
  for (int i = 0; i < 3; ++i) {
    QuicStreamId peer_stream_id =
        test::GetNthClientInitiatedUnidirectionalStreamId(
            transport_version(), 4 + i);
    ReceiveWebTransportUnidirectionalStream(
        session_id, peer_stream_id, "payload");
  }

  // Section 5: 3 incoming uni streams is within our local limit of 10.
  // The WT session should still be functional (able to open new streams).
  // Note: connection_->connected() is NOT a valid check here because
  // CloseSession() only closes the WT session, not the QUIC connection.
  EXPECT_TRUE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "After receiving 3 incoming uni streams (within local "
         "limit of 10), the WT session should still be functional";
  testing::Mock::VerifyAndClearExpectations(writer_);
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(FlowControlDraft15Test, Section5_4_AsymmetricDataLimits) {
  // Section 5.4: Outgoing data limit from peer (1024), incoming data limit
  // from local (256). These are independent.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/256);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/1024);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnSessionClosed(_, _))
      .Times(testing::AnyNumber());

  // Outgoing: peer's data limit is 1024.
  webtransport::Stream* out_stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(out_stream, nullptr);
  std::string data_1024(1024, 'a');
  EXPECT_TRUE(out_stream->Write(data_1024))
      << "Writing 1024 bytes should succeed (peer's WT_MAX_DATA=1024)";
  std::string data_1(1, 'b');
  EXPECT_FALSE(out_stream->Write(data_1))
      << "Write beyond peer's 1024-byte limit must fail";

  // Incoming: our local data limit is 256. Receiving 512 bytes should
  // exceed it and close the session with WT_FLOW_CONTROL_ERROR.
  // With the buggy implementation, max_data_receive_ is set to the peer's
  // value (1024), so 512 bytes will NOT trigger an error.
  QuicStreamId peer_uni_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string oversized(512, 'x');
  ReceiveWebTransportUnidirectionalStream(session_id, peer_uni_id, oversized);

  // Section 5.4: With local max_data=256, receiving 512 bytes should have
  // closed the WT session. Verify via CanOpenNextOutgoingBidirectionalStream()
  // (returns false when session is terminated).
  EXPECT_FALSE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "Receiving 512 bytes should exceed our local "
         "WT_MAX_DATA=256 and terminate the WT session";
  testing::Mock::VerifyAndClearExpectations(writer_);
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(FlowControlDraft15Test, Section5_1_FCRequiresBothSidesNonZero) {
  // Section 5.1: FC is only enabled when BOTH endpoints send at least one
  // non-zero SETTINGS_WT_INITIAL_MAX_* value.
  // Only peer sends non-zero — FC should be disabled.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  // Local limits are all 0 (default).
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/2,
                         /*initial_max_data=*/65536);
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Section 5.1: With FC disabled (only peer sent non-zero), WT-level
  // limits should not apply. Opening more streams than the peer's bidi
  // limit of 2 should still succeed since WT FC is not active.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open 5 bidi streams. With FC disabled, none should be blocked.
  int successful = 0;
  for (int i = 0; i < 5; ++i) {
    webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
    if (stream != nullptr) {
      ++successful;
    }
  }
  // Section 5.1: All 5 should succeed because WT-level FC should not be
  // active when only one side advertises non-zero limits.
  EXPECT_EQ(successful, 5)
      << "With FC disabled (only peer sent non-zero), all 5 "
         "bidi streams should succeed. Got " << successful;
  testing::Mock::VerifyAndClearExpectations(writer_);
}

// ==========================================================================
// Section 5.4: Incoming data must be counted on ALL stream types.
// ==========================================================================

TEST_P(FlowControlDraft15Test, Section5_4_BidiStreamDataCountedAgainstMaxData) {
  // Section 5.4: Incoming data on a bidirectional stream must be counted
  // against WT_MAX_DATA.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/128);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnSessionClosed(_, _))
      .Times(testing::AnyNumber());

  // Receive an incoming bidi stream (preamble only: 0x41 + session_id).
  QuicStreamId bidi_stream_id = GetNthClientInitiatedBidirectionalId(1);
  ReceiveWebTransportBidirectionalStream(session_id, bidi_stream_id);

  // Now send 256 bytes of payload on that stream. The preamble was
  // varint(0x41)=1 byte + varint(session_id)=1 byte = 2 bytes at offset 0.
  // Payload starts at offset 2.
  std::string payload(256, 'x');
  QuicStreamFrame data_frame(bidi_stream_id, /*fin=*/false, /*offset=*/2,
                             payload);
  session_->OnStreamFrame(data_frame);

  // Section 5.4: 256 bytes received exceeds our local WT_MAX_DATA=128.
  // The session should have been closed with WT_FLOW_CONTROL_ERROR.
  EXPECT_FALSE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "Receiving 256 bytes on a bidi stream should exceed "
         "local WT_MAX_DATA=128 and terminate the session";
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(FlowControlDraft15Test, Section5_4_UniStreamSubsequentDataCounted) {
  // Section 5.4: Data arriving on a uni stream AFTER initial association
  // must also be counted against WT_MAX_DATA.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/64);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnSessionClosed(_, _))
      .Times(testing::AnyNumber());

  // Send a uni stream with a small initial payload (16 bytes) that fits
  // within the 64-byte limit.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string small_payload(16, 'a');
  ReceiveWebTransportUnidirectionalStream(
      session_id, uni_stream_id, small_payload);

  // Session should still be alive (16 <= 64).
  EXPECT_TRUE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "16 bytes is within the 64-byte limit";

  // Now send 128 more bytes on the SAME stream at the right offset.
  // Preamble: varint(0x54)=1 byte + varint(session_id)=1 byte = 2 bytes.
  // First payload was 16 bytes. Offset = 2 + 16 = 18.
  std::string more_payload(128, 'b');
  QuicStreamFrame data_frame(uni_stream_id, /*fin=*/false, /*offset=*/18,
                             more_payload);
  session_->OnStreamFrame(data_frame);

  // Section 5.4: Total received = 16 + 128 = 144 bytes > 64 limit.
  // Session should be terminated with WT_FLOW_CONTROL_ERROR.
  EXPECT_FALSE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "Subsequent data on a uni stream (total 144 bytes) "
         "should exceed local WT_MAX_DATA=64 and terminate the session";
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(FlowControlDraft15Test,
       Section5_4_IncomingDataAcrossMultipleStreamsCumulative) {
  // Section 5.4: WT_MAX_DATA is cumulative across all incoming streams,
  // including both bidirectional and unidirectional.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/100);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnSessionClosed(_, _))
      .Times(testing::AnyNumber());

  // Receive a bidi stream with 60 bytes of payload.
  QuicStreamId bidi_stream_id = GetNthClientInitiatedBidirectionalId(1);
  ReceiveWebTransportBidirectionalStream(session_id, bidi_stream_id);
  std::string bidi_payload(60, 'x');
  QuicStreamFrame bidi_data(bidi_stream_id, /*fin=*/false, /*offset=*/2,
                            bidi_payload);
  session_->OnStreamFrame(bidi_data);

  // Receive a uni stream with 60 bytes of payload.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string uni_payload(60, 'y');
  ReceiveWebTransportUnidirectionalStream(
      session_id, uni_stream_id, uni_payload);

  // Section 5.4: Total = 60 (bidi) + 60 (uni) = 120 > 100 limit.
  // Session should be terminated with WT_FLOW_CONTROL_ERROR.
  EXPECT_FALSE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "Cumulative incoming data across bidi (60) + uni (60) "
         "= 120 bytes should exceed local WT_MAX_DATA=100";
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(FlowControlDraft15Test, Section5_4_DataFCDoesNotDoubleCountUnconsumedBytes) {
  // Section 5.4: OnDataAvailable() must count only the new bytes received,
  // not all unconsumed bytes. Bytes not consumed between calls must not be
  // double-counted against WT_MAX_DATA.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  // Set local_max_data=200 so the 160 bytes total should fit.
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/200);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  // The session must NOT be closed — 160 total bytes < 200 limit.
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(0);
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Deliver a uni stream with 80 bytes of payload.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string payload_80(80, 'a');
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_id,
                                          payload_80);

  // Do NOT consume data — the visitor's OnCanRead is a no-op (NiceMock).

  // Compute preamble size: varint(0x54)=2 bytes + varint(session_id=0)=1 byte.
  const size_t preamble_size = 3;

  // Send 80 more bytes on the same stream at the correct offset.
  std::string payload_80b(80, 'b');
  QuicStreamFrame second_frame(uni_stream_id, /*fin=*/false,
                               /*offset=*/preamble_size + 80, payload_80b);
  session_->OnStreamFrame(second_frame);

  // Section 5.4: total_data_received_ should be 160 (80 + 80), NOT 240
  // (80 + 160). The session should still be alive.
  EXPECT_TRUE(connection_->connected())
      << "160 bytes total < 200 limit, but double-counting "
         "would report 240 bytes and incorrectly close the session";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(FlowControlDraft15Test, Section5_ReceiverWindowReplenishesAfterConsumption) {
  // Section 5.4: The receiver window must be replenished by sending
  // WT_MAX_DATA capsules as data is consumed, so that cumulative
  // total_data_received_ does not exceed the limit.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/100);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());

  // Deliver first uni stream with 90 bytes. Do NOT consume in callback
  // (NiceMock default does nothing) so the adapter counts the bytes.
  // After delivery: total_data_received_ = 90, max_data_receive_ = 100.
  QuicStreamId uni_stream_1 =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string payload_90(90, 'a');
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_1, payload_90);

  // Accept and consume all data from stream 1 — this should trigger
  // the receiver to send WT_MAX_DATA, replenishing the window.
  webtransport::Stream* s1 = wt->AcceptIncomingUnidirectionalStream();
  ASSERT_NE(s1, nullptr);
  std::string buf;
  (void)s1->Read(&buf);
  ASSERT_EQ(buf.size(), 90u);

  // The session must NOT be closed when the second stream arrives.
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(0);

  // Deliver second uni stream with 20 bytes. The adapter counts 20 more bytes.
  // Section 5.4: After consuming 90 bytes, max_data_receive_ should be
  // updated to at least 190. 110 < 190, so session stays alive.
  QuicStreamId uni_stream_2 =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 5);
  std::string payload_20(20, 'b');
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_2, payload_20);

  EXPECT_TRUE(connection_->connected())
      << "After consuming 90 bytes, window should replenish";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(FlowControlDraft15Test, Section5_IncomingStreamLimitReplenishesAfterClose) {
  // Section 5.3: After streams are closed, the incoming stream limit should
  // be replenished by sending WT_MAX_STREAMS capsules.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/2,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/100,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());

  // Deliver 2 incoming bidi streams (the limit).
  QuicStreamId bidi_1 = GetNthClientInitiatedBidirectionalId(1);
  QuicStreamId bidi_2 = GetNthClientInitiatedBidirectionalId(2);
  ReceiveWebTransportBidirectionalStream(session_id, bidi_1);
  ReceiveWebTransportBidirectionalStream(session_id, bidi_2);

  // Accept and close both streams.
  webtransport::Stream* s1 = wt->AcceptIncomingBidirectionalStream();
  webtransport::Stream* s2 = wt->AcceptIncomingBidirectionalStream();
  ASSERT_NE(s1, nullptr);
  ASSERT_NE(s2, nullptr);
  s1->SendStopSending(0);
  s1->ResetWithUserCode(0);
  s2->SendStopSending(0);
  s2->ResetWithUserCode(0);

  // The session must NOT be closed when the 3rd stream arrives.
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(0);

  // Deliver a 3rd incoming bidi stream.
  QuicStreamId bidi_3 = GetNthClientInitiatedBidirectionalId(3);
  ReceiveWebTransportBidirectionalStream(session_id, bidi_3);

  // Section 5: After closing 2 streams, the receiver should have sent
  // WT_MAX_STREAMS to allow the peer to open new streams.
  EXPECT_TRUE(connection_->connected())
      << "After closing 2 streams, receiver should send "
         "WT_MAX_STREAMS to allow opening new streams";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

// ==========================================================================
// Section 5.5.3: SETTINGS_WT_INITIAL_MAX_DATA default of 0 means
// "endpoint needs to send WT_MAX_DATA capsule before peer may send data."
// ==========================================================================

TEST_P(FlowControlDraft15Test, Section5_DataLimitZeroBlocksSending) {
  // Section 5.5.3: "The default value ... is '0', indicating that the
  // endpoint needs to send a WT_MAX_DATA capsule within each session
  // before its peer is allowed to send any stream data within that session."
  //
  // When FC is enabled (peer sends SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI=10)
  // but SETTINGS_WT_INITIAL_MAX_DATA is absent (defaults to 0), CanSendData
  // must return false until a WT_MAX_DATA capsule is received.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  // Both sides enable FC via stream limits, but neither advertises data limits.
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/0);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/0);

  ASSERT_TRUE(session_->wt_flow_control_enabled())
      << "FC should be enabled when both sides send non-zero stream limits";

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr);

  // With initial_max_data = 0, no data should be sendable.
  EXPECT_FALSE(wt->CanSendData(1))
      << "initial_max_data=0 means no data until WT_MAX_DATA";

  // After receiving a WT_MAX_DATA capsule, data should be sendable.
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxDataCapsule{/*max_data=*/1000}));
  EXPECT_TRUE(wt->CanSendData(1))
      << "After WT_MAX_DATA(1000), 1 byte should be sendable";
}

// ==========================================================================
// Section 5.6: Window replenishment must be based on consumed data,
// not received data (following QUIC's flow control pattern per RFC 9000 §4.2).
// ==========================================================================

TEST_P(FlowControlDraft15Test, Section5_WindowReplenishmentBasedOnConsumption) {
  // Section 5.6: "Endpoints SHOULD send WT_MAX_DATA ... as they consume
  // data" — window should NOT grow just because data was received; the
  // application must actually consume it.
  //
  // With receive-based replenishment (bug): reading 1 byte after receiving
  // 80 causes replenishment because available = max(100) - received(80) = 20
  // < threshold(50).  Window grows to 200 prematurely.
  //
  // With consumption-based replenishment (correct): reading 1 byte gives
  // available = max(100) - consumed(1) = 99 >= threshold(50), no
  // replenishment — the receiver hasn't processed enough data.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/100);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Receive 80 bytes on a uni stream.
  QuicStreamId uni_1 =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string payload_80(80, 'a');
  ReceiveWebTransportUnidirectionalStream(session_id, uni_1, payload_80);

  // Consume only 1 byte. With receive-based logic (bug), this triggers
  // premature replenishment. With consumption-based logic (correct), it
  // does not.
  webtransport::Stream* s1 = wt->AcceptIncomingUnidirectionalStream();
  ASSERT_NE(s1, nullptr);
  char buf[1];
  auto result = s1->Read(absl::MakeSpan(buf, 1));
  ASSERT_EQ(result.bytes_read, 1u);

  // Now deliver 21 more bytes on a new stream (total received = 101 > 100).
  // Correct: no premature replenishment, so 101 > limit(100) → session
  // terminates with WT_FLOW_CONTROL_ERROR. Verify by checking that the
  // session can no longer open outgoing streams (IsTerminated).
  // Buggy: premature replenishment bumped limit to 200, so 101 < 200, OK.
  QuicStreamId uni_2 =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 5);
  std::string payload_21(21, 'b');
  ReceiveWebTransportUnidirectionalStream(session_id, uni_2, payload_21);

  EXPECT_EQ(wt->OpenOutgoingBidirectionalStream(), nullptr)
      << "After receiving 101 bytes with only 1 consumed, "
         "the session should be terminated (no premature replenishment)";
}

// ==========================================================================
// Section 5.6.2: Visitor notified when WT_MAX_STREAMS raises the limit.
// ==========================================================================

// ==========================================================================
// Section 5.6.2: SETTINGS_WT_INITIAL_MAX_STREAMS values must not exceed 2^60.
// ==========================================================================

TEST_P(FlowControlDraft15Test, Section5_SettingsMaxStreamsExceeding2p60Rejected) {
  // Section 5.6.2: "This value cannot exceed 2^60 ... Receipt of a capsule
  // with a Maximum Streams value greater than 2^60 MUST be treated as a
  // session error." SETTINGS provide initial values for the same limit and
  // should be validated identically.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  CompleteHandshake();

  // Send peer SETTINGS with WT_INITIAL_MAX_STREAMS_BIDI exceeding 2^60.
  SettingsFrame settings;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  settings.values[SETTINGS_WT_ENABLED] = 1;
  settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI] = (1ULL << 60) + 1;
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  // Allow connection-level mock calls during the close sequence.
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_HTTP_INVALID_SETTING_VALUE, _, _))
      .WillOnce(
          testing::Invoke(connection_,
                          &test::MockQuicConnection::ReallyCloseConnection));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _))
      .Times(testing::AnyNumber());

  QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
  session_->OnStreamFrame(frame);

  EXPECT_FALSE(connection_->connected())
      << "SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI > 2^60 "
         "should close the connection";
}

// A visitor that opens a bidi stream when notified that stream creation
// is now possible — the standard callback-driven application pattern.
class StreamOpeningVisitor : public WebTransportVisitor {
 public:
  explicit StreamOpeningVisitor(WebTransportSession* session)
      : session_(session) {}
  void OnSessionReady() override {}
  void OnSessionClosed(WebTransportSessionError, const std::string&) override {}
  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(absl::string_view) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {
    WebTransportStream* stream = session_->OpenOutgoingBidirectionalStream();
    if (stream != nullptr) {
      opened_bidi_streams_.push_back(stream);
    }
  }
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

  const std::vector<WebTransportStream*>& opened_bidi_streams() const {
    return opened_bidi_streams_;
  }

 private:
  WebTransportSession* session_;
  std::vector<WebTransportStream*> opened_bidi_streams_;
};

TEST_P(FlowControlDraft15Test, Section5_VisitorNotifiedWhenStreamLimitRaised) {
  // Section 5.6.2: When the peer sends WT_MAX_STREAMS raising the outgoing
  // stream limit, a callback-driven application should be able to open new
  // streams from the OnCanCreateNewOutgoingBidirectionalStream callback.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/1,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  // Open one bidi stream, exhausting the limit of 1.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream, nullptr);
  EXPECT_EQ(wt->OpenOutgoingBidirectionalStream(), nullptr)
      << "Second stream should be blocked by WT limit of 1";

  // Attach a callback-driven visitor that opens a stream when notified.
  auto visitor = std::make_unique<StreamOpeningVisitor>(wt);
  StreamOpeningVisitor* raw_visitor = visitor.get();
  wt->SetVisitor(std::move(visitor));

  // Deliver WT_MAX_STREAMS_BIDI raising the limit from 1 to 2.
  InjectCapsuleOnConnectStream(
      session_id,
      Capsule(WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional, /*max_stream_count=*/2}));

  // The visitor should have opened a stream in response to the callback.
  EXPECT_EQ(raw_visitor->opened_bidi_streams().size(), 1u)
      << "Visitor must be notified when WT_MAX_STREAMS raises the limit, "
         "enabling it to open new streams";
}

// ==========================================================================
// Section 5.6.3 / 5.6.5: BLOCKED capsules sent when limits are reached.
// ==========================================================================

TEST_P(FlowControlDraft15Test, Section5_StreamsBlockedSentWhenLimitReached) {
  // Section 5.6.3: "A sender SHOULD send a WT_STREAMS_BLOCKED capsule
  // when it wishes to open a stream but is unable to do so due to the
  // maximum stream limit set by its peer."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/1,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open one bidi stream, exhausting the WT limit of 1.
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream, nullptr);

  // Record bytes written on the CONNECT stream before the blocked attempt.
  QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);
  uint64_t bytes_before = connect_stream->stream_bytes_written();

  // Attempt to open another stream — should be blocked by WT limit.
  EXPECT_EQ(wt->OpenOutgoingBidirectionalStream(), nullptr);

  // A WT_STREAMS_BLOCKED capsule should have been written to the CONNECT
  // stream, increasing bytes_written.
  uint64_t bytes_after = connect_stream->stream_bytes_written();
  EXPECT_GT(bytes_after, bytes_before)
      << "A WT_STREAMS_BLOCKED capsule should be sent when "
         "stream creation is blocked by WT-level limits";
}

TEST_P(FlowControlDraft15Test, Section5_DataBlockedSentWhenLimitReached) {
  // Section 5.6.5: "A sender SHOULD send a WT_DATA_BLOCKED capsule when
  // it wishes to send data but is unable to do so due to WebTransport
  // session-level flow control."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/10);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open a bidi stream and exhaust the data limit by sending 10 bytes.
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream, nullptr);
  EXPECT_TRUE(wt->CanSendData(10));
  wt->OnDataSent(10);  // Record the data as sent.
  EXPECT_FALSE(wt->CanSendData(1))
      << "Data limit of 10 should be exhausted";

  // Record bytes written on the CONNECT stream before the blocked write.
  QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);
  uint64_t bytes_before = connect_stream->stream_bytes_written();

  // Attempt to write more data — should be blocked by WT data limit.
  // CanSendData returns false, and the adapter would call
  // MaybeSendDataBlocked.
  wt->MaybeSendDataBlocked();

  uint64_t bytes_after = connect_stream->stream_bytes_written();
  EXPECT_GT(bytes_after, bytes_before)
      << "A WT_DATA_BLOCKED capsule should be sent when "
         "data sending is blocked by WT-level limits";
}

TEST_P(FlowControlDraft15Test,
       Section5_6_2_MaxStreamsExceeding2p60ClosesConnection) {
  // Section 5.6.2 MUST: "Receipt of a capsule with a Maximum Streams value
  // larger than this limit MUST be treated as an HTTP/3 error of type
  // H3_DATAGRAM_ERROR."  This is a CONNECTION-level error, not a session error.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, CloseConnection(_, _, _, _))
      .WillOnce(
          Invoke(connection_, &test::MockQuicConnection::ReallyCloseConnection4));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _))
      .Times(testing::AnyNumber());

  uint64_t too_large = (1ULL << 60) + 1;
  InjectCapsuleOnConnectStream(
      session_id,
      quiche::Capsule(quiche::WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional, too_large}));

  EXPECT_FALSE(connection_->connected())
      << "WT_MAX_STREAMS > 2^60 must close the CONNECTION "
         "with H3_DATAGRAM_ERROR, not just the session";
}

TEST_P(FlowControlDraft15Test,
       Section5_6_2_SameValueMaxStreamsIsNoOp) {
  // Section 5.6.2: Receiving WT_MAX_STREAMS with a value equal to the
  // current limit is legal but carries no new information. It must NOT
  // reset the blocked-sent flag, as that would allow amplification: a
  // malicious peer could repeat same-value capsules to trigger unlimited
  // WT_STREAMS_BLOCKED responses.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/1,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open one bidi stream, exhausting the WT limit of 1.
  webtransport::Stream* s = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(s, nullptr);

  QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);

  // First blocked attempt — sends WT_STREAMS_BLOCKED.
  EXPECT_EQ(wt->OpenOutgoingBidirectionalStream(), nullptr);
  uint64_t bytes_after_first_blocked = connect_stream->stream_bytes_written();

  // Inject WT_MAX_STREAMS_BIDI(1) — same value as current limit.
  InjectCapsuleOnConnectStream(
      session_id,
      quiche::Capsule(quiche::WebTransportMaxStreamsCapsule{
          webtransport::StreamType::kBidirectional, 1}));

  // Second blocked attempt — should NOT send another WT_STREAMS_BLOCKED
  // because the limit didn't increase.
  EXPECT_EQ(wt->OpenOutgoingBidirectionalStream(), nullptr);
  uint64_t bytes_after_second_blocked = connect_stream->stream_bytes_written();

  EXPECT_EQ(bytes_after_second_blocked, bytes_after_first_blocked)
      << "Receiving WT_MAX_STREAMS with the same value "
         "must not reset the blocked-sent flag (a duplicate "
         "WT_STREAMS_BLOCKED capsule was sent, enabling amplification)";
}

TEST_P(FlowControlDraft15Test,
       Section5_6_4_SameValueMaxDataIsNoOp) {
  // Section 5.6.4: Same-value WT_MAX_DATA must not reset the
  // data-blocked-sent flag.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/5);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open a stream and try to write more than the WT_MAX_DATA limit.
  webtransport::Stream* s = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(s, nullptr);

  QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);

  // Write exactly the limit to exhaust it.
  EXPECT_TRUE(s->Write("hello"));  // 5 bytes = limit

  // Next write should be blocked (data limit exhausted).
  EXPECT_FALSE(wt->CanSendData(1));

  // Explicitly send WT_DATA_BLOCKED to mark the flag as sent.
  wt->MaybeSendDataBlocked();
  uint64_t bytes_after_first_blocked = connect_stream->stream_bytes_written();

  // Inject WT_MAX_DATA(5) — same value as current limit.
  InjectCapsuleOnConnectStream(
      session_id,
      quiche::Capsule(quiche::WebTransportMaxDataCapsule{/*max_data=*/5}));

  // CanSendData should still be false — limit didn't change.
  EXPECT_FALSE(wt->CanSendData(1));

  // Call MaybeSendDataBlocked again. If the flag was reset by the
  // same-value WT_MAX_DATA, a duplicate capsule will be sent.
  wt->MaybeSendDataBlocked();
  uint64_t bytes_after_same_value = connect_stream->stream_bytes_written();
  EXPECT_EQ(bytes_after_same_value, bytes_after_first_blocked)
      << "Receiving WT_MAX_DATA with the same value "
         "must not reset the data-blocked-sent flag";
}

TEST_P(FlowControlDraft15Test,
       Section6_FCCapsulesIgnoredAfterTermination) {
  // Section 6: After a session is terminated, flow control capsules
  // should not mutate session state. Specifically, receiving WT_MAX_DATA
  // or WT_MAX_STREAMS after CloseSession() should be harmless (no crash,
  // no double-close, no state update).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/100);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Terminate the session.
  wt->CloseSession(0, "done");

  // These should not crash, assert, or trigger a double-close QUICHE_BUG.
  wt->OnMaxDataCapsuleReceived(999999);
  wt->OnMaxStreamsCapsuleReceived(
      webtransport::StreamType::kBidirectional, 999);
  wt->OnMaxStreamsCapsuleReceived(
      webtransport::StreamType::kUnidirectional, 999);

  // Verify the session is still in a clean terminated state.
  EXPECT_TRUE(connection_->connected())
      << "Post-termination FC capsules should be silently ignored, "
         "not trigger connection errors";
}

TEST_P(FlowControlDraft15Test,
       Section5_4_CanSendDataSafeWhenOverdrawn) {
  // Section 5.4: Defense-in-depth test. If total_data_sent_ ever
  // exceeds max_data_send_ (e.g., due to an accounting bug), CanSendData
  // must return false, not wrap around due to unsigned underflow.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/100);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Simulate an accounting overshoot: report more data sent than allowed.
  wt->OnDataSent(150);

  // CanSendData(1) must return false, not true (from unsigned wrap).
  EXPECT_FALSE(wt->CanSendData(1))
      << "When total_data_sent_ > max_data_send_, "
         "CanSendData must return false, not wrap around via "
         "unsigned underflow";
}

TEST_P(FlowControlDraft15Test,
       Section5_6_4_MaxDataReplenishmentClampsToVarint62) {
  // Verify that WT_MAX_DATA replenishment clamps to varint62 max (2^62-1)
  // rather than overflowing.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  constexpr uint64_t kMaxVarint62 = (1ULL << 62) - 1;
  // Use a large initial limit close to the varint62 max. When replenishment
  // computes new_max = max_data_receive_ + initial_max_data_receive_, it
  // would overflow past kMaxVarint62 without clamping.
  constexpr uint64_t kNearMax = kMaxVarint62 - 100;
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
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr);

  // Override the local data limit to near varint62 max.
  wt->SetInitialDataLimit(/*max_data_send=*/65536,
                          /*max_data_receive=*/kNearMax);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Simulate receiving and consuming enough data to trigger replenishment.
  // Replenishment triggers when available < initial/2, so consume most of
  // the window. OnIncomingDataReceived tracks received bytes;
  // OnIncomingDataConsumed tracks consumed bytes and triggers replenishment.
  wt->OnIncomingDataReceived(kNearMax);
  wt->OnIncomingDataConsumed(kNearMax);

  // If the clamping works, max_data_receive_ should be kMaxVarint62,
  // not an overflowed value. We can verify by checking that CanSendData
  // (peer's limit) is unaffected and the connection is still alive.
  EXPECT_TRUE(connection_->connected())
      << "Connection should remain alive after clamped replenishment";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, Section5_6_4_MaxDataRaiseUnblocksStreams) {
  // Section 5.6.4: When WT_MAX_DATA is raised, streams that were previously
  // blocked by the session data limit should be scheduled for a write attempt.
  // This mirrors QUIC's MAX_DATA → OnWindowUpdateFrame →
  // MarkConnectionLevelWriteBlocked path.
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
                         /*initial_max_data=*/100);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Open a stream and write exactly 100 bytes (exhausting the limit).
  webtransport::Stream* stream = wt->OpenOutgoingBidirectionalStream();
  ASSERT_NE(stream, nullptr);
  std::string data_100(100, 'a');
  EXPECT_TRUE(stream->Write(data_100));

  // Confirm the limit is exhausted.
  EXPECT_FALSE(wt->CanSendData(1))
      << "Limit should be exhausted after writing 100 bytes";

  // Clear the write-blocked list state so we can observe the effect of
  // raising WT_MAX_DATA.
  session_->OnCanWrite();

  // Raise the data limit.
  wt->OnMaxDataCapsuleReceived(200);

  // The stream should now be on the write-blocked list, scheduled for a
  // write attempt.
  EXPECT_TRUE(test::QuicSessionPeer::GetWriteBlockedStreams(&*session_)
                  ->HasWriteBlockedDataStreams())
      << "Raising WT_MAX_DATA must schedule associated "
         "streams for write attempts";
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(FlowControlDraft15Test, ResetIncomingStreamAccountsUnreadData) {
  // Section 5.4: Resetting an incoming stream before reading must account
  // for received bytes as consumed, so the WT_MAX_DATA window replenishes.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/100);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr);
  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());

  // Peer sends 60 bytes on stream A.
  QuicStreamId uni_a =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, uni_a,
                                          std::string(60, 'a'));

  // Accept stream A but don't read — reset it immediately.
  webtransport::Stream* stream_a = wt->AcceptIncomingUnidirectionalStream();
  ASSERT_NE(stream_a, nullptr);
  stream_a->SendStopSending(0);

  // Peer sends 60 more bytes on stream B (total received = 120 > limit 100).
  // Stream A's 60 bytes should have been accounted as consumed when reset,
  // triggering WT_MAX_DATA replenishment so that 120 < new limit.
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(0);

  QuicStreamId uni_b =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 5);
  ReceiveWebTransportUnidirectionalStream(session_id, uni_b,
                                          std::string(60, 'b'));

  EXPECT_NE(wt->OpenOutgoingBidirectionalStream(), nullptr)
      << "Unread data on a reset stream must be accounted as "
         "consumed so the WT_MAX_DATA window replenishes";
  testing::Mock::VerifyAndClearExpectations(visitor);
}

}  // namespace
}  // namespace quic
