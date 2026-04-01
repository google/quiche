// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 tests for capsule dispatch through a WebTransport session.
// These require a full QUIC session with draft-15 negotiation.
// Pure capsule serialization tests live in quiche/common/capsule_draft15_test.cc.

#include <string>

#include "quiche/common/capsule.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace {

using ::testing::_;
using ::testing::Return;

class CapsuleDraft15SessionTest : public test::Draft15SessionTest {
 protected:
  CapsuleDraft15SessionTest()
      : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(
    CapsuleDraft15SessionTests, CapsuleDraft15SessionTest,
    ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(CapsuleDraft15SessionTest, WtCloseSessionFinAfterCapsule) {
  // Section 6 MUST: An endpoint that sends a CLOSE_WEBTRANSPORT_SESSION
  // capsule MUST send a FIN on the CONNECT stream after the capsule.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  wt->CloseSession(42, "bye");

  QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(GetNthClientInitiatedBidirectionalId(0)));
  ASSERT_NE(connect_stream, nullptr);
  EXPECT_TRUE(connect_stream->write_side_closed())
      << "CONNECT stream write side should be closed after CloseSession "
         "(FIN sent)";
}

TEST_P(CapsuleDraft15SessionTest, DataAfterCloseSessionIsError) {
  // Section 6 MUST: Receiving data after CLOSE_WEBTRANSPORT_SESSION
  // should result in the read side being closed (StopReading) and
  // a STOP_SENDING with H3_MESSAGE_ERROR sent to the peer.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  // Get stream reference before close (stream may be destroyed after).
  QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  wt->OnCloseReceived(0, "");
  EXPECT_TRUE(wt->close_received());
  EXPECT_TRUE(connect_stream->reading_stopped())
      << "CONNECT stream should stop reading after "
         "CLOSE_WEBTRANSPORT_SESSION to reject further data";
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(CapsuleDraft15SessionTest, CleanCloseWithoutCapsule) {
  // Section 6: If the CONNECT stream receives a FIN without a
  // CLOSE_WEBTRANSPORT_SESSION capsule, the session is closed with
  // error code 0 and empty message.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(Return(WriteResult(WRITE_STATUS_OK, 0)));

  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnSessionClosed(0, ""));

  wt->OnConnectStreamFinReceived();
  testing::Mock::VerifyAndClearExpectations(writer_);
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(CapsuleDraft15SessionTest, SessionTerminationResetsStreams) {
  // Section 6 MUST: When a session is terminated, all associated streams
  // MUST be reset with WT_SESSION_GONE.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  QuicStreamId peer_uni_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(
          transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, peer_uni_id, "data");
  QuicStreamId peer_bidi_id = GetNthClientInitiatedBidirectionalId(1);
  ReceiveWebTransportBidirectionalStream(session_id, peer_bidi_id);

  EXPECT_GT(wt->NumberOfAssociatedStreams(), 0u);

  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(testing::AtMost(1));

  session_->set_writev_consumes_all_data(true);
  wt->CloseSession(0, "terminated");

  EXPECT_EQ(wt->NumberOfAssociatedStreams(), 0u)
      << "All associated streams should be reset after session termination";
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(CapsuleDraft15SessionTest, NoNewStreamsAfterTermination) {
  // Section 6 MUST NOT: After session termination, no new streams or
  // datagrams may be created.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  wt->CloseSession(0, "");

  EXPECT_EQ(wt->OpenOutgoingBidirectionalStream(), nullptr);
  EXPECT_EQ(wt->OpenOutgoingUnidirectionalStream(), nullptr);

  auto status = wt->SendOrQueueDatagram("post-termination");
  EXPECT_NE(status.code, webtransport::DatagramStatusCode::kSuccess);
}

TEST_P(CapsuleDraft15SessionTest, CloseSessionMessageTooLongAtSession) {
  // Section 6 MUST NOT: The error message in CloseSession() MUST NOT
  // exceed 1024 bytes. The message is truncated with a QUICHE_BUG.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);

  std::string long_message(1025, 'x');
  EXPECT_QUICHE_BUG(wt->CloseSession(42, long_message),
                    "exceeds 1024 bytes");
}

TEST_P(CapsuleDraft15SessionTest, DrainSessionIdempotent) {
  // Section 4.7: NotifySessionDraining() emits a WT_DRAIN_SESSION capsule
  // on the CONNECT stream. Calling it twice should emit data only once.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);

  QuicStream* connect_stream = session_->GetOrCreateStream(session_id);
  ASSERT_NE(connect_stream, nullptr);
  QuicStreamOffset bytes_before =
      test::QuicStreamPeer::SendBuffer(connect_stream).stream_bytes_written();

  wt->NotifySessionDraining();

  QuicStreamOffset bytes_after_first =
      test::QuicStreamPeer::SendBuffer(connect_stream).stream_bytes_written();
  EXPECT_GT(bytes_after_first, bytes_before)
      << "NotifySessionDraining() must emit a "
         "WT_DRAIN_SESSION capsule on the CONNECT stream";

  wt->NotifySessionDraining();
  QuicStreamOffset bytes_after_second =
      test::QuicStreamPeer::SendBuffer(connect_stream).stream_bytes_written();
  EXPECT_EQ(bytes_after_second, bytes_after_first)
      << "Second NotifySessionDraining() should not emit additional data";
}

TEST_P(CapsuleDraft15SessionTest,
       Section6_OnCloseReceivedResetsAssociatedStreams) {
  // Section 6 MUST: "Upon learning that the session has been terminated, the
  // endpoint MUST reset the send side and abort reading on the receive side
  // of all [...] streams associated with the session [...] using the
  // WT_SESSION_GONE error code."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Associate some streams with the session.
  QuicStreamId peer_uni_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, peer_uni_id, "data");
  QuicStreamId peer_bidi_id = GetNthClientInitiatedBidirectionalId(1);
  ReceiveWebTransportBidirectionalStream(session_id, peer_bidi_id);

  EXPECT_GT(wt->NumberOfAssociatedStreams(), 0u)
      << "Precondition: session should have associated streams";

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(_, _)).Times(testing::AtMost(1));
  wt->OnCloseReceived(0, "bye");

  EXPECT_EQ(wt->NumberOfAssociatedStreams(), 0u)
      << "All associated streams must be reset immediately upon "
         "receiving CLOSE_WEBTRANSPORT_SESSION, not deferred until "
         "OnConnectStreamClosing";
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(CapsuleDraft15SessionTest,
       Section6_OnFinReceivedResetsAssociatedStreams) {
  // Section 6: Same behavior when session terminates via FIN without capsule.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr);

  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnIncomingBidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  QuicStreamId peer_uni_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, peer_uni_id, "data");

  EXPECT_GT(wt->NumberOfAssociatedStreams(), 0u);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*visitor, OnSessionClosed(0, ""));
  EXPECT_CALL(*writer_, WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(Return(WriteResult(WRITE_STATUS_OK, 0)));
  wt->OnConnectStreamFinReceived();

  EXPECT_EQ(wt->NumberOfAssociatedStreams(), 0u)
      << "Streams must be reset upon FIN without capsule";
  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(CapsuleDraft15SessionTest,
       Section6_PostCloseDataResetsWithMessageError) {
  // Section 6 MUST: "If any additional stream data is received on the
  // CONNECT stream after receiving a WT_CLOSE_SESSION capsule, the stream
  // MUST be reset with code H3_MESSAGE_ERROR."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Capture STOP_SENDING frames during OnCloseReceived.
  bool got_stop_sending_message_error = false;
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(
          [&got_stop_sending_message_error](const QuicFrame& frame) {
            if (frame.type == STOP_SENDING_FRAME &&
                frame.stop_sending_frame.ietf_error_code ==
                    static_cast<uint64_t>(
                        QuicHttp3ErrorCode::MESSAGE_ERROR)) {
              got_stop_sending_message_error = true;
            }
            test::ClearControlFrame(frame);
            return true;
          });

  // Receive CLOSE_WEBTRANSPORT_SESSION from peer.
  wt->OnCloseReceived(0, "");
  ASSERT_TRUE(wt->close_received());

  // Section 6: OnCloseReceived sends STOP_SENDING to reject further data.
  EXPECT_TRUE(got_stop_sending_message_error)
      << "After receiving WT_CLOSE_SESSION, the CONNECT stream "
         "should send STOP_SENDING with H3_MESSAGE_ERROR";
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(CapsuleDraft15SessionTest, DrainSessionReceivedTwiceIsIdempotent) {
  // Receiving WT_DRAIN_SESSION twice should not crash — the callback is
  // cleared after the first invocation, and the second is a no-op.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ServerSession(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr);

  bool drain_called = false;
  wt->SetOnDraining([&drain_called]() { drain_called = true; });

  // First WT_DRAIN_SESSION — callback should fire.
  wt->OnDrainSessionReceived();
  EXPECT_TRUE(drain_called) << "Drain callback should fire on first receive";

  // Second WT_DRAIN_SESSION — should be a no-op (no crash).
  drain_called = false;
  wt->OnDrainSessionReceived();
  EXPECT_FALSE(drain_called)
      << "Drain callback should not fire again on second receive";

  EXPECT_TRUE(connection_->connected())
      << "Connection should remain open after duplicate drain";
}

}  // namespace
}  // namespace quic
