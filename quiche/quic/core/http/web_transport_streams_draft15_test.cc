// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for WebTransport stream format (Section 4.2, 4.3).

#include <cstdint>
#include <string>

#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"

namespace quic {
namespace {

using ::testing::_;

// --- Stream type assertions (Section 4.2, 4.3) ---
// These validate existing constants against draft-15 spec values.
// PASS immediately.

TEST(WebTransportStreamsDraft15, UnidirectionalStreamType0x54) {
  // Section 4.2: Unidirectional WT streams use stream type byte 0x54.
  EXPECT_EQ(kWebTransportUnidirectionalStream,
            webtransport::draft15::kUniStreamType);
  EXPECT_EQ(kWebTransportUnidirectionalStream, 0x54u);
}

// --- Session-based tests (Section 4.3) ---

class StreamsDraft15SessionTest : public test::Draft15SessionTest {
 protected:
  StreamsDraft15SessionTest() : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(StreamsDraft15SessionTests,
                         StreamsDraft15SessionTest,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(StreamsDraft15SessionTest, BidirectionalSignal0x41) {
  // Section 4.3 MUST: Bidirectional WT streams start with signal byte 0x41
  // (WT_STREAM) followed by the session ID.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  // Verify the constant value.
  EXPECT_EQ(webtransport::draft15::kBidiSignal, 0x41u);

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id, /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Inject a peer-initiated bidi stream with the 0x41 signal byte + session_id.
  QuicStreamId peer_bidi_id = GetNthClientInitiatedBidirectionalId(1);
  ReceiveWebTransportBidirectionalStream(session_id, peer_bidi_id);

  // The session should have an incoming bidi stream available.
  WebTransportStream* incoming = wt->AcceptIncomingBidirectionalStream();
  EXPECT_NE(incoming, nullptr)
      << "Expected incoming bidi stream to be associated with the WT session";
}

TEST_P(StreamsDraft15SessionTest, SessionIdMustBeClientInitiatedBidi) {
  // Section 4 MUST: The session ID MUST be a client-initiated bidirectional
  // stream ID. Non-client-initiated IDs trigger H3_ID_ERROR.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id, /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // A server-initiated bidirectional stream ID is not valid as a session ID.
  QuicStreamId server_bidi_id = GetNthServerInitiatedBidirectionalId(0);
  // Verify the ID is indeed server-initiated (bit 0 = 1 for server).
  EXPECT_EQ(server_bidi_id % 4, 1u)
      << "Expected a server-initiated bidirectional stream ID";

  // Inject a uni stream that references the invalid server-initiated session ID.
  // This should trigger an error since session IDs must be client-initiated
  // bidirectional stream IDs.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  QuicErrorCode observed_error;
  EXPECT_CALL(*connection_, CloseConnection(_, _, _))
      .WillOnce(testing::SaveArg<0>(&observed_error));
  ReceiveWebTransportUnidirectionalStream(server_bidi_id, uni_stream_id);

  QuicErrorCodeToIetfMapping mapping =
      QuicErrorCodeToTransportErrorCode(observed_error);
  EXPECT_EQ(mapping.error_code,
            static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR))
      << "Invalid session ID must close with H3_ID_ERROR (0x108)";
}

TEST_P(StreamsDraft15SessionTest, WtStreamNotAtStreamStart) {
  // Section 4.3 MUST: The WT_STREAM signal (0x41) MUST appear at the start
  // of the stream. If it appears elsewhere, it's an H3_FRAME_ERROR.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id, /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Use a different client-initiated bidi stream (not the CONNECT stream).
  QuicStreamId bidi_stream_id = GetNthClientInitiatedBidirectionalId(1);

  // First, deliver headers on the bidi stream so it becomes a proper HTTP
  // request stream, then deliver a WT_STREAM signal mid-stream (after the
  // headers have been processed).
  QuicStreamFrame frame0(bidi_stream_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
  session_->OnStreamFrame(frame0);
  QuicSpdyStream* bidi_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(bidi_stream_id));
  ASSERT_NE(bidi_stream, nullptr);

  // Deliver request headers via OnStreamHeaderList (bypasses QPACK).
  QuicHeaderList headers;
  headers.OnHeader(":method", "GET");
  headers.OnHeader(":path", "/test");
  headers.OnHeader(":scheme", "https");
  headers.OnHeader(":authority", "test.example.com");
  bidi_stream->OnStreamHeaderList(/*fin=*/false, 0, headers);

  // Now deliver a DATA frame to consume some stream bytes, pushing the
  // sequencer offset past zero.
  std::string data_frame;
  data_frame.push_back(0x00);  // DATA frame type
  data_frame.push_back(0x03);  // payload length = 3
  data_frame.append("abc");    // payload

  // Then append the WT_STREAM signal after the DATA frame.
  std::string signal_data;
  char type_buf[8];
  QuicDataWriter type_writer(sizeof(type_buf), type_buf);
  ASSERT_TRUE(type_writer.WriteVarInt62(0x41));
  signal_data.append(type_buf, type_writer.length());
  char varint_buf[8];
  QuicDataWriter varint_writer(sizeof(varint_buf), varint_buf);
  ASSERT_TRUE(varint_writer.WriteVarInt62(session_id));
  signal_data.append(varint_buf, varint_writer.length());

  std::string combined = data_frame + signal_data;

  // Section 4.3 requires H3_FRAME_ERROR (0x106) on the wire.
  QuicErrorCode observed_error;
  EXPECT_CALL(*connection_, CloseConnection(_, _, _))
      .WillOnce(testing::SaveArg<0>(&observed_error));
  QuicStreamFrame frame2(bidi_stream_id, /*fin=*/false,
                          /*offset=*/0, combined);
  session_->OnStreamFrame(frame2);

  QuicErrorCodeToIetfMapping mapping =
      QuicErrorCodeToTransportErrorCode(observed_error);
  EXPECT_EQ(mapping.error_code,
            static_cast<uint64_t>(QuicHttp3ErrorCode::FRAME_ERROR))
      << "WT_STREAM at non-zero offset must close with "
         "H3_FRAME_ERROR (0x106)";
}

TEST_P(StreamsDraft15SessionTest, UniStreamPreambleFormat) {
  // Section 4.2: Outgoing unidirectional WT streams must have a preamble of
  // varint(0x54) + varint(session_id).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);
  session_->set_writev_consumes_all_data(true);
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Open an outgoing unidirectional stream.
  WebTransportStream* stream = wt->OpenOutgoingUnidirectionalStream();
  ASSERT_NE(stream, nullptr)
      << "Expected to open an outgoing unidirectional stream";

  // The stream should have buffered a preamble: varint(0x54) + varint(session_id).
  // Build the expected preamble.
  std::string expected_preamble;
  expected_preamble.push_back(0x54);
  char varint_buf[8];
  QuicDataWriter varint_writer(sizeof(varint_buf), varint_buf);
  ASSERT_TRUE(varint_writer.WriteVarInt62(session_id));
  expected_preamble.append(varint_buf, varint_writer.length());

  // Look up the underlying QUIC stream by its ID to check the send buffer.
  webtransport::StreamId wt_stream_id = stream->GetStreamId();
  QuicStream* quic_stream = session_->GetOrCreateStream(
      static_cast<QuicStreamId>(wt_stream_id));
  ASSERT_NE(quic_stream, nullptr);
  auto& send_buffer = test::QuicStreamPeer::SendBuffer(quic_stream);
  EXPECT_GE(send_buffer.stream_bytes_written(), expected_preamble.size())
      << "Stream should have written the preamble bytes";
}

TEST_P(StreamsDraft15SessionTest, IncomingUniStreamAssociation) {
  // Section 4.2: Incoming unidirectional streams with type 0x54 and a valid
  // session ID should be associated with the WT session.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id, /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Attach a visitor to observe stream association callbacks.
  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());

  size_t initial_streams = wt->NumberOfAssociatedStreams();

  // Allow MAX_STREAMS and other control frames from stream creation.
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);

  // Inject a unidirectional stream from the peer (client).
  // Use index 4+ to avoid HTTP/3 control stream at index 3.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_id,
                                          "test payload");

  // The incoming uni stream should be available on the WT session.
  WebTransportStream* incoming = wt->AcceptIncomingUnidirectionalStream();
  EXPECT_NE(incoming, nullptr)
      << "Expected incoming uni stream to be associated with the WT session";
  EXPECT_GT(wt->NumberOfAssociatedStreams(), initial_streams)
      << "NumberOfAssociatedStreams should have increased";
  testing::Mock::VerifyAndClearExpectations(connection_);
  testing::Mock::VerifyAndClearExpectations(visitor);
}

TEST_P(StreamsDraft15SessionTest, IncomingBidiStreamAssociation) {
  // Section 4.3: Incoming bidirectional streams with signal 0x41 and a valid
  // session ID should be associated with the WT session.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id, /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  size_t initial_streams = wt->NumberOfAssociatedStreams();

  // Inject a bidirectional stream from the peer (client).
  QuicStreamId bidi_stream_id = GetNthClientInitiatedBidirectionalId(1);
  ReceiveWebTransportBidirectionalStream(session_id, bidi_stream_id);

  // The incoming bidi stream should be available on the WT session.
  WebTransportStream* incoming = wt->AcceptIncomingBidirectionalStream();
  EXPECT_NE(incoming, nullptr)
      << "Expected incoming bidi stream to be associated with the WT session";
  EXPECT_GT(wt->NumberOfAssociatedStreams(), initial_streams)
      << "NumberOfAssociatedStreams should have increased";
}

TEST_P(StreamsDraft15SessionTest, UnknownSessionIdBuffered) {
  // Section 4.6: Streams referencing a session ID that doesn't exist yet
  // should be buffered, not immediately reset. When the session is later
  // established, the buffered stream should become associated.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  // Use a future session ID (not yet established).
  QuicStreamId future_session_id = GetNthClientInitiatedBidirectionalId(1);

  // Inject a uni stream referencing the future session ID before establishing
  // that session. The stream should be buffered, not reset.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(future_session_id, uni_stream_id,
                                          "buffered data");

  // The stream should not be closed/reset yet.
  QuicStream* raw_stream = session_->GetOrCreateStream(uni_stream_id);
  EXPECT_NE(raw_stream, nullptr)
      << "Buffered stream should still exist before session is established";

  // Now establish the session with that ID.
  auto* wt = AttemptWebTransportDraft15Session(future_session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // The previously buffered stream should now be associated with the session.
  WebTransportStream* incoming = wt->AcceptIncomingUnidirectionalStream();
  EXPECT_NE(incoming, nullptr)
      << "Buffered stream should be delivered after session establishment";
}

TEST_P(StreamsDraft15SessionTest, InvalidSessionIdOnUniStream) {
  // Section 4 MUST: "If the Session ID [...] is not a client-initiated
  // bidirectional stream [...] the recipient MUST close the connection with
  // an H3_ID_ERROR error." H3_ID_ERROR = 0x108.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id,
                                       /*initial_max_streams_uni=*/10,
                                       /*initial_max_streams_bidi=*/10,
                                       /*initial_max_data=*/65536);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // A unidirectional stream ID is not a valid session ID.
  QuicStreamId invalid_session_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 0);

  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);

  // Section 4 requires H3_ID_ERROR (0x108) on the wire.
  QuicErrorCode observed_error;
  EXPECT_CALL(*connection_, CloseConnection(_, _, _))
      .WillOnce(testing::SaveArg<0>(&observed_error));
  ReceiveWebTransportUnidirectionalStream(invalid_session_id, uni_stream_id);

  QuicErrorCodeToIetfMapping mapping =
      QuicErrorCodeToTransportErrorCode(observed_error);
  EXPECT_EQ(mapping.error_code,
            static_cast<uint64_t>(QuicHttp3ErrorCode::ID_ERROR))
      << "Invalid session ID must close with H3_ID_ERROR (0x108)";
}

}  // namespace
}  // namespace quic
