// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for stream/datagram buffering (Section 4.6).

#include <cstdint>
#include <memory>
#include <string>

#include "absl/strings/str_cat.h"

#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"

namespace quic {
namespace {

using ::testing::_;
using ::testing::Not;
using test::MockWebTransportSessionVisitor;

class BufferingDraft15Test : public test::Draft15SessionTest {
 protected:
  BufferingDraft15Test() : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(BufferingDraft15, BufferingDraft15Test,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

TEST_P(BufferingDraft15Test, BufferStreamsUntilSession) {
  // Section 4.6 SHOULD: Streams arriving before the session is fully
  // established should be buffered pending session association.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  // The session ID will be on the first client-initiated bidi stream.
  QuicStreamId future_session_id = GetNthClientInitiatedBidirectionalId(0);

  // Inject a uni stream BEFORE the session is established.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(future_session_id, uni_stream_id,
                                          "pre-session data");

  // Now establish the session.
  auto* wt = AttemptWebTransportDraft15Session(future_session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // The previously buffered stream should now be available.
  WebTransportStream* incoming = wt->AcceptIncomingUnidirectionalStream();
  EXPECT_NE(incoming, nullptr)
      << "Stream injected before session should be buffered and delivered";
}

TEST_P(BufferingDraft15Test, BufferDatagramsUntilSession) {
  // Section 4.6 SHOULD: "Endpoints SHOULD buffer [...] datagrams [...] until
  // the streams can be associated with the appropriate session."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  session_->set_buffer_web_transport_datagrams(true);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);

  // Create the QUIC stream without delivering headers — session not yet
  // established.
  QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                        absl::string_view());
  session_->OnStreamFrame(frame);
  ASSERT_NE(session_->GetOrCreateStream(session_id), nullptr);

  // HTTP/3 datagrams use quarter-stream-ID encoding: varint(session_id/4) +
  // payload.
  uint64_t quarter_id = session_id / kHttpDatagramStreamIdDivisor;
  std::string datagram;
  char varint_buf[8];
  QuicDataWriter writer(sizeof(varint_buf), varint_buf);
  ASSERT_TRUE(writer.WriteVarInt62(quarter_id));
  datagram.append(varint_buf, writer.length());
  datagram.append("pre-session payload");
  session_->OnDatagramReceived(datagram);

  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Session should be established";

  // Expectations must be set before SetVisitor because SetVisitor flushes
  // buffered datagrams.
  int datagram_count = 0;
  auto mock = std::make_unique<
      testing::NiceMock<MockWebTransportSessionVisitor>>();
  auto* raw = mock.get();
  EXPECT_CALL(*raw, OnDatagramReceived(_))
      .WillRepeatedly([&datagram_count](absl::string_view) {
        ++datagram_count;
      });
  wt->SetVisitor(std::move(mock));

  EXPECT_GE(datagram_count, 1)
      << "Pre-session datagram must be buffered and "
         "delivered after session establishment";
  testing::Mock::VerifyAndClearExpectations(raw);
}

TEST_P(BufferingDraft15Test, ExcessBufferedStreamsRejected) {
  // Section 4.6 MUST: Excess buffered streams are rejected with
  // WT_BUFFERED_STREAM_REJECTED.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  EXPECT_EQ(webtransport::draft15::kWtBufferedStreamRejected, 0x3994bd84u);

  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/100,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  // Use a future session ID that hasn't been established yet.
  QuicStreamId future_session_id = GetNthClientInitiatedBidirectionalId(0);

  // Inject more uni streams than the buffering limit allows, all referencing
  // the future session ID. The first kMaxUnassociatedWebTransportStreams
  // should be buffered; the rest should be reset.
  // Section 4.6: Excess buffered streams SHALL be closed with RESET_STREAM
  // and/or STOP_SENDING with WT_BUFFERED_STREAM_REJECTED (0x3994bd84).
  // For incoming uni streams, only STOP_SENDING is applicable.
  EXPECT_CALL(*connection_,
              SendControlFrame(test::IsStopSendingWithIetfCode(
                  webtransport::draft15::kWtBufferedStreamRejected)))
      .Times(4)  // total_streams - kMaxUnassociatedWebTransportStreams
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_,
              SendControlFrame(
                  Not(test::IsStopSendingWithIetfCode(
                      webtransport::draft15::kWtBufferedStreamRejected))))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());
  const size_t total_streams = kMaxUnassociatedWebTransportStreams + 4;
  for (size_t i = 0; i < total_streams; ++i) {
    // Use client-initiated uni stream IDs starting at index 4 (skip HTTP/3
    // control streams at indices 0-2 and the control stream at index 3).
    QuicStreamId uni_stream_id =
        test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(),
                                                         4 + i);
    ReceiveWebTransportUnidirectionalStream(future_session_id, uni_stream_id,
                                            "data");
  }

  // Now establish the session.
  auto* wt = AttemptWebTransportDraft15Session(future_session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Count how many incoming uni streams are available. It should be at most
  // kMaxUnassociatedWebTransportStreams.
  size_t accepted_count = 0;
  while (wt->AcceptIncomingUnidirectionalStream() != nullptr) {
    ++accepted_count;
  }
  EXPECT_LE(accepted_count, kMaxUnassociatedWebTransportStreams)
      << "Excess streams beyond the buffer limit should have been rejected";
}

// A WebTransport server visitor that accepts incoming streams in response to
// OnIncoming*StreamAvailable() callbacks, as real server applications do
// (e.g., QuicSimpleServerStream, WebTransportOnlyServerSession).
class CallbackDrivenVisitor : public WebTransportVisitor {
 public:
  explicit CallbackDrivenVisitor(WebTransportSession* session)
      : session_(session) {}

  void OnSessionReady() override { session_ready_ = true; }
  void OnSessionClosed(WebTransportSessionError /*error_code*/,
                       const std::string& /*error_message*/) override {}

  void OnIncomingUnidirectionalStreamAvailable() override {
    while (WebTransportStream* stream =
               session_->AcceptIncomingUnidirectionalStream()) {
      accepted_uni_streams_.push_back(stream);
    }
  }

  void OnIncomingBidirectionalStreamAvailable() override {
    while (WebTransportStream* stream =
               session_->AcceptIncomingBidirectionalStream()) {
      accepted_bidi_streams_.push_back(stream);
    }
  }

  void OnDatagramReceived(absl::string_view /*datagram*/) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

  bool session_ready() const { return session_ready_; }
  const std::vector<WebTransportStream*>& accepted_uni_streams() const {
    return accepted_uni_streams_;
  }

 private:
  WebTransportSession* session_;
  bool session_ready_ = false;
  std::vector<WebTransportStream*> accepted_uni_streams_;
  std::vector<WebTransportStream*> accepted_bidi_streams_;
};

TEST_P(BufferingDraft15Test, BufferedStreamDeliveredToCallbackDrivenVisitor) {
  // Section 4.6: Streams arriving before the CONNECT request (due to QUIC
  // transport-layer reordering) are buffered. Once the session is established,
  // the visitor must be notified about them via
  // OnIncomingUnidirectionalStreamAvailable() so that a callback-driven
  // application can accept them.
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

  // A unidirectional stream arrives before the CONNECT request.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_id,
                                          "early data");

  // Create the session without calling HeadersReceived — we need to set the
  // visitor first (matching the real server flow).
  QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                        absl::string_view());
  session_->OnStreamFrame(frame);
  auto* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);
  QuicHeaderList request_headers;
  request_headers.OnHeader(":method", "CONNECT");
  request_headers.OnHeader(":protocol", "webtransport-h3");
  request_headers.OnHeader(":scheme", "https");
  request_headers.OnHeader(":authority", "test.example.com");
  request_headers.OnHeader(":path", "/wt");
  connect_stream->OnStreamHeaderList(/*fin=*/false, 0, request_headers);
  auto* wt = session_->GetWebTransportSession(session_id);
  ASSERT_NE(wt, nullptr);

  // Attach a callback-driven visitor (the standard server application pattern).
  auto visitor = std::make_unique<CallbackDrivenVisitor>(wt);
  CallbackDrivenVisitor* raw_visitor = visitor.get();
  wt->SetVisitor(std::move(visitor));

  // Server calls HeadersReceived() after setting the visitor.
  quiche::HttpHeaderBlock response_headers;
  wt->HeadersReceived(response_headers);
  ASSERT_TRUE(raw_visitor->session_ready());

  // The pre-buffered stream must have been delivered to the visitor.
  EXPECT_EQ(raw_visitor->accepted_uni_streams().size(), 1u);
}

TEST_P(BufferingDraft15Test, ExcessBufferedDatagramsDropped) {
  // Section 4.6 MUST/SHALL: "Endpoints MUST limit the number of [...] buffered
  // datagrams [...]. Excess datagrams SHALL be dropped."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  session_->set_buffer_web_transport_datagrams(true);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);

  // Create the QUIC stream without delivering headers.
  QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                        absl::string_view());
  session_->OnStreamFrame(frame);
  ASSERT_NE(session_->GetOrCreateStream(session_id), nullptr);

  const int kNumDatagrams = 200;
  uint64_t quarter_id = session_id / kHttpDatagramStreamIdDivisor;
  for (int i = 0; i < kNumDatagrams; ++i) {
    std::string datagram;
    char varint_buf[8];
    QuicDataWriter writer(sizeof(varint_buf), varint_buf);
    ASSERT_TRUE(writer.WriteVarInt62(quarter_id));
    datagram.append(varint_buf, writer.length());
    datagram.append(absl::StrCat("datagram-", i));
    session_->OnDatagramReceived(datagram);
  }

  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Session should be established";

  // Expectations must be set before SetVisitor because SetVisitor flushes
  // buffered datagrams.
  int datagram_count = 0;
  auto mock = std::make_unique<
      testing::NiceMock<MockWebTransportSessionVisitor>>();
  auto* raw = mock.get();
  EXPECT_CALL(*raw, OnDatagramReceived(_))
      .WillRepeatedly([&datagram_count](absl::string_view) {
        ++datagram_count;
      });
  wt->SetVisitor(std::move(mock));

  EXPECT_GT(datagram_count, 0)
      << "Pre-session datagrams must be buffered";
  EXPECT_LT(datagram_count, kNumDatagrams)
      << "Excess buffered datagrams must be dropped";
  testing::Mock::VerifyAndClearExpectations(raw);
}

TEST_P(BufferingDraft15Test, Section5_4_PreAssociationDataCountedAgainstMaxData) {
  // Section 5.4: Data arriving on a WT stream BEFORE the session is established
  // (transport-layer reordering per Section 4.6) must still be counted against
  // WT_MAX_DATA. Otherwise the receive-side flow control is bypassed.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  const uint64_t kLocalMaxData = 50;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/kLocalMaxData);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);

  // Inject a uni stream with exactly kLocalMaxData bytes BEFORE the session
  // is established.
  QuicStreamId uni_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 4);
  std::string payload(kLocalMaxData, 'x');
  ReceiveWebTransportUnidirectionalStream(session_id, uni_stream_id, payload);

  // Set up mock expectations before establishing the session, since the
  // FC violation can fire during session establishment or stream injection.
  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  // Now establish the session. The buffered data should be counted.
  auto* wt = AttemptWebTransportDraft15Session(session_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  auto* visitor = AttachMockVisitor(wt);
  EXPECT_CALL(*visitor, OnIncomingUnidirectionalStreamAvailable())
      .Times(testing::AnyNumber());
  EXPECT_CALL(*visitor, OnSessionClosed(_, _))
      .Times(testing::AnyNumber());

  // Inject 1 more byte on a new stream. Total = kLocalMaxData + 1 > limit.
  QuicStreamId uni2_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 5);
  ReceiveWebTransportUnidirectionalStream(session_id, uni2_id, "Z");

  // Session should be terminated: pre-association data (50) + new data (1) = 51
  // exceeds WT_MAX_DATA = 50.
  EXPECT_FALSE(wt->CanOpenNextOutgoingBidirectionalStream())
      << "Pre-association data must be counted against "
         "WT_MAX_DATA. Total received (51) exceeds limit (50)";

  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(connection_);
}

}  // namespace
}  // namespace quic
