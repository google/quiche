// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Shared test infrastructure for draft-15 WebTransport tests.
// Extends QuicSpdySessionTestBase (from quic_spdy_session_test_utils.h) with
// draft-15-specific helpers for SETTINGS negotiation, session establishment,
// and capsule injection.

#ifndef QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_DRAFT15_TEST_UTILS_H_
#define QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_DRAFT15_TEST_UTILS_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_header_list.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_test_utils.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/web_transport_test_tools.h"
#include "quiche/common/capsule.h"
#include "quiche/web_transport/web_transport_headers.h"

namespace quic {
namespace test {

// Matches a QuicFrame that is a RST_STREAM with the given ietf_error_code.
// Use with SendControlFrame expectations to verify the HTTP/3 wire-level
// error code (e.g., kWtSessionGone, kWtBufferedStreamRejected).
MATCHER_P(IsRstStreamWithIetfCode, expected_code,
          absl::StrCat("is RST_STREAM with ietf_error_code=0x",
                       absl::Hex(static_cast<uint64_t>(expected_code)))) {
  if (arg.type != RST_STREAM_FRAME || arg.rst_stream_frame == nullptr) {
    return false;
  }
  *result_listener << "ietf_error_code=0x"
                   << absl::Hex(arg.rst_stream_frame->ietf_error_code);
  return arg.rst_stream_frame->ietf_error_code ==
         static_cast<uint64_t>(expected_code);
}

// ---------------------------------------------------------------------------
// Draft15SessionTest — parameterized test fixture for draft-15 tests.
// Extends QuicSpdySessionTestBase with draft-15-specific helpers.
// ---------------------------------------------------------------------------
class Draft15SessionTest : public QuicSpdySessionTestBase {
 protected:
  explicit Draft15SessionTest(
      Perspective perspective = Perspective::IS_SERVER,
      bool allow_extended_connect = true)
      : QuicSpdySessionTestBase(perspective, allow_extended_connect) {}

  void Initialize(
      WebTransportHttp3VersionSet wt_versions = WebTransportHttp3VersionSet(),
      HttpDatagramSupport datagram_support = HttpDatagramSupport::kNone) {
    session_.emplace(connection_);
    if (connection_->perspective() == Perspective::IS_SERVER &&
        VersionIsIetfQuic(transport_version())) {
      session_->set_allow_extended_connect(allow_extended_connect_);
    }
    session_->set_locally_supported_web_transport_versions(wt_versions);
    session_->set_local_http_datagram_support(datagram_support);
    session_->Initialize();
    session_->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (VersionIsIetfQuic(transport_version())) {
      // Allow enough incoming uni streams for HTTP/3 control + WT streams.
      QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
          session_->config(), kHttp3StaticUnidirectionalStreamCount + 16);
    }
    QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesUnidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    session_->OnConfigNegotiated();
    // Section 3.1: max_datagram_frame_size > 0 is required for WebTransport.
    QuicConfigPeer::SetReceivedMaxDatagramFrameSize(
        session_->config(), kMaxAcceptedDatagramFrameSize);
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .Times(testing::AnyNumber());
    writer_ = static_cast<MockPacketWriter*>(
        QuicConnectionPeer::GetWriter(session_->connection()));
  }

  // Sends a peer SETTINGS frame containing draft-15 WebTransport settings.
  // Also enables the reset_stream_at transport parameter on the connection
  // (Section 3.1 requires it for draft-15). This must be done after
  // CompleteHandshake() since OnConfigNegotiated() resets the flag.
  void ReceiveWebTransportDraft15Settings(
      uint64_t wt_enabled_value = 1,
      uint64_t initial_max_streams_uni = 0,
      uint64_t initial_max_streams_bidi = 0,
      uint64_t initial_max_data = 0) {
    const_cast<QuicFramer*>(&connection_->framer())
        ->set_process_reset_stream_at(true);
    SettingsFrame settings;
    settings.values[SETTINGS_H3_DATAGRAM] = 1;
    settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
    settings.values[SETTINGS_WT_ENABLED] = wt_enabled_value;
    if (initial_max_streams_uni > 0) {
      settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_UNI] =
          initial_max_streams_uni;
    }
    if (initial_max_streams_bidi > 0) {
      settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI] =
          initial_max_streams_bidi;
    }
    if (initial_max_data > 0) {
      settings.values[SETTINGS_WT_INITIAL_MAX_DATA] = initial_max_data;
    }
    std::string data = std::string(1, kControlStream) +
                       HttpEncoder::SerializeSettingsFrame(settings);
    QuicStreamId control_stream_id =
        session_->perspective() == Perspective::IS_SERVER
            ? GetNthClientInitiatedUnidirectionalStreamId(
                  transport_version(), 3)
            : GetNthServerInitiatedUnidirectionalStreamId(
                  transport_version(), 3);
    QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0,
                          data);
    session_->OnStreamFrame(frame);
  }

  // Sends peer SETTINGS for draft-07 WebTransport (for comparison tests).
  void ReceiveWebTransportDraft07Settings(uint64_t max_sessions = 16) {
    SettingsFrame settings;
    settings.values[SETTINGS_H3_DATAGRAM] = 1;
    settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
    settings.values[SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07] = max_sessions;
    std::string data = std::string(1, kControlStream) +
                       HttpEncoder::SerializeSettingsFrame(settings);
    QuicStreamId control_stream_id =
        session_->perspective() == Perspective::IS_SERVER
            ? GetNthClientInitiatedUnidirectionalStreamId(
                  transport_version(), 3)
            : GetNthServerInitiatedUnidirectionalStreamId(
                  transport_version(), 3);
    QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0,
                          data);
    session_->OnStreamFrame(frame);
  }

  // Server-perspective: creates an incoming CONNECT stream via OnStreamFrame,
  // delivers draft-15 headers, and completes the server handshake by calling
  // HeadersReceived (which processes buffered streams and marks the session
  // ready). Returns nullptr if the session could not be established.
  WebTransportHttp3* AttemptWebTransportDraft15Session(
      QuicStreamId session_id,
      const std::string& path = "/wt") {
    QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
    session_->OnStreamFrame(frame);
    QuicSpdyStream* connect_stream = static_cast<QuicSpdyStream*>(
        session_->GetOrCreateStream(session_id));
    if (connect_stream == nullptr) return nullptr;
    QuicHeaderList headers;
    headers.OnHeader(":method", "CONNECT");
    headers.OnHeader(":protocol", "webtransport-h3");
    headers.OnHeader(":scheme", "https");
    headers.OnHeader(":authority", "test.example.com");
    headers.OnHeader(":path", path);
    connect_stream->OnStreamHeaderList(/*fin=*/false, 0, headers);
    WebTransportHttp3* wt = session_->GetWebTransportSession(session_id);
    if (wt != nullptr) {
      quiche::HttpHeaderBlock response_headers;
      wt->HeadersReceived(response_headers);
    }
    return wt;
  }

  // Client-perspective: creates an outgoing CONNECT stream with WriteHeaders,
  // which triggers MaybeProcessSentWebTransportHeaders.
  WebTransportHttp3* AttemptWebTransportDraft15ClientSession(
      const std::string& path = "/wt") {
    session_->set_writev_consumes_all_data(true);
    EXPECT_CALL(*writer_,
                WritePacket(testing::_, testing::_, testing::_, testing::_,
                            testing::_, testing::_))
        .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
    TestStream* stream = session_->CreateOutgoingBidirectionalStream();
    if (stream == nullptr) return nullptr;
    quiche::HttpHeaderBlock headers;
    headers[":method"] = "CONNECT";
    headers[":protocol"] = "webtransport-h3";
    headers[":scheme"] = "https";
    headers[":authority"] = "test.example.com";
    headers[":path"] = path;
    stream->WriteHeaders(std::move(headers), /*fin=*/false, nullptr);
    testing::Mock::VerifyAndClearExpectations(writer_);
    return stream->web_transport();
  }

  // Composite setup: Initialize + CompleteHandshake + ReceiveWebTransportDraft15Settings +
  // AttemptWebTransportDraft15Session. Returns non-null WebTransportHttp3* or fails.
  WebTransportHttp3* SetUpWebTransportDraft15ServerSession(
      QuicStreamId session_id,
      uint64_t initial_max_streams_uni = 0,
      uint64_t initial_max_streams_bidi = 0,
      uint64_t initial_max_data = 0) {
    Initialize(
        WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
        HttpDatagramSupport::kRfc);
    CompleteHandshake();
    ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                           initial_max_streams_uni,
                           initial_max_streams_bidi,
                           initial_max_data);
    return AttemptWebTransportDraft15Session(session_id);
  }

  // Client-perspective composite setup.
  WebTransportHttp3* SetUpWebTransportDraft15ClientSession(
      uint64_t initial_max_streams_uni = 0,
      uint64_t initial_max_streams_bidi = 0,
      uint64_t initial_max_data = 0,
      const std::string& path = "/wt") {
    Initialize(
        WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
        HttpDatagramSupport::kRfc);
    CompleteHandshake();
    ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                           initial_max_streams_uni,
                           initial_max_streams_bidi,
                           initial_max_data);
    return AttemptWebTransportDraft15ClientSession(path);
  }

  // Dispatches a capsule to the WebTransport session associated with the
  // given CONNECT stream. This calls the OnCapsule handler directly,
  // bypassing HTTP/3 frame decoding and CapsuleParser. This is appropriate
  // for unit tests where headers are delivered via OnStreamHeaderList()
  // (not through the HTTP/3 decoder). Real capsule parsing is tested in
  // end-to-end tests that use the full HTTP/3 stack.
  void InjectCapsuleOnConnectStream(QuicStreamId session_id,
                                    const quiche::Capsule& capsule) {
    QuicSpdyStream* stream = static_cast<QuicSpdyStream*>(
        session_->GetOrCreateStream(session_id));
    ASSERT_NE(stream, nullptr);
    stream->OnCapsule(capsule);
  }

  // Injects an incoming bidirectional WT stream: varint(0x41) + varint(session_id).
  void ReceiveWebTransportBidirectionalStream(
      QuicStreamId session_id,
      QuicStreamId stream_id) {
    std::string data;
    // Encode the WT_STREAM signal (0x41) as a proper QUIC varint.
    char type_buf[8];
    QuicDataWriter type_writer(sizeof(type_buf), type_buf);
    ASSERT_TRUE(type_writer.WriteVarInt62(0x41));
    data.append(type_buf, type_writer.length());
    // Encode session_id as varint.
    char varint_buf[8];
    QuicDataWriter varint_writer(sizeof(varint_buf), varint_buf);
    ASSERT_TRUE(varint_writer.WriteVarInt62(session_id));
    data.append(varint_buf, varint_writer.length());
    QuicStreamFrame frame(stream_id, /*fin=*/false, /*offset=*/0, data);
    session_->OnStreamFrame(frame);
  }

  // Client-perspective: delivers response headers on a CONNECT stream and
  // triggers HeadersReceived() on the WebTransport session, mirroring the
  // behavior of QuicSpdyClientStream::OnInitialHeadersComplete().
  void ReceiveWebTransportDraft15Response(
      QuicStreamId stream_id,
      int status_code,
      std::optional<std::string> wt_protocol = std::nullopt) {
    QuicSpdyStream* stream = static_cast<QuicSpdyStream*>(
        session_->GetOrCreateStream(stream_id));
    ASSERT_NE(stream, nullptr);
    // Serialize wt-protocol as a Structured Fields Item (quoted string),
    // matching the wire format that ParseSubprotocolResponseHeader expects.
    std::string serialized_wt_protocol;
    if (wt_protocol.has_value()) {
      auto serialized =
          webtransport::SerializeSubprotocolResponseHeader(*wt_protocol);
      ASSERT_TRUE(serialized.ok()) << serialized.status();
      serialized_wt_protocol = *serialized;
    }
    QuicHeaderList headers;
    headers.OnHeader(":status", std::to_string(status_code));
    if (wt_protocol.has_value()) {
      headers.OnHeader("wt-protocol", serialized_wt_protocol);
    }
    stream->OnStreamHeaderList(/*fin=*/false, 0, headers);
    // TestStream inherits from QuicSpdyStream, not
    // QuicSpdyClientStream. The latter calls
    // web_transport()->HeadersReceived() automatically in
    // OnInitialHeadersComplete(); we must do so explicitly here.
    if (stream->web_transport() != nullptr) {
      quiche::HttpHeaderBlock header_block;
      header_block[":status"] = std::to_string(status_code);
      if (wt_protocol.has_value()) {
        header_block["wt-protocol"] = serialized_wt_protocol;
      }
      stream->web_transport()->HeadersReceived(header_block);
    }
  }

  // Creates and attaches a MockWebTransportSessionVisitor. Returns raw
  // pointer for EXPECT_CALL usage.
  MockWebTransportSessionVisitor* AttachMockVisitor(WebTransportHttp3* wt) {
    auto visitor = std::make_unique<
        testing::NiceMock<MockWebTransportSessionVisitor>>();
    MockWebTransportSessionVisitor* raw = visitor.get();
    wt->SetVisitor(std::move(visitor));
    return raw;
  }
};

}  // namespace test
}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_DRAFT15_TEST_UTILS_H_
