// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/web_transport_http3.h"

#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/base/casts.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/common/capsule.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/web_transport/web_transport.h"
#include "quiche/web_transport/web_transport_headers.h"

#define ENDPOINT \
  (session_->perspective() == Perspective::IS_SERVER ? "Server: " : "Client: ")

namespace quic {

namespace {
class NoopWebTransportVisitor : public WebTransportVisitor {
  void OnSessionReady() override {}
  void OnSessionClosed(WebTransportSessionError /*error_code*/,
                       const std::string& /*error_message*/) override {}
  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {}
  void OnDatagramReceived(absl::string_view /*datagram*/) override {}
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}
};
}  // namespace

WebTransportHttp3::WebTransportHttp3(QuicSpdySession* session,
                                     QuicSpdyStream* connect_stream,
                                     WebTransportSessionId id)
    : session_(session),
      connect_stream_(connect_stream),
      id_(id),
      visitor_(std::make_unique<NoopWebTransportVisitor>()) {
  QUICHE_DCHECK(session_->SupportsWebTransport());
  QUICHE_DCHECK(IsValidWebTransportSessionId(id, session_->version()));
  QUICHE_DCHECK_EQ(connect_stream_->id(), id);
  connect_stream_->RegisterHttp3DatagramVisitor(this);
}

void WebTransportHttp3::SetWebTransportSessionOnAdapter(
    QuicStreamId stream_id) {
  QuicStream* stream = session_->GetActiveStream(stream_id);
  if (stream == nullptr) {
    return;
  }
  if (QuicUtils::IsBidirectionalStreamId(stream_id, session_->version())) {
    auto* spdy_stream = static_cast<QuicSpdyStream*>(stream);
    if (spdy_stream->web_transport_stream_adapter() != nullptr) {
      spdy_stream->web_transport_stream_adapter()
          ->SetWebTransportSession(this);
    }
  } else {
    static_cast<WebTransportHttp3UnidirectionalStream*>(stream)
        ->SetWebTransportSession(this);
  }
}

void WebTransportHttp3::AssociateStream(QuicStreamId stream_id) {
  streams_.insert(stream_id);

  // Set direct WT session pointer on the stream's adapter for FC.
  SetWebTransportSessionOnAdapter(stream_id);

  ParsedQuicVersion version = session_->version();
  if (QuicUtils::IsOutgoingStreamId(version, stream_id,
                                    session_->perspective())) {
    return;
  }
  // Section 5.3: Check incoming stream limits.
  OnIncomingStreamAssociated(stream_id);
  if (close_sent_) {
    return;  // Session was closed due to stream limit violation.
  }
  if (QuicUtils::IsBidirectionalStreamId(stream_id, version)) {
    incoming_bidirectional_streams_.push_back(stream_id);
    visitor_->OnIncomingBidirectionalStreamAvailable();
  } else {
    incoming_unidirectional_streams_.push_back(stream_id);
    visitor_->OnIncomingUnidirectionalStreamAvailable();
  }
}

void WebTransportHttp3::MaybeDecrementSessionCount() {
  if (session_counted_) {
    session_counted_ = false;
    session_->OnWebTransportSessionDestroyed();
  }
}

void WebTransportHttp3::OnConnectStreamClosing() {
  ResetAssociatedStreams();
  connect_stream_->UnregisterHttp3DatagramVisitor();

  MaybeDecrementSessionCount();
  MaybeNotifyClose();
}

void WebTransportHttp3::CloseSession(WebTransportSessionError error_code,
                                     absl::string_view error_message) {
  if (close_sent_) {
    QUIC_BUG(WebTransportHttp3 close sent twice)
        << "Calling WebTransportHttp3::CloseSession() more than once is not "
           "allowed.";
    return;
  }
  close_sent_ = true;
  MaybeDecrementSessionCount();

  // There can be a race between us trying to send our close and peer sending
  // one.  If we received a close, however, we cannot send ours since we already
  // closed the stream in response.
  if (close_received_) {
    QUIC_DLOG(INFO) << "Not sending CLOSE_WEBTRANSPORT_SESSION as we've "
                       "already sent one from peer.";
    return;
  }

  error_code_ = error_code;
  // Section 6: "its length MUST NOT exceed 1024 bytes."
  if (error_message.size() > 1024) {
    QUICHE_BUG(webtransport_close_message_too_long)
        << "CloseSession error message exceeds 1024 bytes, truncating";
    error_message_ = std::string(error_message.substr(0, 1024));
  } else {
    error_message_ = std::string(error_message);
  }

  // Section 6: Reset all associated streams upon session termination.
  ResetAssociatedStreams();

  QuicConnection::ScopedPacketFlusher flusher(
      connect_stream_->spdy_session()->connection());
  connect_stream_->WriteCapsule(
      quiche::Capsule::CloseWebTransportSession(error_code, error_message_),
      /*fin=*/true);
  connect_stream_->StopReading();
}

void WebTransportHttp3::OnCloseReceived(WebTransportSessionError error_code,
                                        absl::string_view error_message) {
  if (close_received_) {
    QUIC_BUG(WebTransportHttp3 notified of close received twice)
        << "WebTransportHttp3::OnCloseReceived() may be only called once.";
    return;
  }
  // Section 6: "its length MUST NOT exceed 1024 bytes."
  if (error_message.size() > 1024) {
    OnInternalError(0, "WT_CLOSE_SESSION error message exceeds 1024 bytes");
    return;
  }
  close_received_ = true;
  MaybeDecrementSessionCount();

  // Section 6: Reset all associated streams upon session termination.
  ResetAssociatedStreams();

  // If the peer has sent a close after we sent our own, keep the local error.
  if (close_sent_) {
    QUIC_DLOG(INFO) << "Ignoring received CLOSE_WEBTRANSPORT_SESSION as we've "
                       "already sent our own.";
    return;
  }

  error_code_ = error_code;
  error_message_ = std::string(error_message);
  connect_stream_->WriteOrBufferBody("", /*fin=*/true);
  // Section 6 MUST: "If any additional stream data is received on the CONNECT
  // stream after receiving a WT_CLOSE_SESSION capsule, the stream MUST be
  // reset with code H3_MESSAGE_ERROR."
  connect_stream_->SendStopSending(QuicResetStreamError(
      QUIC_STREAM_CANCELLED,
      static_cast<uint64_t>(QuicHttp3ErrorCode::MESSAGE_ERROR)));
  MaybeNotifyClose();
}

void WebTransportHttp3::OnConnectStreamFinReceived() {
  // If we already received a CLOSE_WEBTRANSPORT_SESSION capsule, we don't need
  // to do anything about receiving a FIN, since we already sent one in
  // response.
  if (close_received_) {
    return;
  }
  close_received_ = true;
  MaybeDecrementSessionCount();

  ResetAssociatedStreams();

  if (close_sent_) {
    QUIC_DLOG(INFO) << "Ignoring received FIN as we've already sent our close.";
    return;
  }

  connect_stream_->WriteOrBufferBody("", /*fin=*/true);
  MaybeNotifyClose();
}

void WebTransportHttp3::CloseSessionWithFinOnlyForTests() {
  QUICHE_DCHECK(!close_sent_);
  close_sent_ = true;
  if (close_received_) {
    return;
  }

  connect_stream_->WriteOrBufferBody("", /*fin=*/true);
}

void WebTransportHttp3::HeadersReceived(
    const quiche::HttpHeaderBlock& headers) {
  if (session_->perspective() == Perspective::IS_CLIENT) {
    int status_code;
    if (!QuicSpdyStream::ParseHeaderStatusCode(headers, &status_code)) {
      QUIC_DVLOG(1) << ENDPOINT
                    << "Received WebTransport headers from server without "
                       "a valid status code, rejecting.";
      rejection_reason_ = WebTransportHttp3RejectionReason::kNoStatusCode;
      return;
    }
    bool valid_status = status_code >= 200 && status_code <= 299;
    if (!valid_status) {
      QUIC_DVLOG(1) << ENDPOINT
                    << "Received WebTransport headers from server with "
                       "status code "
                    << status_code << ", rejecting.";
      rejection_reason_ = WebTransportHttp3RejectionReason::kWrongStatusCode;
      return;
    }
    MaybeSetSubprotocolFromResponseHeaders(headers);

    // Section 3.3: Client MUST close with WT_ALPN_ERROR if it offered
    // subprotocols and the server did not select a valid one.
    if (session_->SupportedWebTransportVersion() ==
            WebTransportHttp3Version::kDraft15 &&
        !subprotocols_offered_.empty() && !subprotocol_selected_.has_value()) {
      rejection_reason_ =
          WebTransportHttp3RejectionReason::kSubprotocolNegotiationFailed;
      OnInternalError(kWtAlpnError, "ALPN negotiation failed");
      return;
    }
  }

  QUIC_DVLOG(1) << ENDPOINT << "WebTransport session " << id_ << " ready.";
  ready_ = true;
  visitor_->OnSessionReady();
  session_->ProcessBufferedWebTransportStreamsForSession(this);
}

WebTransportStream* WebTransportHttp3::AcceptIncomingBidirectionalStream() {
  while (!incoming_bidirectional_streams_.empty()) {
    QuicStreamId id = incoming_bidirectional_streams_.front();
    incoming_bidirectional_streams_.pop_front();
    QuicSpdyStream* stream = session_->GetOrCreateSpdyDataStream(id);
    if (stream == nullptr) {
      // Skip the streams that were reset in between the time they were
      // receieved and the time the client has polled for them.
      continue;
    }
    return stream->web_transport_stream();
  }
  return nullptr;
}

WebTransportStream* WebTransportHttp3::AcceptIncomingUnidirectionalStream() {
  while (!incoming_unidirectional_streams_.empty()) {
    QuicStreamId id = incoming_unidirectional_streams_.front();
    incoming_unidirectional_streams_.pop_front();
    QuicStream* stream = session_->GetActiveStream(id);
    if (stream == nullptr) {
      // Skip the streams that were reset in between the time they were
      // receieved and the time the client has polled for them.
      continue;
    }
    return absl::down_cast<WebTransportHttp3UnidirectionalStream*>(stream)
        ->interface();
  }
  return nullptr;
}

bool WebTransportHttp3::CanOpenNextOutgoingBidirectionalStream() {
  if (IsTerminated()) {
    return false;
  }
  if (!CanOpenNextOutgoingStream(webtransport::StreamType::kBidirectional)) {
    return false;
  }
  return session_->CanOpenOutgoingBidirectionalWebTransportStream(id_);
}
bool WebTransportHttp3::CanOpenNextOutgoingUnidirectionalStream() {
  if (IsTerminated()) {
    return false;
  }
  if (!CanOpenNextOutgoingStream(webtransport::StreamType::kUnidirectional)) {
    return false;
  }
  return session_->CanOpenOutgoingUnidirectionalWebTransportStream(id_);
}
WebTransportStream* WebTransportHttp3::OpenOutgoingBidirectionalStream() {
  // Section 6: After session termination, no new streams may be opened.
  if (IsTerminated()) {
    return nullptr;
  }
  // Section 5.3: Check WT-level stream limit.
  if (!CanOpenNextOutgoingStream(webtransport::StreamType::kBidirectional)) {
    MaybeSendStreamsBlocked(webtransport::StreamType::kBidirectional);
    return nullptr;
  }
  QuicSpdyStream* stream =
      session_->CreateOutgoingBidirectionalWebTransportStream(this);
  if (stream == nullptr) {
    return nullptr;
  }
  ++outgoing_bidi_stream_count_;
  return stream->web_transport_stream();
}

WebTransportStream* WebTransportHttp3::OpenOutgoingUnidirectionalStream() {
  // Section 6: After session termination, no new streams may be opened.
  if (IsTerminated()) {
    return nullptr;
  }
  // Section 5.3: Check WT-level stream limit.
  if (!CanOpenNextOutgoingStream(webtransport::StreamType::kUnidirectional)) {
    MaybeSendStreamsBlocked(webtransport::StreamType::kUnidirectional);
    return nullptr;
  }
  WebTransportHttp3UnidirectionalStream* stream =
      session_->CreateOutgoingUnidirectionalWebTransportStream(this);
  if (stream == nullptr) {
    return nullptr;
  }
  ++outgoing_uni_stream_count_;
  return stream->interface();
}

bool WebTransportHttp3::CanOpenNextOutgoingStream(
    webtransport::StreamType stream_type) const {
  if (!wt_stream_limits_enabled_) {
    return true;
  }
  if (stream_type == webtransport::StreamType::kBidirectional) {
    return outgoing_bidi_stream_count_ < max_outgoing_bidi_streams_;
  }
  return outgoing_uni_stream_count_ < max_outgoing_uni_streams_;
}

void WebTransportHttp3::SetInitialStreamLimits(uint64_t max_outgoing_bidi,
                                                uint64_t max_outgoing_uni,
                                                uint64_t max_incoming_bidi,
                                                uint64_t max_incoming_uni) {
  max_outgoing_bidi_streams_ = max_outgoing_bidi;
  max_outgoing_uni_streams_ = max_outgoing_uni;
  max_incoming_bidi_streams_ = max_incoming_bidi;
  max_incoming_uni_streams_ = max_incoming_uni;
  initial_max_incoming_bidi_streams_ = max_incoming_bidi;
  initial_max_incoming_uni_streams_ = max_incoming_uni;
  wt_stream_limits_enabled_ = true;
}

void WebTransportHttp3::SetInitialDataLimit(uint64_t max_data_send,
                                            uint64_t max_data_receive) {
  max_data_send_ = max_data_send;
  max_data_receive_ = max_data_receive;
  initial_max_data_receive_ = max_data_receive;
  wt_data_limits_enabled_ = true;
}

void WebTransportHttp3::OnMaxDataCapsuleReceived(uint64_t max_data) {
  if (!wt_data_limits_enabled_) {
    return;
  }
  // Section 5.6.4: WT_MAX_DATA must not decrease.
  if (max_data < max_data_send_) {
    OnInternalError(
        kWtFlowControlError,
        "WT_MAX_DATA decreased");
    return;
  }
  if (max_data == max_data_send_) {
    return;
  }
  max_data_send_ = max_data;
  data_blocked_sent_ = false;
  for (QuicStreamId id : streams_) {
    session_->MarkConnectionLevelWriteBlocked(id);
  }
}

bool WebTransportHttp3::CanSendData(size_t bytes) const {
  if (!wt_data_limits_enabled_) {
    return true;
  }
  if (total_data_sent_ > max_data_send_) {
    return false;
  }
  return bytes <= max_data_send_ - total_data_sent_;
}

void WebTransportHttp3::OnDataSent(size_t bytes) {
  total_data_sent_ += bytes;
}

void WebTransportHttp3::OnIncomingDataReceived(size_t bytes) {
  if (!wt_data_limits_enabled_) {
    return;
  }
  total_data_received_ += bytes;
  if (total_data_received_ > max_data_receive_) {
    OnInternalError(
        kWtFlowControlError,
        "Incoming data exceeded WT_MAX_DATA limit");
  }
}

void WebTransportHttp3::OnIncomingDataConsumed(size_t bytes) {
  if (!wt_data_limits_enabled_ || close_sent_) return;
  total_data_consumed_ += bytes;
  if (total_data_consumed_ > max_data_receive_) return;
  // Section 5.6.4: Send WT_MAX_DATA when available window drops below half.
  uint64_t available = max_data_receive_ - total_data_consumed_;
  if (available < initial_max_data_receive_ / 2) {
    constexpr uint64_t kMaxVarint62 = (1ULL << 62) - 1;
    uint64_t new_max = max_data_receive_ + initial_max_data_receive_;
    if (new_max > kMaxVarint62) {
      new_max = kMaxVarint62;
    }
    if (new_max == max_data_receive_) return;
    max_data_receive_ = new_max;
    QuicConnection::ScopedPacketFlusher flusher(
        connect_stream_->spdy_session()->connection());
    connect_stream_->WriteCapsule(
        quiche::Capsule(quiche::WebTransportMaxDataCapsule{max_data_receive_}));
  }
}

void WebTransportHttp3::OnStreamClosed(QuicStreamId stream_id) {
  streams_.erase(stream_id);
  if (!wt_stream_limits_enabled_ || close_sent_) return;
  ParsedQuicVersion version = session_->version();
  if (QuicUtils::IsOutgoingStreamId(version, stream_id,
                                    session_->perspective())) {
    return;
  }
  if (QuicUtils::IsBidirectionalStreamId(stream_id, version)) {
    MaybeReplenishStreamLimit(webtransport::StreamType::kBidirectional);
  } else {
    MaybeReplenishStreamLimit(webtransport::StreamType::kUnidirectional);
  }
}

void WebTransportHttp3::MaybeReplenishStreamLimit(
    webtransport::StreamType type) {
  uint64_t& max_incoming =
      (type == webtransport::StreamType::kBidirectional)
          ? max_incoming_bidi_streams_
          : max_incoming_uni_streams_;
  const uint64_t& count =
      (type == webtransport::StreamType::kBidirectional)
          ? incoming_bidi_stream_count_
          : incoming_uni_stream_count_;
  const uint64_t initial =
      (type == webtransport::StreamType::kBidirectional)
          ? initial_max_incoming_bidi_streams_
          : initial_max_incoming_uni_streams_;
  uint64_t available = max_incoming - count;
  // Section 5.6.2: Send WT_MAX_STREAMS when available window drops below half.
  if (available < initial / 2) {
    constexpr uint64_t kMaxStreamsUpperBound = 1ULL << 60;
    uint64_t new_max = max_incoming + initial;
    if (new_max > kMaxStreamsUpperBound) {
      new_max = kMaxStreamsUpperBound;
    }
    if (new_max == max_incoming) return;
    max_incoming = new_max;
    QuicConnection::ScopedPacketFlusher flusher(
        connect_stream_->spdy_session()->connection());
    connect_stream_->WriteCapsule(quiche::Capsule(
        quiche::WebTransportMaxStreamsCapsule{type, max_incoming}));
  }
}

void WebTransportHttp3::MaybeSendStreamsBlocked(
    webtransport::StreamType type) {
  if (!wt_stream_limits_enabled_ || close_sent_) return;
  bool& sent = (type == webtransport::StreamType::kBidirectional)
                   ? bidi_streams_blocked_sent_
                   : uni_streams_blocked_sent_;
  if (sent) return;
  sent = true;
  uint64_t limit = (type == webtransport::StreamType::kBidirectional)
                       ? max_outgoing_bidi_streams_
                       : max_outgoing_uni_streams_;
  QuicConnection::ScopedPacketFlusher flusher(
      connect_stream_->spdy_session()->connection());
  connect_stream_->WriteCapsule(quiche::Capsule(
      quiche::WebTransportStreamsBlockedCapsule{type, limit}));
}

void WebTransportHttp3::MaybeSendDataBlocked() {
  if (!wt_data_limits_enabled_ || close_sent_ || data_blocked_sent_) return;
  data_blocked_sent_ = true;
  QuicConnection::ScopedPacketFlusher flusher(
      connect_stream_->spdy_session()->connection());
  connect_stream_->WriteCapsule(quiche::Capsule(
      quiche::WebTransportDataBlockedCapsule{max_data_send_}));
}

void WebTransportHttp3::OnIncomingStreamAssociated(QuicStreamId stream_id) {
  if (!wt_stream_limits_enabled_) {
    return;
  }
  ParsedQuicVersion version = session_->version();
  if (QuicUtils::IsOutgoingStreamId(version, stream_id,
                                    session_->perspective())) {
    return;
  }
  if (QuicUtils::IsBidirectionalStreamId(stream_id, version)) {
    ++incoming_bidi_stream_count_;
    if (incoming_bidi_stream_count_ > max_incoming_bidi_streams_) {
      OnInternalError(
          kWtFlowControlError,
          "Incoming bidirectional stream count exceeds limit");
    }
  } else {
    ++incoming_uni_stream_count_;
    if (incoming_uni_stream_count_ > max_incoming_uni_streams_) {
      OnInternalError(
          kWtFlowControlError,
          "Incoming unidirectional stream count exceeds limit");
    }
  }
}

void WebTransportHttp3::OnMaxStreamsCapsuleReceived(
    webtransport::StreamType stream_type, uint64_t max_stream_count) {
  if (!wt_stream_limits_enabled_) {
    return;
  }
  // Section 5.6.2: Maximum Streams cannot exceed 2^60.
  constexpr uint64_t kMaxStreamsUpperBound = 1ULL << 60;
  if (max_stream_count > kMaxStreamsUpperBound) {
    QUIC_DLOG(ERROR) << ENDPOINT << "Received WT_MAX_STREAMS with value "
                     << max_stream_count << " exceeding 2^60 limit.";
    session_->connection()->CloseConnection(
        QUIC_HTTP_FRAME_ERROR,
        static_cast<QuicIetfTransportErrorCodes>(kH3DatagramError),
        "WT_MAX_STREAMS value exceeds 2^60",
        ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
    return;
  }
  if (stream_type == webtransport::StreamType::kBidirectional) {
    // Section 5.6.2: WT_MAX_STREAMS must not decrease.
    if (max_stream_count < max_outgoing_bidi_streams_) {
      QUIC_DLOG(ERROR) << ENDPOINT
                       << "Received WT_MAX_STREAMS_BIDI with decreased "
                          "value, closing session.";
      OnInternalError(
          kWtFlowControlError,
          "WT_MAX_STREAMS decreased");
      return;
    }
    if (max_stream_count == max_outgoing_bidi_streams_) {
      return;
    }
    max_outgoing_bidi_streams_ = max_stream_count;
    bidi_streams_blocked_sent_ = false;
    visitor_->OnCanCreateNewOutgoingBidirectionalStream();
  } else {
    if (max_stream_count < max_outgoing_uni_streams_) {
      QUIC_DLOG(ERROR) << ENDPOINT
                       << "Received WT_MAX_STREAMS_UNIDI with decreased "
                          "value, closing session.";
      OnInternalError(
          kWtFlowControlError,
          "WT_MAX_STREAMS decreased");
      return;
    }
    if (max_stream_count == max_outgoing_uni_streams_) {
      return;
    }
    max_outgoing_uni_streams_ = max_stream_count;
    uni_streams_blocked_sent_ = false;
    visitor_->OnCanCreateNewOutgoingUnidirectionalStream();
  }
}

webtransport::Stream* WebTransportHttp3::GetStreamById(
    webtransport::StreamId id) {
  if (!streams_.contains(id)) {
    return nullptr;
  }
  QuicStream* stream = session_->GetActiveStream(id);
  const bool bidi = QuicUtils::IsBidirectionalStreamId(
      id, ParsedQuicVersion::RFCv1());  // Assume IETF QUIC for WebTransport
  if (bidi) {
    return absl::down_cast<QuicSpdyStream*>(stream)->web_transport_stream();
  } else {
    return absl::down_cast<WebTransportHttp3UnidirectionalStream*>(stream)
        ->interface();
  }
}

webtransport::DatagramStatus WebTransportHttp3::SendOrQueueDatagram(
    absl::string_view datagram) {
  if (IsTerminated()) {
    return webtransport::DatagramStatus(
        webtransport::DatagramStatusCode::kInternalError,
        "Session is closed");
  }
  return DatagramStatusToWebTransportStatus(
      connect_stream_->SendHttp3Datagram(datagram));
}

QuicByteCount WebTransportHttp3::GetMaxDatagramSize() const {
  return connect_stream_->GetMaxDatagramSize();
}

void WebTransportHttp3::SetDatagramMaxTimeInQueue(
    absl::Duration max_time_in_queue) {
  connect_stream_->SetMaxDatagramTimeInQueue(QuicTimeDelta(max_time_in_queue));
}

void WebTransportHttp3::NotifySessionDraining() {
  if (!drain_sent_) {
    connect_stream_->WriteCapsule(
        quiche::Capsule(quiche::DrainWebTransportSessionCapsule()));
    drain_sent_ = true;
  }
}

void WebTransportHttp3::SetVisitor(
    std::unique_ptr<WebTransportVisitor> visitor) {
  visitor_ = std::move(visitor);
  // Draft-15 Section 4.6: streams and datagrams that arrive before the
  // session is fully established must be buffered and delivered once the
  // session is ready. So, flush any buffered datagrams now — SetVisitor is the
  // earliest point where both ready_ and a real visitor exist (the noop
  // visitor is still active during HeadersReceived).
  if (ready_) {
    session_->FlushBufferedDatagramsForSession(this);
  }
}

void WebTransportHttp3::OnHttp3Datagram(QuicStreamId stream_id,
                                        absl::string_view payload) {
  QUICHE_DCHECK_EQ(stream_id, connect_stream_->id());
  visitor_->OnDatagramReceived(payload);
}

void WebTransportHttp3::OnInternalError(WebTransportSessionError error_code,
                                        absl::string_view error_message) {
  if (IsTerminated()) {
    return;
  }
  CloseSession(error_code, error_message);
  MaybeNotifyClose();
}

void WebTransportHttp3::ResetAssociatedStreams() {
  // Copy the stream list before iterating over it, as calls below can
  // potentially mutate the |session_| stream map.
  std::vector<QuicStreamId> streams(streams_.begin(), streams_.end());
  streams_.clear();
  for (QuicStreamId id : streams) {
    QuicStream* stream = session_->GetOrCreateStream(id);
    if (stream == nullptr) {
      continue;
    }
    QuicResetStreamError error =
        (session_->SupportedWebTransportVersion() ==
         WebTransportHttp3Version::kDraft15)
            ? QuicResetStreamError(QUIC_STREAM_WEBTRANSPORT_SESSION_GONE,
                                   kWtSessionGone)
            : QuicResetStreamError::FromInternal(
                  QUIC_STREAM_WEBTRANSPORT_SESSION_GONE);
    // Section 4.4: Use RESET_STREAM_AT when available to ensure the peer
    // can associate the stream with the correct session even after reset.
    // Only use RESET_STREAM_AT when data has been written (the stream header
    // counts); without data, there is nothing to reliably deliver.
    if (stream->stream_bytes_written() > 0 && stream->SetReliableSize()) {
      stream->PartialResetWriteSide(error);
    } else {
      stream->ResetWriteSide(error);
    }
    // Section 6: "abort reading on the receive side"
    stream->SendStopSending(error);
  }
}

void WebTransportHttp3::MaybeNotifyClose() {
  if (close_notified_) {
    return;
  }
  close_notified_ = true;
  visitor_->OnSessionClosed(error_code_, error_message_);
}

void WebTransportHttp3::OnGoAwayReceived() {
  if (drain_callback_ != nullptr) {
    std::move(drain_callback_)();
    drain_callback_ = nullptr;
  }
}

void WebTransportHttp3::OnDrainSessionReceived() { OnGoAwayReceived(); }

WebTransportHttp3UnidirectionalStream::WebTransportHttp3UnidirectionalStream(
    PendingStream* pending, QuicSpdySession* session)
    : QuicStream(pending, session, /*is_static=*/false),
      session_(session),
      adapter_(session, this, sequencer(), std::nullopt),
      needs_to_send_preamble_(false) {
  sequencer()->set_level_triggered(true);
}

WebTransportHttp3UnidirectionalStream::WebTransportHttp3UnidirectionalStream(
    QuicStreamId id, QuicSpdySession* session, WebTransportSessionId session_id)
    : QuicStream(id, session, /*is_static=*/false, WRITE_UNIDIRECTIONAL),
      session_(session),
      adapter_(session, this, sequencer(), session_id),
      session_id_(session_id),
      needs_to_send_preamble_(true) {}

void WebTransportHttp3UnidirectionalStream::WritePreamble() {
  if (!needs_to_send_preamble_ || !session_id_.has_value()) {
    QUIC_BUG(WebTransportHttp3UnidirectionalStream duplicate preamble)
        << ENDPOINT << "Sending preamble on stream ID " << id()
        << " at the wrong time.";
    OnUnrecoverableError(QUIC_INTERNAL_ERROR,
                         "Attempting to send a WebTransport unidirectional "
                         "stream preamble at the wrong time.");
    return;
  }

  QuicConnection::ScopedPacketFlusher flusher(session_->connection());
  char buffer[sizeof(uint64_t) * 2];  // varint62, varint62
  QuicDataWriter writer(sizeof(buffer), buffer);
  bool success = true;
  success = success && writer.WriteVarInt62(kWebTransportUnidirectionalStream);
  success = success && writer.WriteVarInt62(*session_id_);
  QUICHE_DCHECK(success);
  WriteOrBufferData(absl::string_view(buffer, writer.length()), /*fin=*/false,
                    /*ack_listener=*/nullptr);
  QUIC_DVLOG(1) << ENDPOINT << "Sent stream type and session ID ("
                << *session_id_ << ") on WebTransport stream " << id();
  needs_to_send_preamble_ = false;
}

bool WebTransportHttp3UnidirectionalStream::ReadSessionId() {
  iovec iov;
  if (!sequencer()->GetReadableRegion(&iov)) {
    return false;
  }
  QuicDataReader reader(static_cast<const char*>(iov.iov_base), iov.iov_len);
  WebTransportSessionId session_id;
  uint8_t session_id_length = reader.PeekVarInt62Length();
  if (!reader.ReadVarInt62(&session_id)) {
    // If all of the data has been received, and we still cannot associate the
    // stream with a session, consume all of the data so that the stream can
    // be closed.
    if (sequencer()->IsAllDataAvailable()) {
      QUIC_DLOG(WARNING)
          << ENDPOINT << "Failed to associate WebTransport stream " << id()
          << " with a session because the stream ended prematurely.";
      sequencer()->MarkConsumed(sequencer()->NumBytesBuffered());
    }
    return false;
  }
  sequencer()->MarkConsumed(session_id_length);
  session_id_ = session_id;
  adapter_.SetSessionId(session_id);
  session_->AssociateIncomingWebTransportStreamWithSession(session_id, id());
  return true;
}

void WebTransportHttp3UnidirectionalStream::OnDataAvailable() {
  if (!session_id_.has_value()) {
    if (!ReadSessionId()) {
      return;
    }
  }

  // The adapter's OnDataAvailable() counts readable bytes against
  // WT_MAX_DATA (Section 5.4), covering both initially-buffered and
  // subsequently-arriving payload data.
  adapter_.OnDataAvailable();
}

void WebTransportHttp3UnidirectionalStream::OnCanWriteNewData() {
  adapter_.OnCanWriteNewData();
}

void WebTransportHttp3UnidirectionalStream::OnClose() {
  QuicStream::OnClose();

  if (!session_id_.has_value()) {
    return;
  }
  WebTransportHttp3* session = session_->GetWebTransportSession(*session_id_);
  if (session == nullptr) {
    QUIC_DLOG(WARNING) << ENDPOINT << "WebTransport stream " << id()
                       << " attempted to notify parent session " << *session_id_
                       << ", but the session could not be found.";
    return;
  }
  adapter_.OnClosingWithUnreadData();
  session->OnStreamClosed(id());
}

void WebTransportHttp3UnidirectionalStream::OnStreamReset(
    const QuicRstStreamFrame& frame) {
  if (adapter_.visitor() != nullptr) {
    adapter_.visitor()->OnResetStreamReceived(
        Http3ErrorToWebTransportOrDefault(frame.ietf_error_code));
  }
  QuicStream::OnStreamReset(frame);
}
bool WebTransportHttp3UnidirectionalStream::OnStopSending(
    QuicResetStreamError error) {
  if (adapter_.visitor() != nullptr) {
    adapter_.visitor()->OnStopSendingReceived(
        Http3ErrorToWebTransportOrDefault(error.ietf_application_code()));
  }
  return QuicStream::OnStopSending(error);
}
void WebTransportHttp3UnidirectionalStream::OnWriteSideInDataRecvdState() {
  if (adapter_.visitor() != nullptr) {
    adapter_.visitor()->OnWriteSideInDataRecvdState();
  }

  QuicStream::OnWriteSideInDataRecvdState();
}

namespace {
constexpr uint64_t kWebTransportMappedErrorCodeFirst = 0x52e4a40fa8db;
constexpr uint64_t kWebTransportMappedErrorCodeLast = 0x52e5ac983162;
constexpr WebTransportStreamError kDefaultWebTransportError = 0;
}  // namespace

std::optional<WebTransportStreamError> Http3ErrorToWebTransport(
    uint64_t http3_error_code) {
  // Ensure the code is within the valid range.
  if (http3_error_code < kWebTransportMappedErrorCodeFirst ||
      http3_error_code > kWebTransportMappedErrorCodeLast) {
    return std::nullopt;
  }
  // Exclude GREASE codepoints.
  if ((http3_error_code - 0x21) % 0x1f == 0) {
    return std::nullopt;
  }

  uint64_t shifted = http3_error_code - kWebTransportMappedErrorCodeFirst;
  uint64_t result = shifted - shifted / 0x1f;
  QUICHE_DCHECK_LE(result,
                   std::numeric_limits<webtransport::StreamErrorCode>::max());
  return static_cast<WebTransportStreamError>(result);
}

WebTransportStreamError Http3ErrorToWebTransportOrDefault(
    uint64_t http3_error_code) {
  std::optional<WebTransportStreamError> result =
      Http3ErrorToWebTransport(http3_error_code);
  return result.has_value() ? *result : kDefaultWebTransportError;
}

uint64_t WebTransportErrorToHttp3(
    WebTransportStreamError webtransport_error_code) {
  return kWebTransportMappedErrorCodeFirst + webtransport_error_code +
         webtransport_error_code / 0x1e;
}

void WebTransportHttp3::MaybeSetSubprotocolFromResponseHeaders(
    const quiche::HttpHeaderBlock& headers) {
  auto subprotocol_it = headers.find(webtransport::kSubprotocolResponseHeader);
  if (subprotocol_it == headers.end()) {
    return;
  }

  absl::StatusOr<std::string> subprotocol =
      webtransport::ParseSubprotocolResponseHeader(subprotocol_it->second);
  if (!subprotocol.ok()) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "WebTransport server has malformed WT-Protocol "
                     "header, ignoring.";
    return;
  }

  if (session_->perspective() == Perspective::IS_CLIENT &&
      !absl::c_linear_search(subprotocols_offered_, *subprotocol)) {
    QUIC_DVLOG(1) << ENDPOINT
                  << "WebTransport server has offered a subprotocol value \""
                  << *subprotocol
                  << "\", which was not one of the ones offered, ignoring.";
    return;
  }

  subprotocol_selected_ = *std::move(subprotocol);
}

}  // namespace quic
