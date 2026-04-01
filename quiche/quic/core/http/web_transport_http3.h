// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_HTTP3_H_
#define QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_HTTP3_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/attributes.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/web_transport_stream_adapter.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/web_transport_interface.h"
#include "quiche/quic/core/web_transport_stats.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/web_transport.h"

namespace quic {

class QuicSpdySession;
class QuicSpdyStream;

enum class WebTransportHttp3RejectionReason {
  kNone,
  kNoStatusCode,
  kWrongStatusCode,
  kMissingDraftVersion,
  kUnsupportedDraftVersion,
  kSubprotocolNegotiationFailed,
};

// A session of WebTransport over HTTP/3.  The session is owned by
// QuicSpdyStream object for the CONNECT stream that established it.
//
// WebTransport over HTTP/3 specification:
// <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3>
class QUICHE_EXPORT WebTransportHttp3
    : public WebTransportSession,
      public QuicSpdyStream::Http3DatagramVisitor {
 public:
  WebTransportHttp3(QuicSpdySession* session, QuicSpdyStream* connect_stream,
                    WebTransportSessionId id);

  void HeadersReceived(const quiche::HttpHeaderBlock& headers);
  void SetVisitor(std::unique_ptr<WebTransportVisitor> visitor);

  WebTransportSessionId id() { return id_; }
  bool ready() { return ready_; }

  void AssociateStream(QuicStreamId stream_id);
  void OnStreamClosed(QuicStreamId stream_id);
  void OnConnectStreamClosing();

  size_t NumberOfAssociatedStreams() { return streams_.size(); }

  void CloseSession(WebTransportSessionError error_code,
                    absl::string_view error_message) override;
  void OnCloseReceived(WebTransportSessionError error_code,
                       absl::string_view error_message);
  void OnConnectStreamFinReceived();

  // It is legal for WebTransport to be closed without a
  // CLOSE_WEBTRANSPORT_SESSION capsule.  We always send a capsule, but we still
  // need to ensure we handle this case correctly.
  void CloseSessionWithFinOnlyForTests();

  // Return the earliest incoming stream that has been received by the session
  // but has not been accepted.  Returns nullptr if there are no incoming
  // streams.
  WebTransportStream* AcceptIncomingBidirectionalStream() override;
  WebTransportStream* AcceptIncomingUnidirectionalStream() override;

  bool CanOpenNextOutgoingBidirectionalStream() override;
  bool CanOpenNextOutgoingUnidirectionalStream() override;
  WebTransportStream* OpenOutgoingBidirectionalStream() override;
  WebTransportStream* OpenOutgoingUnidirectionalStream() override;

  webtransport::Stream* GetStreamById(webtransport::StreamId id) override;

  webtransport::DatagramStatus SendOrQueueDatagram(
      absl::string_view datagram) override;
  QuicByteCount GetMaxDatagramSize() const override;
  void SetDatagramMaxTimeInQueue(absl::Duration max_time_in_queue) override;

  webtransport::DatagramStats GetDatagramStats() override {
    return WebTransportDatagramStatsForQuicSession(*session_);
  }
  webtransport::SessionStats GetSessionStats() override {
    return WebTransportStatsForQuicSession(*session_);
  }

  void NotifySessionDraining() override;
  void SetOnDraining(quiche::SingleUseCallback<void()> callback) override {
    drain_callback_ = std::move(callback);
  }

  // From QuicSpdyStream::Http3DatagramVisitor.
  void OnHttp3Datagram(QuicStreamId stream_id,
                       absl::string_view payload) override;
  void OnUnknownCapsule(QuicStreamId /*stream_id*/,
                        const quiche::UnknownCapsule& /*capsule*/) override {}

  bool close_received() const { return close_received_; }
  void set_session_counted(bool counted) { session_counted_ = counted; }
  WebTransportHttp3RejectionReason rejection_reason() const {
    return rejection_reason_;
  }

  void OnGoAwayReceived();
  void OnDrainSessionReceived();

  // Session-level stream limits (Section 5.3).
  void OnMaxStreamsCapsuleReceived(webtransport::StreamType stream_type,
                                   uint64_t max_stream_count);
  void SetInitialStreamLimits(uint64_t max_outgoing_bidi,
                              uint64_t max_outgoing_uni,
                              uint64_t max_incoming_bidi,
                              uint64_t max_incoming_uni);
  bool CanOpenNextOutgoingStream(webtransport::StreamType stream_type) const;

  // Session-level data limits (Section 5.4).
  void SetInitialDataLimit(uint64_t max_data_send, uint64_t max_data_receive);
  void OnMaxDataCapsuleReceived(uint64_t max_data);
  bool CanSendData(size_t bytes) const;
  void OnDataSent(size_t bytes);
  void OnIncomingDataReceived(size_t bytes);
  void OnIncomingDataConsumed(size_t bytes);

  void OnIncomingStreamAssociated(QuicStreamId stream_id);
  void MaybeReplenishStreamLimit(webtransport::StreamType type);
  void MaybeSendStreamsBlocked(webtransport::StreamType type);
  void MaybeSendDataBlocked();

  const std::vector<std::string>& subprotocols_offered() const {
    return subprotocols_offered_;
  }
  void set_subprotocols_offered(std::vector<std::string> subprotocols_offered) {
    subprotocols_offered_ = std::move(subprotocols_offered);
  }
  std::optional<std::string> GetNegotiatedSubprotocol() const override {
    return subprotocol_selected_;
  }
  void MaybeSetSubprotocolFromResponseHeaders(
      const quiche::HttpHeaderBlock& headers);

  // Closes the session and notifies the visitor due to a protocol error
  // detected by the WT implementation (as opposed to the application).
  void OnInternalError(WebTransportSessionError error_code,
                       absl::string_view error_message);

 private:
  // Returns true if the session has been closed (either locally or by peer).
  bool IsTerminated() const { return close_sent_ || close_received_; }

  // Sets the direct WebTransportHttp3 pointer on a stream's adapter.
  void SetWebTransportSessionOnAdapter(QuicStreamId stream_id);

  // Resets all associated streams with QUIC_STREAM_WEBTRANSPORT_SESSION_GONE
  // and clears the stream set.
  void ResetAssociatedStreams();

  // Decrements the session counter if this session is still counted.
  void MaybeDecrementSessionCount();

  // Notifies the visitor that the connection has been closed.  Ensures that the
  // visitor is only ever called once.
  void MaybeNotifyClose();

  QuicSpdySession* const session_;        // Unowned.
  QuicSpdyStream* const connect_stream_;  // Unowned.
  const WebTransportSessionId id_;
  // |ready_| is set to true when the peer has seen both sets of headers.
  bool ready_ = false;
  std::unique_ptr<WebTransportVisitor> visitor_;
  absl::flat_hash_set<QuicStreamId> streams_;
  quiche::QuicheCircularDeque<QuicStreamId> incoming_bidirectional_streams_;
  quiche::QuicheCircularDeque<QuicStreamId> incoming_unidirectional_streams_;

  bool close_sent_ = false;
  bool close_received_ = false;
  bool close_notified_ = false;
  bool session_counted_ = false;

  // On client side, stores the offered subprotocols.
  std::vector<std::string> subprotocols_offered_;
  // Stores the actually selected subprotocol, both on the client and on the
  // server.
  std::optional<std::string> subprotocol_selected_;

  quiche::SingleUseCallback<void()> drain_callback_ = nullptr;

  // Draft-15 session-level stream limits (Section 5).
  // Cumulative count of outgoing streams opened on this session.
  uint64_t outgoing_bidi_stream_count_ = 0;
  uint64_t outgoing_uni_stream_count_ = 0;
  // Maximum number of outgoing streams allowed by the peer (from SETTINGS
  // initial values and WT_MAX_STREAMS capsules). 0 means unlimited when
  // WT FC is not negotiated.
  uint64_t max_outgoing_bidi_streams_ = 0;
  uint64_t max_outgoing_uni_streams_ = 0;
  // Whether WT-level stream/data limits are active for this session.
  bool wt_stream_limits_enabled_ = false;
  // Tracks whether BLOCKED capsules have been sent at the current limit,
  // to avoid redundant sends. Reset when the limit is raised.
  bool bidi_streams_blocked_sent_ = false;
  bool uni_streams_blocked_sent_ = false;
  bool data_blocked_sent_ = false;

  // Draft-15 session-level data limits (Section 5.4).
  uint64_t total_data_sent_ = 0;
  uint64_t max_data_send_ = 0;       // Peer's WT_MAX_DATA for data we send
  uint64_t total_data_received_ = 0;
  uint64_t total_data_consumed_ = 0; // Bytes consumed by the application
  uint64_t max_data_receive_ = 0;    // Our WT_MAX_DATA for data we receive
  uint64_t initial_max_data_receive_ = 0;  // Initial window size for threshold
  bool wt_data_limits_enabled_ = false;

  // Incoming stream count tracking for enforcement.
  uint64_t incoming_bidi_stream_count_ = 0;
  uint64_t incoming_uni_stream_count_ = 0;
  // Max incoming streams (from our SETTINGS, not peer's).
  uint64_t max_incoming_bidi_streams_ = 0;
  uint64_t max_incoming_uni_streams_ = 0;
  uint64_t initial_max_incoming_bidi_streams_ = 0;
  uint64_t initial_max_incoming_uni_streams_ = 0;

  WebTransportHttp3RejectionReason rejection_reason_ =
      WebTransportHttp3RejectionReason::kNone;
  bool drain_sent_ = false;
  // Those are set to default values, which are used if the session is not
  // closed cleanly using an appropriate capsule.
  WebTransportSessionError error_code_ = 0;
  std::string error_message_ = "";
};

class QUICHE_EXPORT WebTransportHttp3UnidirectionalStream : public QuicStream {
 public:
  // Incoming stream.
  WebTransportHttp3UnidirectionalStream(PendingStream* pending,
                                        QuicSpdySession* session);
  // Outgoing stream.
  WebTransportHttp3UnidirectionalStream(QuicStreamId id,
                                        QuicSpdySession* session,
                                        WebTransportSessionId session_id);

  // Sends the stream type and the session ID on the stream.
  void WritePreamble();

  // Implementation of QuicStream.
  void OnDataAvailable() override;
  void OnCanWriteNewData() override;
  void OnClose() override;
  void OnStreamReset(const QuicRstStreamFrame& frame) override;
  bool OnStopSending(QuicResetStreamError error) override;
  void OnWriteSideInDataRecvdState() override;

  WebTransportStream* interface() { return &adapter_; }
  void SetUnblocked() { sequencer()->SetUnblocked(); }
  void SetWebTransportSession(WebTransportHttp3* session) {
    adapter_.SetWebTransportSession(session);
  }

 private:
  QuicSpdySession* session_;
  WebTransportStreamAdapter adapter_;
  std::optional<WebTransportSessionId> session_id_;
  bool needs_to_send_preamble_;

  bool ReadSessionId();
  // Closes the stream if all of the data has been received.
  void MaybeCloseIncompleteStream();
};

// Remaps HTTP/3 error code into a WebTransport error code.  Returns nullopt if
// the provided code is outside of valid range.
QUICHE_EXPORT std::optional<WebTransportStreamError> Http3ErrorToWebTransport(
    uint64_t http3_error_code);

// Same as above, but returns default error value (zero) when none could be
// mapped.
QUICHE_EXPORT WebTransportStreamError
Http3ErrorToWebTransportOrDefault(uint64_t http3_error_code);

// Remaps WebTransport error code into an HTTP/3 error code.
QUICHE_EXPORT uint64_t
WebTransportErrorToHttp3(WebTransportStreamError webtransport_error_code);

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_HTTP3_H_
