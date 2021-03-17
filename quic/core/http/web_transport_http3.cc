// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/http/web_transport_http3.h"

#include <memory>

#include "quic/core/http/quic_spdy_session.h"
#include "quic/core/http/quic_spdy_stream.h"
#include "quic/core/quic_utils.h"
#include "common/platform/api/quiche_logging.h"

namespace quic {

namespace {
class QUIC_NO_EXPORT NoopWebTransportVisitor : public WebTransportVisitor {
  void OnSessionReady() override {}
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
}

void WebTransportHttp3::HeadersReceived(
    const spdy::SpdyHeaderBlock& /*headers*/) {
  ready_ = true;
  visitor_->OnSessionReady();
}

WebTransportStream* WebTransportHttp3::AcceptIncomingBidirectionalStream() {
  // TODO(vasilvv): implement this.
  return nullptr;
}
WebTransportStream* WebTransportHttp3::AcceptIncomingUnidirectionalStream() {
  // TODO(vasilvv): implement this.
  return nullptr;
}

bool WebTransportHttp3::CanOpenNextOutgoingBidirectionalStream() {
  // TODO(vasilvv): implement this.
  return false;
}
bool WebTransportHttp3::CanOpenNextOutgoingUnidirectionalStream() {
  // TODO(vasilvv): implement this.
  return false;
}
WebTransportStream* WebTransportHttp3::OpenOutgoingBidirectionalStream() {
  // TODO(vasilvv): implement this.
  return nullptr;
}
WebTransportStream* WebTransportHttp3::OpenOutgoingUnidirectionalStream() {
  // TODO(vasilvv): implement this.
  return nullptr;
}

MessageStatus WebTransportHttp3::SendOrQueueDatagram(
    QuicMemSlice /*datagram*/) {
  // TODO(vasilvv): implement this.
  return MessageStatus::MESSAGE_STATUS_UNSUPPORTED;
}
void WebTransportHttp3::SetDatagramMaxTimeInQueue(
    QuicTime::Delta /*max_time_in_queue*/) {
  // TODO(vasilvv): implement this.
}

}  // namespace quic
