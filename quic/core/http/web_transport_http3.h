// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_HTTP3_H_
#define QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_HTTP3_H_

#include <memory>

#include "quic/core/quic_types.h"
#include "quic/core/web_transport_interface.h"
#include "spdy/core/spdy_header_block.h"

namespace quic {

class QuicSpdySession;
class QuicSpdyStream;

// A session of WebTransport over HTTP/3.  The session is owned by
// QuicSpdyStream object for the CONNECT stream that established it.
//
// WebTransport over HTTP/3 specification:
// <https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3>
class QUIC_EXPORT_PRIVATE WebTransportHttp3 : public WebTransportSession {
 public:
  WebTransportHttp3(QuicSpdySession* session,
                    QuicSpdyStream* connect_stream,
                    WebTransportSessionId id);

  void HeadersReceived(const spdy::SpdyHeaderBlock& headers);
  void SetVisitor(std::unique_ptr<WebTransportVisitor> visitor) {
    visitor_ = std::move(visitor);
  }

  WebTransportSessionId id() { return id_; }

  // Return the earliest incoming stream that has been received by the session
  // but has not been accepted.  Returns nullptr if there are no incoming
  // streams.
  WebTransportStream* AcceptIncomingBidirectionalStream() override;
  WebTransportStream* AcceptIncomingUnidirectionalStream() override;

  bool CanOpenNextOutgoingBidirectionalStream() override;
  bool CanOpenNextOutgoingUnidirectionalStream() override;
  WebTransportStream* OpenOutgoingBidirectionalStream() override;
  WebTransportStream* OpenOutgoingUnidirectionalStream() override;

  MessageStatus SendOrQueueDatagram(QuicMemSlice datagram) override;
  void SetDatagramMaxTimeInQueue(QuicTime::Delta max_time_in_queue) override;

 private:
  const QuicSpdySession* session_;        // Unowned.
  const QuicSpdyStream* connect_stream_;  // Unowned.
  const WebTransportSessionId id_;
  // |ready_| is set to true when the peer has seen both sets of headers.
  bool ready_ = false;
  std::unique_ptr<WebTransportVisitor> visitor_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_WEB_TRANSPORT_HTTP3_H_
