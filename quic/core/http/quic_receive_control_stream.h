// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_QUIC_RECEIVE_CONTROL_STREAM_H_
#define QUICHE_QUIC_CORE_HTTP_QUIC_RECEIVE_CONTROL_STREAM_H_

#include "net/third_party/quiche/src/quic/core/http/http_decoder.h"
#include "net/third_party/quiche/src/quic/core/quic_stream.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"

namespace quic {

class QuicSpdySession;

// 3.2.1 Control Stream.
// The receive control stream is peer initiated and is read only.
class QUIC_EXPORT_PRIVATE QuicReceiveControlStream : public QuicStream {
 public:
  explicit QuicReceiveControlStream(PendingStream* pending);
  QuicReceiveControlStream(const QuicReceiveControlStream&) = delete;
  QuicReceiveControlStream& operator=(const QuicReceiveControlStream&) = delete;
  ~QuicReceiveControlStream() override;

  // Overriding QuicStream::OnStreamReset to make sure control stream is never
  // closed before connection.
  void OnStreamReset(const QuicRstStreamFrame& frame) override;

  // Implementation of QuicStream.
  void OnDataAvailable() override;

  void SetUnblocked() { sequencer()->SetUnblocked(); }

 private:
  class HttpDecoderVisitor;

  // Called from HttpDecoderVisitor.
  bool OnSettingsFrameStart(Http3FrameLengths frame_lengths);
  bool OnSettingsFrame(const SettingsFrame& settings);
  bool OnPriorityFrameStart(Http3FrameLengths frame_lengths);
  // TODO(renjietang): Decode Priority in HTTP/3 style.
  bool OnPriorityFrame(const PriorityFrame& priority);

  // Track the current priority frame length.
  QuicByteCount current_priority_length_;

  // Track the number of settings bytes received.
  size_t received_settings_length_;

  // HttpDecoder and its visitor.
  std::unique_ptr<HttpDecoderVisitor> http_decoder_visitor_;
  HttpDecoder decoder_;

  // Sequencer offset keeping track of how much data HttpDecoder has processed.
  // Initial value is sequencer()->NumBytesConsumed() at time of
  // QuicReceiveControlStream construction: that is the length of the
  // unidirectional stream type at the beginning of the stream.
  QuicStreamOffset sequencer_offset_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_QUIC_RECEIVE_CONTROL_STREAM_H_
