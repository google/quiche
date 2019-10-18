// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_STREAM_H_
#define QUICHE_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_STREAM_H_

#include <cstddef>

#include "net/third_party/quiche/src/quic/core/quic_session.h"
#include "net/third_party/quiche/src/quic/core/quic_stream.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_macros.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/quic_transport/quic_transport_session_interface.h"

namespace quic {

// QuicTransportStream is an extension of QuicStream that provides I/O interface
// that is safe to use in the QuicTransport context.  The interface ensures no
// application data is processed before the client indication is processed.
class QuicTransportStream : public QuicStream {
 public:
  class Visitor {
   public:
    virtual ~Visitor() {}
    virtual void OnCanRead() = 0;
    virtual void OnCanWrite() = 0;
  };

  QuicTransportStream(QuicStreamId id,
                      QuicSession* session,
                      QuicTransportSessionInterface* session_interface);

  // Reads at most |buffer_size| bytes into |buffer| and returns the number of
  // bytes actually read.
  size_t Read(char* buffer, size_t buffer_size);
  // Writes |data| into the stream.  Returns true on success.
  QUIC_MUST_USE_RESULT bool Write(QuicStringPiece data);
  // Sends the FIN on the stream.  Returns true on success.
  QUIC_MUST_USE_RESULT bool SendFin();

  // Indicates whether it is possible to write into stream right now.
  bool CanWrite() const;
  // Indicates the number of bytes that can be read from the stream.
  size_t ReadableBytes() const;

  // QuicSession method implementations.
  void OnDataAvailable() override;
  void OnCanWriteNewData() override;

  void set_visitor(Visitor* visitor) { visitor_ = visitor; }

 protected:
  QuicTransportSessionInterface* session_interface_;
  Visitor* visitor_ = nullptr;
};

}  // namespace quic

#endif  // QUICHE_QUIC_QUIC_TRANSPORT_QUIC_TRANSPORT_STREAM_H_
