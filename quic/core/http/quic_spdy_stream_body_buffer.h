// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_STREAM_BODY_BUFFER_H_
#define QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_STREAM_BODY_BUFFER_H_

#include <functional>
#include <list>

#include "net/third_party/quiche/src/quic/core/http/http_decoder.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_iovec.h"

namespace quic {

class QuicStreamSequencer;

// Keep references to decoded body (DATA frame payload) fragments, and manage
// calling QuicStreamSequencer::MarkConsumed() for all data received on the
// stream.
class QUIC_EXPORT_PRIVATE QuicSpdyStreamBodyBuffer {
 private:
  using ConsumeFunction = std::function<void(size_t)>;

  // Class that calls QuicStreamSequencer::MarkConsumed() appropriately as DATA
  // frame payload is consumed by higher layers.
  class QUIC_EXPORT_PRIVATE QuicSpdyStreamConsumeManager {
   public:
    explicit QuicSpdyStreamConsumeManager(ConsumeFunction consume_function);
    ~QuicSpdyStreamConsumeManager() = default;

    // Called when data that could immediately be marked consumed with the
    // sequencer (provided that all previous DATA frame payloads are consumed)
    // is received.
    void OnConsumableBytes(QuicByteCount length);

    // Called when DATA frame payload is received.  This cannot be marked
    // consumed with the sequencer until higher layers consume it and
    // ConsumeData() is called.  |length| must be positive.
    void OnDataPayload(QuicByteCount length);

    // Called when some amount of DATA frame payload is consumed by higher
    // layers. |length| bytes of DATA payload as well as all interleaving and
    // immediately following consumable data are marked consumed with the
    // sequencer.  Must not be called with larger |length| than total currently
    // unconsumed DATA payload.
    void ConsumeData(QuicByteCount length);

   private:
    struct Fragment {
      QuicByteCount length;
      bool consumable;
    };

    // Queue of data fragments.
    // The front of the queue must not be consumable (otherwise it should be
    // immediately consumed).  Fragments must not be empty.
    std::list<Fragment> fragments_;

    ConsumeFunction consume_function_;
  };

 public:
  // QuicSpdyStreamBodyBuffer doesn't own the sequencer and the sequencer can
  // outlive the buffer.
  explicit QuicSpdyStreamBodyBuffer(QuicStreamSequencer* sequencer);

  // Used for tests.
  explicit QuicSpdyStreamBodyBuffer(ConsumeFunction consume_function);

  ~QuicSpdyStreamBodyBuffer();

  // One of the following two methods must be called every time data is received
  // on the request stream.

  // Called when data that could immediately be marked consumed with the
  // sequencer (provided that all previous DATA frame payloads are consumed) is
  // received.  |length| must be positive.
  void OnConsumableBytes(QuicByteCount length);

  // Called when DATA frame payload is received.  |payload| is added to the
  // buffer.  The data pointed to by |payload| is kept alive until a
  // MarkBodyConsumed() or ReadBody() call consumes it.  Data must be owned by
  // QuicStreamSequencer.  |payload| must not be empty.
  void OnDataPayload(QuicStringPiece payload);

  // Consume |num_bytes| of DATA frame payload, and an other interleaved or
  // immediately succeeding consumable bytes.
  void MarkBodyConsumed(size_t num_bytes);

  // Fill up to |iov_len| with bodies available in buffer. No data is consumed.
  // |iov|.iov_base will point to data in the buffer, and |iov|.iov_len will
  // be set to the underlying data length accordingly.
  // Returns the number of iov used.
  int PeekBody(iovec* iov, size_t iov_len) const;

  // Copies from buffer into |iov| up to |iov_len|, and calls
  // QuicSpdyStreamConsumeManager::ConsumeData() with number of bytes read.
  // |iov.iov_base| and |iov.iov_len| are preassigned and will not be changed.
  // Returns the number of bytes read.
  size_t ReadBody(const struct iovec* iov, size_t iov_len);

  bool HasBytesToRead() const { return !bodies_.empty(); }

  uint64_t total_body_bytes_received() const {
    return total_body_bytes_received_;
  }

 private:
  // Storage for decoded data.
  QuicDeque<QuicStringPiece> bodies_;
  // Bytes in the first available data frame that are not consumed yet.
  QuicByteCount bytes_remaining_;
  // Total available body data in the stream.
  QuicByteCount total_body_bytes_readable_;
  // Total bytes read from the stream excluding headers.
  QuicByteCount total_body_bytes_received_;
  // Consume manager that talks to the stream sequencer.
  QuicSpdyStreamConsumeManager consume_manager_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_STREAM_BODY_BUFFER_H_
