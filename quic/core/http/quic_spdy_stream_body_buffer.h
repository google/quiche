// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_STREAM_BODY_BUFFER_H_
#define QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_STREAM_BODY_BUFFER_H_

#include "net/third_party/quiche/src/quic/core/quic_constants.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_containers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_iovec.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_macros.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"

namespace quic {

// "Body" means DATA frame payload.
// QuicSpdyStreamBodyBuffer does two things: it keeps references to body
// fragments (owned by QuicStreamSequencer) and offers methods to read them; and
// calculates the total number of bytes (including DATA frame headers) the
// caller needs to mark consumed (with QuicStreamSequencer) whenever DATA frame
// headers are received or body bytes are read.
// TODO(bnc): Rename to QuicSpdyStreamBodyManager or similar.
class QUIC_EXPORT_PRIVATE QuicSpdyStreamBodyBuffer {
 public:
  QuicSpdyStreamBodyBuffer();
  ~QuicSpdyStreamBodyBuffer() = default;

  // Called when DATA frame header bytes are received.  |length| must be
  // positive.  Returns number of bytes the caller shall mark consumed, which
  // might be zero.
  QUIC_MUST_USE_RESULT size_t OnDataHeader(QuicByteCount length);

  // Called when DATA frame payload is received.  |payload| is added to
  // |fragments_|.  The data pointed to by |payload| must be kept alive until an
  // OnBodyConsumed() or ReadBody() call consumes it.  |payload| must not be
  // empty.
  void OnDataPayload(QuicStringPiece payload);

  // Internally marks |num_bytes| of DATA frame payload consumed.  |num_bytes|
  // might be zero.  Returns the number of bytes that the caller should mark
  // consumed with the sequencer, which is the sum of |num_bytes| for payload
  // and additional DATA frame header bytes, if any.
  QUIC_MUST_USE_RESULT size_t OnBodyConsumed(size_t num_bytes);

  // Set up to |iov_len| elements of iov[] to point to available bodies: each
  // iov[i].iov_base will point to a body fragment, and iov[i].iov_len will be
  // set to its length.  No data is copied, no data is consumed.  Returns the
  // number of iov set.
  int PeekBody(iovec* iov, size_t iov_len) const;

  // Copies data from available bodies into at most |iov_len| elements of iov[].
  // Internally consumes copied payload bytes as well as all interleaving and
  // immediately following DATA frame header bytes.  |iov.iov_base| and
  // |iov.iov_len| are preassigned and will not be changed.  Returns the total
  // number of bytes the caller shall mark consumed.  Sets
  // |*total_bytes_read| to the total number of DATA payload bytes read.
  QUIC_MUST_USE_RESULT size_t ReadBody(const struct iovec* iov,
                                       size_t iov_len,
                                       size_t* total_bytes_read);

  bool HasBytesToRead() const { return !fragments_.empty(); }

  uint64_t total_body_bytes_received() const {
    return total_body_bytes_received_;
  }

 private:
  // A Fragment instance represents a body fragment with a count of bytes
  // received afterwards but before the next body fragment that can be marked
  // consumed as soon as all of the body fragment is read.
  struct Fragment {
    // |body| must not be empty.
    QuicStringPiece body;
    // Might be zero.
    QuicByteCount trailing_consumable_bytes;
  };
  // Queue of DATA frame payload fragments and byte counts.
  QuicDeque<Fragment> fragments_;
  // Total body bytes received.
  QuicByteCount total_body_bytes_received_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_QUIC_SPDY_STREAM_BODY_BUFFER_H_
