// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QPACK_QPACK_DECODED_HEADERS_ACCUMULATOR_H_
#define QUICHE_QUIC_CORE_QPACK_QPACK_DECODED_HEADERS_ACCUMULATOR_H_

#include <cstddef>
#include <string>

#include "net/third_party/quiche/src/quic/core/http/quic_header_list.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_progressive_decoder.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"

namespace quic {

class QpackDecoder;

// A class that creates and owns a QpackProgressiveDecoder instance, accumulates
// decoded headers in a QuicHeaderList, and keeps track of uncompressed and
// compressed size so that it can be passed to
// QuicHeaderList::OnHeaderBlockEnd().
class QUIC_EXPORT_PRIVATE QpackDecodedHeadersAccumulator
    : public QpackProgressiveDecoder::HeadersHandlerInterface {
 public:
  // Visitor interface to signal success or error.
  // Exactly one method will be called.
  // Methods may be called synchronously from Decode() and EndHeaderBlock(),
  // or asynchronously.
  // Method implementations are allowed to destroy |this|.
  class QUIC_EXPORT_PRIVATE Visitor {
   public:
    virtual ~Visitor() = default;

    // Called when headers are successfully decoded.
    virtual void OnHeadersDecoded(QuicHeaderList headers) = 0;

    // Called when an error has occurred.
    virtual void OnHeaderDecodingError(QuicStringPiece error_message) = 0;
  };

  QpackDecodedHeadersAccumulator(QuicStreamId id,
                                 QpackDecoder* qpack_decoder,
                                 Visitor* visitor,
                                 size_t max_header_list_size);
  virtual ~QpackDecodedHeadersAccumulator() = default;

  // QpackProgressiveDecoder::HeadersHandlerInterface implementation.
  // These methods should only be called by |decoder_|.
  void OnHeaderDecoded(QuicStringPiece name, QuicStringPiece value) override;
  void OnDecodingCompleted() override;
  void OnDecodingErrorDetected(QuicStringPiece error_message) override;

  // Decode payload data.
  // Must not be called if an error has been detected.
  // Must not be called after EndHeaderBlock().
  void Decode(QuicStringPiece data);

  // Signal end of HEADERS frame.
  // Must not be called if an error has been detected.
  // Must not be called more that once.
  void EndHeaderBlock();

 private:
  std::unique_ptr<QpackProgressiveDecoder> decoder_;
  Visitor* visitor_;
  QuicHeaderList quic_header_list_;
  size_t uncompressed_header_bytes_;
  size_t compressed_header_bytes_;
  // True if headers have been completedly and successfully decoded.
  bool headers_decoded_;
  // An error is detected during decoding.
  bool error_detected_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QPACK_QPACK_DECODED_HEADERS_ACCUMULATOR_H_
