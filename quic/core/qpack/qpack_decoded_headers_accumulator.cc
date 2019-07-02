// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_decoded_headers_accumulator.h"

#include "net/third_party/quiche/src/quic/core/qpack/qpack_decoder.h"

namespace quic {

QpackDecodedHeadersAccumulator::QpackDecodedHeadersAccumulator(
    QuicStreamId id,
    QpackDecoder* qpack_decoder,
    Visitor* visitor,
    size_t max_header_list_size,
    bool pretend_blocked_decoding_for_tests)
    : decoder_(qpack_decoder->CreateProgressiveDecoder(id, this)),
      visitor_(visitor),
      uncompressed_header_bytes_(0),
      compressed_header_bytes_(0),
      blocked_(false),
      pretend_blocked_decoding_for_tests_(pretend_blocked_decoding_for_tests),
      error_detected_(false) {
  quic_header_list_.set_max_header_list_size(max_header_list_size);
  quic_header_list_.OnHeaderBlockStart();
}

void QpackDecodedHeadersAccumulator::OnHeaderDecoded(QuicStringPiece name,
                                                     QuicStringPiece value) {
  DCHECK(!error_detected_);

  uncompressed_header_bytes_ += name.size() + value.size();
  quic_header_list_.OnHeader(name, value);
}

void QpackDecodedHeadersAccumulator::OnDecodingCompleted() {
  quic_header_list_.OnHeaderBlockEnd(uncompressed_header_bytes_,
                                     compressed_header_bytes_);

  if (blocked_) {
    visitor_->OnHeadersDecoded(quic_header_list_);
  }
}

void QpackDecodedHeadersAccumulator::OnDecodingErrorDetected(
    QuicStringPiece error_message) {
  DCHECK(!error_detected_);

  error_detected_ = true;
  // Copy error message to ensure it remains valid for the lifetime of |this|.
  error_message_.assign(error_message.data(), error_message.size());

  if (blocked_) {
    visitor_->OnHeaderDecodingError();
  }
}

bool QpackDecodedHeadersAccumulator::Decode(QuicStringPiece data) {
  DCHECK(!error_detected_);

  compressed_header_bytes_ += data.size();
  decoder_->Decode(data);

  return !error_detected_;
}

QpackDecodedHeadersAccumulator::Status
QpackDecodedHeadersAccumulator::EndHeaderBlock() {
  DCHECK(!error_detected_);

  decoder_->EndHeaderBlock();

  if (pretend_blocked_decoding_for_tests_) {
    blocked_ = true;
    return Status::kBlocked;
  }

  return error_detected_ ? Status::kError : Status::kSuccess;
}

const QuicHeaderList& QpackDecodedHeadersAccumulator::quic_header_list() const {
  DCHECK(!error_detected_);
  return quic_header_list_;
}

QuicStringPiece QpackDecodedHeadersAccumulator::error_message() const {
  DCHECK(error_detected_);
  return error_message_;
}

}  // namespace quic
