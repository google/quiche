// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_encoder.h"

#include <string>

#include "net/third_party/quiche/src/quic/core/qpack/qpack_constants.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_instruction_encoder.h"
#include "net/third_party/quiche/src/quic/core/qpack/value_splitting_header_list.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"

namespace quic {

QpackEncoder::QpackEncoder(
    DecoderStreamErrorDelegate* decoder_stream_error_delegate,
    QpackStreamSenderDelegate* encoder_stream_sender_delegate)
    : decoder_stream_error_delegate_(decoder_stream_error_delegate),
      decoder_stream_receiver_(this),
      encoder_stream_sender_(encoder_stream_sender_delegate) {
  DCHECK(decoder_stream_error_delegate_);
  DCHECK(encoder_stream_sender_delegate);
}

QpackEncoder::~QpackEncoder() {}

std::string QpackEncoder::EncodeHeaderList(
    QuicStreamId /* stream_id */,
    const spdy::SpdyHeaderBlock* header_list) {
  QpackInstructionEncoder instruction_encoder;
  std::string encoded_headers;

  // TODO(bnc): Implement dynamic entries and set Required Insert Count and
  // Delta Base accordingly.
  QpackInstructionEncoder::Values values;
  values.varint = 0;
  values.varint2 = 0;
  values.s_bit = false;

  instruction_encoder.Encode(QpackPrefixInstruction(), values,
                             &encoded_headers);

  for (const auto& header : ValueSplittingHeaderList(header_list)) {
    QuicStringPiece name = header.first;
    QuicStringPiece value = header.second;

    bool is_static;
    uint64_t index;

    auto match_type =
        header_table_.FindHeaderField(name, value, &is_static, &index);

    switch (match_type) {
      case QpackHeaderTable::MatchType::kNameAndValue:
        DCHECK(is_static) << "Dynamic table entries not supported yet.";

        values.s_bit = is_static;
        values.varint = index;

        instruction_encoder.Encode(QpackIndexedHeaderFieldInstruction(), values,
                                   &encoded_headers);

        break;
      case QpackHeaderTable::MatchType::kName:
        DCHECK(is_static) << "Dynamic table entries not supported yet.";

        values.s_bit = is_static;
        values.varint = index;
        values.value = value;

        instruction_encoder.Encode(
            QpackLiteralHeaderFieldNameReferenceInstruction(), values,
            &encoded_headers);

        break;
      case QpackHeaderTable::MatchType::kNoMatch:
        values.name = name;
        values.value = value;

        instruction_encoder.Encode(QpackLiteralHeaderFieldInstruction(), values,
                                   &encoded_headers);

        break;
    }
  }

  return encoded_headers;
}

void QpackEncoder::DecodeDecoderStreamData(QuicStringPiece data) {
  decoder_stream_receiver_.Decode(data);
}

void QpackEncoder::OnInsertCountIncrement(uint64_t /*increment*/) {
  // TODO(bnc): Implement dynamic table management for encoding.
}

void QpackEncoder::OnHeaderAcknowledgement(QuicStreamId /*stream_id*/) {
  // TODO(bnc): Implement dynamic table management for encoding.
}

void QpackEncoder::OnStreamCancellation(QuicStreamId /*stream_id*/) {
  // TODO(bnc): Implement dynamic table management for encoding.
}

void QpackEncoder::OnErrorDetected(QuicStringPiece error_message) {
  decoder_stream_error_delegate_->OnDecoderStreamError(error_message);
}

}  // namespace quic
