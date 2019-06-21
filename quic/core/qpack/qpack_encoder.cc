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
  instruction_encoder.set_varint(0);
  instruction_encoder.set_varint2(0);
  instruction_encoder.set_s_bit(false);

  instruction_encoder.Encode(QpackPrefixInstruction());
  DCHECK(instruction_encoder.HasNext());
  instruction_encoder.Next(std::numeric_limits<size_t>::max(),
                           &encoded_headers);
  DCHECK(!instruction_encoder.HasNext());

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

        instruction_encoder.set_s_bit(is_static);
        instruction_encoder.set_varint(index);

        instruction_encoder.Encode(QpackIndexedHeaderFieldInstruction());

        break;
      case QpackHeaderTable::MatchType::kName:
        DCHECK(is_static) << "Dynamic table entries not supported yet.";

        instruction_encoder.set_s_bit(is_static);
        instruction_encoder.set_varint(index);
        instruction_encoder.set_value(value);

        instruction_encoder.Encode(
            QpackLiteralHeaderFieldNameReferenceInstruction());

        break;
      case QpackHeaderTable::MatchType::kNoMatch:
        instruction_encoder.set_name(name);
        instruction_encoder.set_value(value);

        instruction_encoder.Encode(QpackLiteralHeaderFieldInstruction());

        break;
    }

    DCHECK(instruction_encoder.HasNext());
    instruction_encoder.Next(std::numeric_limits<size_t>::max(),
                             &encoded_headers);
    DCHECK(!instruction_encoder.HasNext());
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
