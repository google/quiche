// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_encoder.h"

#include <utility>

#include "net/third_party/quiche/src/quic/core/qpack/qpack_constants.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_instruction_encoder.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_required_insert_count.h"
#include "net/third_party/quiche/src/quic/core/qpack/value_splitting_header_list.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"

namespace quic {

QpackEncoder::QpackEncoder(
    DecoderStreamErrorDelegate* decoder_stream_error_delegate)
    : decoder_stream_error_delegate_(decoder_stream_error_delegate),
      decoder_stream_receiver_(this),
      maximum_blocked_streams_(0) {
  DCHECK(decoder_stream_error_delegate_);
}

QpackEncoder::~QpackEncoder() {}

QpackEncoder::Instructions QpackEncoder::FirstPassEncode(
    const spdy::SpdyHeaderBlock* header_list) {
  Instructions instructions;
  instructions.reserve(header_list->size());

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

        instructions.push_back({QpackIndexedHeaderFieldInstruction(), {}});
        instructions.back().values.s_bit = is_static;
        instructions.back().values.varint = index;

        break;
      case QpackHeaderTable::MatchType::kName:
        DCHECK(is_static) << "Dynamic table entries not supported yet.";

        instructions.push_back(
            {QpackLiteralHeaderFieldNameReferenceInstruction(), {}});
        instructions.back().values.s_bit = is_static;
        instructions.back().values.varint = index;
        instructions.back().values.value = value;

        break;
      case QpackHeaderTable::MatchType::kNoMatch:
        instructions.push_back({QpackLiteralHeaderFieldInstruction(), {}});
        instructions.back().values.name = name;
        instructions.back().values.value = value;

        break;
    }
  }

  return instructions;
}

std::string QpackEncoder::SecondPassEncode(
    QpackEncoder::Instructions instructions,
    uint64_t required_insert_count) const {
  QpackInstructionEncoder instruction_encoder;
  std::string encoded_headers;

  // Header block prefix.
  QpackInstructionEncoder::Values values;
  values.varint = QpackEncodeRequiredInsertCount(required_insert_count,
                                                 header_table_.max_entries());
  values.varint2 = 0;    // Delta Base.
  values.s_bit = false;  // Delta Base sign.

  instruction_encoder.Encode(QpackPrefixInstruction(), values,
                             &encoded_headers);

  for (const auto& instruction : instructions) {
    instruction_encoder.Encode(instruction.instruction, instruction.values,
                               &encoded_headers);
  }

  return encoded_headers;
}

std::string QpackEncoder::EncodeHeaderList(
    QuicStreamId /* stream_id */,
    const spdy::SpdyHeaderBlock* header_list) {
  // First pass: encode into |instructions|.
  Instructions instructions = FirstPassEncode(header_list);

  // TODO(bnc): Implement dynamic entries and set Required Insert Count
  // accordingly.
  const uint64_t required_insert_count = 0;

  // Second pass.
  return SecondPassEncode(std::move(instructions), required_insert_count);
}

void QpackEncoder::SetMaximumDynamicTableCapacity(
    uint64_t maximum_dynamic_table_capacity) {
  // TODO(b/112770235): Send set dynamic table capacity instruction on encoder
  // stream.
  header_table_.SetMaximumDynamicTableCapacity(maximum_dynamic_table_capacity);
}

void QpackEncoder::SetMaximumBlockedStreams(uint64_t maximum_blocked_streams) {
  maximum_blocked_streams_ = maximum_blocked_streams;
}

void QpackEncoder::OnInsertCountIncrement(uint64_t increment) {
  if (increment == 0) {
    decoder_stream_error_delegate_->OnDecoderStreamError(
        "Invalid increment value 0.");
    return;
  }

  blocking_manager_.OnInsertCountIncrement(increment);

  if (blocking_manager_.known_received_count() >
      header_table_.inserted_entry_count()) {
    decoder_stream_error_delegate_->OnDecoderStreamError(QuicStrCat(
        "Increment value ", increment, " raises known received count to ",
        blocking_manager_.known_received_count(),
        " exceeding inserted entry count ",
        header_table_.inserted_entry_count()));
  }
}

void QpackEncoder::OnHeaderAcknowledgement(QuicStreamId stream_id) {
  if (!blocking_manager_.OnHeaderAcknowledgement(stream_id)) {
    decoder_stream_error_delegate_->OnDecoderStreamError(
        QuicStrCat("Header Acknowledgement received for stream ", stream_id,
                   " with no outstanding header blocks."));
  }
}

void QpackEncoder::OnStreamCancellation(QuicStreamId stream_id) {
  blocking_manager_.OnStreamCancellation(stream_id);
}

void QpackEncoder::OnErrorDetected(QuicStringPiece error_message) {
  decoder_stream_error_delegate_->OnDecoderStreamError(error_message);
}

}  // namespace quic
