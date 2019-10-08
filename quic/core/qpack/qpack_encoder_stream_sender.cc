// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_encoder_stream_sender.h"

#include <cstddef>
#include <limits>
#include <string>

#include "net/third_party/quiche/src/quic/core/qpack/qpack_constants.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"

namespace quic {

QpackEncoderStreamSender::QpackEncoderStreamSender() : delegate_(nullptr) {}

QuicByteCount QpackEncoderStreamSender::SendInsertWithNameReference(
    bool is_static,
    uint64_t name_index,
    QuicStringPiece value) {
  values_.s_bit = is_static;
  values_.varint = name_index;
  values_.value = value;

  return Encode(InsertWithNameReferenceInstruction());
}

QuicByteCount QpackEncoderStreamSender::SendInsertWithoutNameReference(
    QuicStringPiece name,
    QuicStringPiece value) {
  values_.name = name;
  values_.value = value;

  return Encode(InsertWithoutNameReferenceInstruction());
}

QuicByteCount QpackEncoderStreamSender::SendDuplicate(uint64_t index) {
  values_.varint = index;

  return Encode(DuplicateInstruction());
}

QuicByteCount QpackEncoderStreamSender::SendSetDynamicTableCapacity(
    uint64_t capacity) {
  values_.varint = capacity;

  return Encode(SetDynamicTableCapacityInstruction());
}

void QpackEncoderStreamSender::Flush() {
  if (buffer_.empty()) {
    return;
  }

  delegate_->WriteStreamData(buffer_);
  buffer_.clear();
}

QuicByteCount QpackEncoderStreamSender::Encode(
    const QpackInstruction* instruction) {
  const size_t old_buffer_size = buffer_.size();
  instruction_encoder_.Encode(instruction, values_, &buffer_);
  return buffer_.size() - old_buffer_size;
}

}  // namespace quic
