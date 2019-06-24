// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_instruction_encoder.h"

#include <limits>

#include "net/third_party/quiche/src/http2/hpack/huffman/hpack_huffman_encoder.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_utils.h"

namespace quic {

QpackInstructionEncoder::QpackInstructionEncoder()
    : s_bit_(false),
      varint_(0),
      varint2_(0),
      byte_(0),
      state_(State::kOpcode),
      instruction_(nullptr) {}

void QpackInstructionEncoder::Encode(const QpackInstruction* instruction,
                                     std::string* output) {
  DCHECK(instruction);

  state_ = State::kOpcode;
  instruction_ = instruction;
  field_ = instruction_->fields.begin();

  // Field list must not be empty.
  DCHECK(field_ != instruction_->fields.end());

  do {
    switch (state_) {
      case State::kOpcode:
        DoOpcode();
        break;
      case State::kStartField:
        DoStartField();
        break;
      case State::kSbit:
        DoStaticBit();
        break;
      case State::kVarintStart:
        DoVarintStart(output);
        break;
      case State::kVarintResume:
        DoVarintResume(output);
        break;
      case State::kStartString:
        DoStartString();
        break;
      case State::kWriteString:
        DoWriteString(output);
        break;
    }
  } while (field_ != instruction_->fields.end());
}

void QpackInstructionEncoder::DoOpcode() {
  DCHECK_EQ(0u, byte_);

  byte_ = instruction_->opcode.value;

  state_ = State::kStartField;
}

void QpackInstructionEncoder::DoStartField() {
  switch (field_->type) {
    case QpackInstructionFieldType::kSbit:
      state_ = State::kSbit;
      return;
    case QpackInstructionFieldType::kVarint:
    case QpackInstructionFieldType::kVarint2:
      state_ = State::kVarintStart;
      return;
    case QpackInstructionFieldType::kName:
    case QpackInstructionFieldType::kValue:
      state_ = State::kStartString;
      return;
  }
}

void QpackInstructionEncoder::DoStaticBit() {
  DCHECK(field_->type == QpackInstructionFieldType::kSbit);

  if (s_bit_) {
    DCHECK_EQ(0, byte_ & field_->param);

    byte_ |= field_->param;
  }

  ++field_;
  state_ = State::kStartField;
}

void QpackInstructionEncoder::DoVarintStart(std::string* output) {
  DCHECK(field_->type == QpackInstructionFieldType::kVarint ||
         field_->type == QpackInstructionFieldType::kVarint2 ||
         field_->type == QpackInstructionFieldType::kName ||
         field_->type == QpackInstructionFieldType::kValue);
  DCHECK(!varint_encoder_.IsEncodingInProgress());

  uint64_t integer_to_encode;
  switch (field_->type) {
    case QpackInstructionFieldType::kVarint:
      integer_to_encode = varint_;
      break;
    case QpackInstructionFieldType::kVarint2:
      integer_to_encode = varint2_;
      break;
    default:
      integer_to_encode = string_to_write_.size();
      break;
  }

  output->push_back(
      varint_encoder_.StartEncoding(byte_, field_->param, integer_to_encode));
  byte_ = 0;

  if (varint_encoder_.IsEncodingInProgress()) {
    state_ = State::kVarintResume;
    return;
  }

  if (field_->type == QpackInstructionFieldType::kVarint ||
      field_->type == QpackInstructionFieldType::kVarint2) {
    ++field_;
    state_ = State::kStartField;
    return;
  }

  state_ = State::kWriteString;
}

void QpackInstructionEncoder::DoVarintResume(std::string* output) {
  DCHECK(field_->type == QpackInstructionFieldType::kVarint ||
         field_->type == QpackInstructionFieldType::kVarint2 ||
         field_->type == QpackInstructionFieldType::kName ||
         field_->type == QpackInstructionFieldType::kValue);
  DCHECK(varint_encoder_.IsEncodingInProgress());

  varint_encoder_.ResumeEncoding(std::numeric_limits<size_t>::max(), output);
  DCHECK(!varint_encoder_.IsEncodingInProgress());

  if (field_->type == QpackInstructionFieldType::kVarint ||
      field_->type == QpackInstructionFieldType::kVarint2) {
    ++field_;
    state_ = State::kStartField;
    return;
  }

  state_ = State::kWriteString;
}

void QpackInstructionEncoder::DoStartString() {
  DCHECK(field_->type == QpackInstructionFieldType::kName ||
         field_->type == QpackInstructionFieldType::kValue);

  string_to_write_ =
      (field_->type == QpackInstructionFieldType::kName) ? name_ : value_;
  http2::HuffmanEncode(string_to_write_, &huffman_encoded_string_);

  if (huffman_encoded_string_.size() < string_to_write_.size()) {
    DCHECK_EQ(0, byte_ & (1 << field_->param));

    byte_ |= (1 << field_->param);
    string_to_write_ = huffman_encoded_string_;
  }

  state_ = State::kVarintStart;
}

void QpackInstructionEncoder::DoWriteString(std::string* output) {
  DCHECK(field_->type == QpackInstructionFieldType::kName ||
         field_->type == QpackInstructionFieldType::kValue);

  QuicStrAppend(output, string_to_write_);

  ++field_;
  state_ = State::kStartField;
}

}  // namespace quic
