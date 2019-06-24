// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QPACK_QPACK_INSTRUCTION_ENCODER_H_
#define QUICHE_QUIC_CORE_QPACK_QPACK_INSTRUCTION_ENCODER_H_

#include <cstdint>
#include <string>

#include "net/third_party/quiche/src/http2/hpack/varint/hpack_varint_encoder.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_constants.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"

namespace quic {

// Generic instruction encoder class.  Takes a QpackLanguage that describes a
// language, that is, a set of instruction opcodes together with a list of
// fields that follow each instruction.
class QUIC_EXPORT_PRIVATE QpackInstructionEncoder {
 public:
  QpackInstructionEncoder();
  QpackInstructionEncoder(const QpackInstructionEncoder&) = delete;
  QpackInstructionEncoder& operator=(const QpackInstructionEncoder&) = delete;

  // Setters for values to be encoded.
  // |name| and |value| must remain valid until the instruction is encoded.
  void set_s_bit(bool s_bit) { s_bit_ = s_bit; }
  void set_varint(uint64_t varint) { varint_ = varint; }
  void set_varint2(uint64_t varint2) { varint2_ = varint2; }
  void set_name(QuicStringPiece name) { name_ = name; }
  void set_value(QuicStringPiece value) { value_ = value; }

  // Append encoded instruction to |output|.
  void Encode(const QpackInstruction* instruction, std::string* output);

 private:
  enum class State {
    // Write instruction opcode to |byte_|.
    kOpcode,
    // Select state based on type of current field.
    kStartField,
    // Write static bit to |byte_|.
    kSbit,
    // Encode an integer (|varint_| or |varint2_| or string length) with a
    // prefix, using |byte_| for the high bits.
    kVarintEncode,
    // Determine if Huffman encoding should be used for |name_| or |value_|, set
    // up |name_| or |value_| and |huffman_encoded_string_| accordingly, and
    // write the Huffman bit to |byte_|.
    kStartString,
    // Write string.
    kWriteString
  };

  // One method for each state.  Some append encoded bytes to |output|.
  // Some only change internal state.
  void DoOpcode();
  void DoStartField();
  void DoStaticBit();
  void DoVarintEncode(std::string* output);
  void DoStartString();
  void DoWriteString(std::string* output);

  // Storage for field values to be encoded.
  bool s_bit_;
  uint64_t varint_;
  uint64_t varint2_;
  // The caller must keep the string that |name_| and |value_| point to
  // valid until they are encoded.
  QuicStringPiece name_;
  QuicStringPiece value_;

  // Storage for the Huffman encoded string literal to be written if Huffman
  // encoding is used.
  std::string huffman_encoded_string_;

  // If Huffman encoding is used, points to a substring of
  // |huffman_encoded_string_|.
  // Otherwise points to a substring of |name_| or |value_|.
  QuicStringPiece string_to_write_;

  // Storage for a single byte that contains multiple fields, that is, multiple
  // states are writing it.
  uint8_t byte_;

  // Encoding state.
  State state_;

  // Instruction currently being decoded.
  const QpackInstruction* instruction_;

  // Field currently being decoded.
  QpackInstructionFields::const_iterator field_;

  // Decoder instance for decoding integers.
  http2::HpackVarintEncoder varint_encoder_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QPACK_QPACK_INSTRUCTION_ENCODER_H_
