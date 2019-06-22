// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_instruction_encoder.h"

#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"

using ::testing::Values;

namespace quic {
namespace test {
namespace {

class QpackInstructionEncoderTest : public QuicTest {
 protected:
  QpackInstructionEncoderTest() : verified_position_(0) {}
  ~QpackInstructionEncoderTest() override = default;

  // Append encoded |instruction| to |output_|.
  void EncodeInstruction(const QpackInstruction* instruction) {
    encoder_.Encode(instruction, &output_);
  }

  // Compare substring appended to |output_| since last EncodedSegmentMatches()
  // call against hex-encoded argument.
  bool EncodedSegmentMatches(QuicStringPiece hex_encoded_expected_substring) {
    auto recently_encoded = QuicStringPiece(output_).substr(verified_position_);
    auto expected = QuicTextUtils::HexDecode(hex_encoded_expected_substring);
    verified_position_ = output_.size();
    return recently_encoded == expected;
  }

  QpackInstructionEncoder encoder_;

 private:
  std::string output_;
  std::string::size_type verified_position_;
};

TEST_F(QpackInstructionEncoderTest, Varint) {
  const QpackInstruction instruction{QpackInstructionOpcode{0x00, 0x80},
                                     {{QpackInstructionFieldType::kVarint, 7}}};

  encoder_.set_varint(5);
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("05"));

  encoder_.set_varint(127);
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("7f00"));
}

TEST_F(QpackInstructionEncoderTest, SBitAndTwoVarint2) {
  const QpackInstruction instruction{
      QpackInstructionOpcode{0x80, 0xc0},
      {{QpackInstructionFieldType::kSbit, 0x20},
       {QpackInstructionFieldType::kVarint, 5},
       {QpackInstructionFieldType::kVarint2, 8}}};

  encoder_.set_s_bit(true);
  encoder_.set_varint(5);
  encoder_.set_varint2(200);
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("a5c8"));

  encoder_.set_s_bit(false);
  encoder_.set_varint(31);
  encoder_.set_varint2(356);
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("9f00ff65"));
}

TEST_F(QpackInstructionEncoderTest, SBitAndVarintAndValue) {
  const QpackInstruction instruction{QpackInstructionOpcode{0xc0, 0xc0},
                                     {{QpackInstructionFieldType::kSbit, 0x20},
                                      {QpackInstructionFieldType::kVarint, 5},
                                      {QpackInstructionFieldType::kValue, 7}}};

  encoder_.set_s_bit(true);
  encoder_.set_varint(100);
  encoder_.set_value("foo");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("ff458294e7"));

  encoder_.set_s_bit(false);
  encoder_.set_varint(3);
  encoder_.set_value("bar");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("c303626172"));
}

TEST_F(QpackInstructionEncoderTest, Name) {
  const QpackInstruction instruction{QpackInstructionOpcode{0xe0, 0xe0},
                                     {{QpackInstructionFieldType::kName, 4}}};

  encoder_.set_name("");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("e0"));

  encoder_.set_name("foo");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("f294e7"));

  encoder_.set_name("bar");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("e3626172"));
}

TEST_F(QpackInstructionEncoderTest, Value) {
  const QpackInstruction instruction{QpackInstructionOpcode{0xf0, 0xf0},
                                     {{QpackInstructionFieldType::kValue, 3}}};

  encoder_.set_value("");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("f0"));

  encoder_.set_value("foo");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("fa94e7"));

  encoder_.set_value("bar");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("f3626172"));
}

TEST_F(QpackInstructionEncoderTest, SBitAndNameAndValue) {
  const QpackInstruction instruction{QpackInstructionOpcode{0xf0, 0xf0},
                                     {{QpackInstructionFieldType::kSbit, 0x08},
                                      {QpackInstructionFieldType::kName, 2},
                                      {QpackInstructionFieldType::kValue, 7}}};

  encoder_.set_s_bit(false);
  encoder_.set_name("");
  encoder_.set_value("");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("f000"));

  encoder_.set_s_bit(true);
  encoder_.set_name("foo");
  encoder_.set_value("bar");
  EncodeInstruction(&instruction);
  EXPECT_TRUE(EncodedSegmentMatches("fe94e703626172"));
}

}  // namespace
}  // namespace test
}  // namespace quic
