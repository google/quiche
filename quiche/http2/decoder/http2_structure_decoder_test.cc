// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/decoder/http2_structure_decoder.h"

// Tests decoding all of the fixed size HTTP/2 structures (i.e. those defined in
// quiche/http2/core/http2_structures.h) using Http2StructureDecoder, which
// handles buffering of structures split across input buffer boundaries, and in
// turn uses DoDecode when it has all of a structure in a contiguous buffer.
// Tests both pairs of Start and Resume methods (with and without a
// remaining_payload parameter).

#include <stddef.h>

#include <cstdint>
#include <memory>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/http2/core/http2_constants.h"
#include "quiche/http2/core/http2_structures.h"
#include "quiche/http2/decoder/decode_buffer.h"
#include "quiche/http2/decoder/decode_status.h"
#include "quiche/http2/test_tools/http2_frame_builder.h"
#include "quiche/http2/test_tools/http2_structure_decoder_test_util.h"
#include "quiche/http2/test_tools/http2_structures_test_util.h"
#include "quiche/http2/test_tools/random_decoder_test_base.h"
#include "quiche/http2/test_tools/verify_macros.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_text_utils.h"

using ::testing::AssertionSuccess;

namespace http2 {
namespace test {
namespace {
const bool kMayReturnZeroOnFirst = false;

template <class S>
class Http2StructureDecoderTest : public RandomDecoderTest {
 protected:
  typedef S Structure;

  Http2StructureDecoderTest() {
    // IF the test adds more data after the encoded structure, stop as
    // soon as the structure is decoded.
    stop_decode_on_done_ = true;
  }

  DecodeStatus StartDecoding(DecodeBuffer* b) override {
    // Overwrite the current contents of |structure_|, into which we'll
    // decode the buffer, so that we can be confident that we really decoded
    // the structure every time.
    structure_ = std::make_unique<S>();

    // Do the same with the decoder so that we can be sure the decoder
    // is not depending on or affected by the state from the previous
    // decoding calls.
    Http2StructureDecoderPeer::Randomize(&structure_decoder_, RandomPtr());

    if (!use_remaining_payload_) {
      uint32_t old_remaining = b->Remaining();
      if (structure_decoder_.Start(structure_.get(), b)) {
        EXPECT_EQ(old_remaining - S::EncodedSize(), b->Remaining());
        ++fast_decode_count_;
        return DecodeStatus::kDecodeDone;
      } else {
        EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
        EXPECT_EQ(0u, b->Remaining());
        EXPECT_EQ(old_remaining - structure_decoder_.offset(), b->Remaining());
        ++incomplete_start_count_;
        return DecodeStatus::kDecodeInProgress;
      }
    }

    const uint32_t avail = b->Remaining();

    QUICHE_VLOG(2) << "StartDecoding, avail=" << b->Remaining()
                   << "; needed=" << S::EncodedSize();

    remaining_payload_ = remaining_payload_at_start_;
    DecodeStatus status =
        structure_decoder_.Start(structure_.get(), b, &remaining_payload_);

    const uint32_t consumed_payload =
        remaining_payload_at_start_ - remaining_payload_;
    const uint32_t consumed_input = avail - b->Remaining();
    EXPECT_EQ(consumed_payload, consumed_input);

    if (status == DecodeStatus::kDecodeDone) {
      EXPECT_EQ(consumed_payload, S::EncodedSize());
      ++fast_decode_count_;
    } else if (status == DecodeStatus::kDecodeInProgress) {
      EXPECT_LT(avail, S::EncodedSize());
      EXPECT_EQ(0u, b->Remaining());
      EXPECT_EQ(avail, structure_decoder_.offset());
      EXPECT_GT(remaining_payload_, 0u);
      ++incomplete_start_count_;
    } else {
      EXPECT_EQ(status, DecodeStatus::kDecodeError);
      EXPECT_EQ(remaining_payload_, 0u);
      ++error_start_count_;
    }
    return status;
  }

  DecodeStatus ResumeDecoding(DecodeBuffer* b) override {
    const uint32_t old_offset = structure_decoder_.offset();
    EXPECT_LT(old_offset, S::EncodedSize());
    const uint32_t avail = b->Remaining();

    if (!use_remaining_payload_) {
      if (structure_decoder_.Resume(structure_.get(), b)) {
        EXPECT_EQ(S::EncodedSize(), structure_decoder_.offset());
        EXPECT_LE(S::EncodedSize(), old_offset + avail);
        EXPECT_EQ(b->Remaining(), avail - (S::EncodedSize() - old_offset));
        ++slow_decode_count_;
        return DecodeStatus::kDecodeDone;
      } else {
        EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
        EXPECT_EQ(0u, b->Remaining());
        EXPECT_GT(S::EncodedSize(), old_offset + avail);
        ++incomplete_resume_count_;
        return DecodeStatus::kDecodeInProgress;
      }
    }

    const uint32_t needed = S::EncodedSize() - old_offset;

    QUICHE_VLOG(2) << "ResumeDecoding, avail=" << b->Remaining()
                   << "; needed=" << needed;

    const uint32_t old_remaining_payload = remaining_payload_;
    if (structure_decoder_.Resume(structure_.get(), b, &remaining_payload_)) {
      EXPECT_EQ(structure_decoder_.offset(), S::EncodedSize());
      EXPECT_GT(old_remaining_payload, remaining_payload_);
      const uint32_t consumed_payload =
          old_remaining_payload - remaining_payload_;
      const uint32_t consumed_input = avail - b->Remaining();
      EXPECT_EQ(needed, consumed_payload);
      EXPECT_EQ(needed, consumed_input);
      ++slow_decode_count_;
      return DecodeStatus::kDecodeDone;
    } else if (remaining_payload_ == 0) {
      EXPECT_GT(needed, old_remaining_payload);
      ++error_resume_count_;
      return DecodeStatus::kDecodeError;
    } else {
      // There is more payload to come, whether or not it is sufficient to
      // meet the needs of decoding a Structure.
      EXPECT_GE(old_remaining_payload, remaining_payload_);
      EXPECT_EQ(0u, b->Remaining());
      const uint32_t consumed = old_remaining_payload - remaining_payload_;
      const uint32_t copied = structure_decoder_.offset() - old_offset;
      EXPECT_EQ(copied, avail);
      EXPECT_EQ(copied, consumed);
      EXPECT_LT(avail, needed);
      EXPECT_LT(structure_decoder_.offset(), S::EncodedSize());
      ++incomplete_resume_count_;
      return DecodeStatus::kDecodeInProgress;
    }
  }

  AssertionResult DecodeLeadingStructureWithoutRemainingPayload(
      const S* expected, absl::string_view data) {
    use_remaining_payload_ = false;
    HTTP2_VERIFY_LE(S::EncodedSize(), data.size());
    DecodeBuffer original(data);

    // The validator is called after each of the several times that the input
    // DecodeBuffer is decoded, each with a different segmentation of the input.
    // Validate that structure_ matches the expected value, if provided.
    Validator validator;
    if (expected != nullptr) {
      validator = [expected, this](const DecodeBuffer& /*db*/,
                                   DecodeStatus /*status*/) -> AssertionResult {
        HTTP2_VERIFY_EQ(*expected, *structure_);
        return AssertionSuccess();
      };
    }

    // Before that, validate that decoding is done and that we've advanced
    // the cursor the expected amount.
    validator = ValidateDoneAndOffset(S::EncodedSize(), std::move(validator));

    // Decode several times, with several segmentations of the input buffer.
    fast_decode_count_ = 0;
    slow_decode_count_ = 0;
    incomplete_start_count_ = 0;
    incomplete_resume_count_ = 0;
    HTTP2_VERIFY_SUCCESS(DecodeAndValidateSeveralWays(
        &original, kMayReturnZeroOnFirst, validator));
    HTTP2_VERIFY_FALSE(HasFailure());
    HTTP2_VERIFY_EQ(S::EncodedSize(), original.Offset());
    HTTP2_VERIFY_LT(0u, fast_decode_count_);
    HTTP2_VERIFY_LT(0u, slow_decode_count_);
    HTTP2_VERIFY_LT(0u, incomplete_start_count_);

    // If the structure is large enough so that SelectZeroOrOne will have
    // caused Resume to return false, check that occurred.
    if (S::EncodedSize() >= 2) {
      HTTP2_VERIFY_LE(0u, incomplete_resume_count_);
    } else {
      HTTP2_VERIFY_EQ(0u, incomplete_resume_count_);
    }
    if (expected != nullptr) {
      QUICHE_DVLOG(1) << "DecodeLeadingStructure expected: " << *expected;
      QUICHE_DVLOG(1) << "DecodeLeadingStructure   actual: " << *structure_;
      HTTP2_VERIFY_EQ(*expected, *structure_);
    }
    return AssertionSuccess();
  }

  // Fully decodes the structure at the start of data, and confirms it matches
  // *expected (if provided) if initial_remaining_payload is big enough. Note
  // that data is expected to be big enough to include an instance of the
  // Structure, and possibly more than that.
  AssertionResult DecodeLeadingStructureWithRemainingPayload(
      const S* expected, absl::string_view data,
      size_t initial_remaining_payload) {
    QUICHE_VLOG(2) << "DecodeLeadingStructure: " << data.size()
                   << " bytes of data: "
                   << quiche::QuicheTextUtils::HexDump(data)
                   << "\n   initial_remaining_payload="
                   << initial_remaining_payload
                   << "\n   needed=" << S::EncodedSize();
    if (expected != nullptr) {
      QUICHE_VLOG(2) << "DecodeLeadingStructure: expected: " << *expected;
    }

    use_remaining_payload_ = true;
    remaining_payload_at_start_ = initial_remaining_payload;

    HTTP2_VERIFY_LE(S::EncodedSize(), data.size());

    DecodeBuffer original(data.substr(0, initial_remaining_payload));

    // The validator is called after each of the several times that the input
    // DecodeBuffer is decoded, each with a different segmentation of the input.
    // Create an appropriate validator based on whether the payload is big
    // enough or not.

    Validator validator;
    if (initial_remaining_payload >= S::EncodedSize()) {
      // We expect complete decoding.
      NoArgValidator inner_validator = [expected, this]() -> AssertionResult {
        // remaining_payload_at_start_ should have been large enough.
        HTTP2_VERIFY_LE(S::EncodedSize(), remaining_payload_at_start_);

        // remaining_payload_ should have dropped by S::EncodedSize().
        HTTP2_VERIFY_EQ(remaining_payload_ + S::EncodedSize(),
                        remaining_payload_at_start_);

        // Validate that structure_ matches the expected value, if provided.
        if (expected != nullptr) {
          HTTP2_VERIFY_EQ(*expected, *structure_);
        }
        return AssertionSuccess();
      };

      // First validate that decoding is done and that we've advanced the cursor
      // the expected amount (i.e. the size of the encoded structure).
      validator =
          ValidateDoneAndOffset(S::EncodedSize(), std::move(inner_validator));
    } else {
      // Not enough payload left, so decoding should fail.
      HTTP2_VERIFY_LT(initial_remaining_payload, S::EncodedSize());

      validator = [this](const DecodeBuffer& /*db*/,
                         DecodeStatus status) -> AssertionResult {
        HTTP2_VERIFY_EQ(status, DecodeStatus::kDecodeError);
        HTTP2_VERIFY_GT(S::EncodedSize(), remaining_payload_at_start_);
        HTTP2_VERIFY_EQ(0u, remaining_payload_);
        // Should have filled the structure_decoder_'s buffer with all of the
        // available data.
        HTTP2_VERIFY_EQ(remaining_payload_at_start_,
                        structure_decoder_.offset());
        return AssertionSuccess();
      };
    }

    // Decode several times, with several segmentations of the input buffer.
    fast_decode_count_ = 0;
    slow_decode_count_ = 0;
    error_start_count_ = 0;
    error_resume_count_ = 0;
    incomplete_start_count_ = 0;
    incomplete_resume_count_ = 0;

    HTTP2_VERIFY_SUCCESS(DecodeAndValidateSeveralWays(
        &original, kMayReturnZeroOnFirst, validator));
    HTTP2_VERIFY_FALSE(HasFailure());

    // Check that both the fast and slow decode or error paths have been tested,
    // and if successful that the expected structure has been decoded.
    if (initial_remaining_payload >= S::EncodedSize()) {
      // Should have advanced the original DecodeBuffer to the end of the
      // encoded structure.
      HTTP2_VERIFY_EQ(S::EncodedSize(), original.Offset());

      // Should have done both a fast decode, where StartDecoding was passed
      // the entire input, and also a slow decode, where StartDecoding didn't
      // get the whole thing, including an empty buffer.
      HTTP2_VERIFY_LT(0u, fast_decode_count_);
      HTTP2_VERIFY_LT(0u, slow_decode_count_);
      HTTP2_VERIFY_LT(0u, incomplete_start_count_);

      // There should have been no errors during decoding.
      HTTP2_VERIFY_EQ(0u, error_start_count_);
      HTTP2_VERIFY_EQ(0u, error_resume_count_);

      // If the input is at least two bytes long, then at least one segmentation
      // of the input will result in ResumeDecoding being called twice, so we
      // should have counted at least one incomplete resume.
      if (S::EncodedSize() >= 2) {
        HTTP2_VERIFY_LE(0u, incomplete_resume_count_);
      } else {
        HTTP2_VERIFY_EQ(0u, incomplete_resume_count_);
      }

      // Double check that the decoded structure has the expected value.
      if (expected != nullptr) {
        HTTP2_VERIFY_EQ(*expected, *structure_);
      }
    } else {
      // We didn't have enough remaining payload, so we should have buffered
      // all that was available in the decoder, and reached the end of the
      // payload.
      HTTP2_VERIFY_EQ(initial_remaining_payload, structure_decoder_.offset());
      HTTP2_VERIFY_EQ(0u, remaining_payload_);

      // Should not have succeeded in decoding fast or slow.
      HTTP2_VERIFY_EQ(0u, fast_decode_count_);
      HTTP2_VERIFY_EQ(0u, slow_decode_count_);

      // Should have determined there was an error during StartDecoding
      // at least once.
      HTTP2_VERIFY_LT(0u, error_start_count_);

      // If the input is at least one byte long, then at least one segmentation
      // will result in an empty buffer being passed to StartDecoding.
      if (initial_remaining_payload >= 1) {
        HTTP2_VERIFY_LT(0u, incomplete_start_count_);
        HTTP2_VERIFY_LT(0u, error_resume_count_);

        // And if the input is at least 2 bytes long, then at least one
        // segmentation of the input will result in ResumeDecoding being called
        // twice, so we should have counted at least one incomplete resume.
        if (initial_remaining_payload >= 2) {
          HTTP2_VERIFY_LT(0u, incomplete_resume_count_);
        }
      }
    }
    return AssertionSuccess();
  }

  // Fully decodes the Structure at the start of data using both pairs of Start
  // and Resume methods, and confirms it matches *expected (if provided).
  AssertionResult DecodeLeadingStructure(const S* expected,
                                         absl::string_view data) {
    HTTP2_VERIFY_SUCCESS(
        DecodeLeadingStructureWithoutRemainingPayload(expected, data));
    const S decoded_without_remaining_payload = *structure_;
    const S* expected_for_remaining =
        expected != nullptr ? expected : &decoded_without_remaining_payload;

    // Decode with various sizes of remaining payload, from none,
    // to insufficient, to enough, and finally more than enough.
    for (size_t initial_remaining_payload = 0;
         initial_remaining_payload <= S::EncodedSize() + 1;
         ++initial_remaining_payload) {
      HTTP2_VERIFY_SUCCESS(DecodeLeadingStructureWithRemainingPayload(
          expected_for_remaining, data, initial_remaining_payload));
    }
    return AssertionSuccess();
  }

  template <size_t N>
  AssertionResult DecodeLeadingStructure(const char (&data)[N]) {
    return DecodeLeadingStructure(nullptr, absl::string_view(data, N));
  }

  template <size_t N>
  AssertionResult DecodeLeadingStructure(const unsigned char (&data)[N]) {
    return DecodeLeadingStructure(nullptr, ToStringPiece(data));
  }

  // Encode the structure |in_s| into bytes, then decode the bytes
  // and validate that the decoder produced the same field values.
  AssertionResult EncodeThenDecode(const S& in_s) {
    std::string bytes = SerializeStructure(in_s);
    HTTP2_VERIFY_EQ(S::EncodedSize(), bytes.size());
    return DecodeLeadingStructure(&in_s, bytes);
  }

  // Repeatedly fill a structure with random but valid contents, encode it, then
  // decode it, and finally validate that the decoded structure matches the
  // random input. Lather-rinse-and-repeat.
  AssertionResult TestDecodingRandomizedStructures(size_t count) {
    for (size_t i = 0; i < count; ++i) {
      Structure input;
      Randomize(&input, RandomPtr());
      HTTP2_VERIFY_SUCCESS(EncodeThenDecode(input));
    }
    return AssertionSuccess();
  }

  AssertionResult TestDecodingRandomizedStructures() {
    HTTP2_VERIFY_SUCCESS(TestDecodingRandomizedStructures(100));
    return AssertionSuccess();
  }

  uint32_t decode_offset_ = 0;
  std::unique_ptr<S> structure_;
  Http2StructureDecoder structure_decoder_;
  size_t fast_decode_count_ = 0;
  size_t slow_decode_count_ = 0;
  size_t incomplete_start_count_ = 0;
  size_t incomplete_resume_count_ = 0;
  size_t error_start_count_ = 0;
  size_t error_resume_count_ = 0;

 private:
  bool use_remaining_payload_ = false;
  uint32_t remaining_payload_ = 0;
  uint32_t remaining_payload_at_start_ = 0;
};

class Http2FrameHeaderDecoderTest
    : public Http2StructureDecoderTest<Http2FrameHeader> {};

TEST_F(Http2FrameHeaderDecoderTest, DecodesLiteral) {
  {
    // Realistic input.
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x05,        // Payload length: 5
        0x01,                    // Frame type: HEADERS
        0x08,                    // Flags: PADDED
        0x00, 0x00, 0x00, 0x01,  // Stream ID: 1
        0x04,                    // Padding length: 4
        0x00, 0x00, 0x00, 0x00,  // Padding bytes
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(5u, structure_->payload_length);
    EXPECT_EQ(Http2FrameType::HEADERS, structure_->type);
    EXPECT_EQ(Http2FrameFlag::PADDED, structure_->flags);
    EXPECT_EQ(1u, structure_->stream_id);
  }
  {
    // Unlikely input.
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff,        // Payload length: uint24 max
        0xff,                    // Frame type: Unknown
        0xff,                    // Flags: Unknown/All
        0xff, 0xff, 0xff, 0xff,  // Stream ID: uint31 max, plus R-bit
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ((1u << 24) - 1u, structure_->payload_length);
    EXPECT_EQ(static_cast<Http2FrameType>(255), structure_->type);
    EXPECT_EQ(255, structure_->flags);
    EXPECT_EQ(0x7FFFFFFFu, structure_->stream_id);
  }
}

TEST_F(Http2FrameHeaderDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2PriorityFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2PriorityFields> {};

TEST_F(Http2PriorityFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const unsigned char kData[] = {
        0x80, 0x00, 0x00, 0x05,  // Exclusive (yes) and Dependency (5)
        0xff,                    // Weight: 256 (after adding 1)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(5u, structure_->stream_dependency);
    EXPECT_EQ(256u, structure_->weight);
    EXPECT_EQ(true, structure_->is_exclusive);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0x7f, 0xff, 0xff, 0xff,  // Excl. (no) and Dependency (uint31 max)
        0x00,                    // Weight: 1 (after adding 1)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->stream_dependency);
    EXPECT_EQ(1u, structure_->weight);
    EXPECT_FALSE(structure_->is_exclusive);
  }
}

TEST_F(Http2PriorityFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2RstStreamFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2RstStreamFields> {};

TEST_F(Http2RstStreamFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Error: PROTOCOL_ERROR
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_TRUE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(Http2ErrorCode::PROTOCOL_ERROR, structure_->error_code);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff,  // Error: max uint32 (Unknown error code)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_FALSE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_->error_code);
  }
}

TEST_F(Http2RstStreamFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2SettingFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2SettingFields> {};

TEST_F(Http2SettingFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x01,              // Setting: HEADER_TABLE_SIZE
        0x00, 0x00, 0x40, 0x00,  // Value: 16K
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_TRUE(structure_->IsSupportedParameter());
    EXPECT_EQ(Http2SettingsParameter::HEADER_TABLE_SIZE, structure_->parameter);
    EXPECT_EQ(1u << 14, structure_->value);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0x00, 0x00,              // Setting: Unknown (0)
        0xff, 0xff, 0xff, 0xff,  // Value: max uint32
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_FALSE(structure_->IsSupportedParameter());
    EXPECT_EQ(static_cast<Http2SettingsParameter>(0), structure_->parameter);
  }
}

TEST_F(Http2SettingFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2PushPromiseFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2PushPromiseFields> {};

TEST_F(Http2PushPromiseFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const unsigned char kData[] = {
        0x00, 0x01, 0x8a, 0x92,  // Promised Stream ID: 101010
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(101010u, structure_->promised_stream_id);
  }
  {
    // Promised stream id has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const unsigned char kData[] = {
        // Promised Stream ID: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->promised_stream_id);
  }
}

TEST_F(Http2PushPromiseFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2PingFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2PingFields> {};

TEST_F(Http2PingFieldsDecoderTest, DecodesLiteral) {
  {
    // Each byte is different, so can detect if order changed.
    const char kData[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_->opaque_bytes));
  }
  {
    // All zeros, detect problems handling NULs.
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_->opaque_bytes));
  }
  {
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(ToStringPiece(kData), ToStringPiece(structure_->opaque_bytes));
  }
}

TEST_F(Http2PingFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2GoAwayFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2GoAwayFields> {};

TEST_F(Http2GoAwayFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Last Stream ID: 0
        0x00, 0x00, 0x00, 0x00,  // Error: NO_ERROR (0)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_->last_stream_id);
    EXPECT_TRUE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(Http2ErrorCode::HTTP2_NO_ERROR, structure_->error_code);
  }
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x01,  // Last Stream ID: 1
        0x00, 0x00, 0x00, 0x0d,  // Error: HTTP_1_1_REQUIRED
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(1u, structure_->last_stream_id);
    EXPECT_TRUE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(Http2ErrorCode::HTTP_1_1_REQUIRED, structure_->error_code);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff, 0xff, 0xff,  // Last Stream ID: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,  // Error: max uint32 (Unknown error code)
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->last_stream_id);  // No high-bit.
    EXPECT_FALSE(structure_->IsSupportedErrorCode());
    EXPECT_EQ(static_cast<Http2ErrorCode>(0xffffffff), structure_->error_code);
  }
}

TEST_F(Http2GoAwayFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2WindowUpdateFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2WindowUpdateFields> {};

TEST_F(Http2WindowUpdateFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x01, 0x00, 0x00,  // Window Size Increment: 2 ^ 16
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(1u << 16, structure_->window_size_increment);
  }
  {
    // Increment must be non-zero, but we need to be able to decode the invalid
    // zero to detect it.
    // clang-format off
    const char kData[] = {
        0x00, 0x00, 0x00, 0x00,  // Window Size Increment: 0
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0u, structure_->window_size_increment);
  }
  {
    // Increment has R-bit (reserved for future use) set, which
    // should be cleared by the decoder.
    // clang-format off
    const unsigned char kData[] = {
        // Window Size Increment: max uint31 and R-bit
        0xff, 0xff, 0xff, 0xff,
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(StreamIdMask(), structure_->window_size_increment);
  }
}

TEST_F(Http2WindowUpdateFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

//------------------------------------------------------------------------------

class Http2AltSvcFieldsDecoderTest
    : public Http2StructureDecoderTest<Http2AltSvcFields> {};

TEST_F(Http2AltSvcFieldsDecoderTest, DecodesLiteral) {
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x00,  // Origin Length: 0
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(0, structure_->origin_length);
  }
  {
    // clang-format off
    const char kData[] = {
        0x00, 0x14,  // Origin Length: 20
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(20, structure_->origin_length);
  }
  {
    // clang-format off
    const unsigned char kData[] = {
        0xff, 0xff,  // Origin Length: uint16 max
    };
    // clang-format on
    ASSERT_TRUE(DecodeLeadingStructure(kData));
    EXPECT_EQ(65535, structure_->origin_length);
  }
}

TEST_F(Http2AltSvcFieldsDecoderTest, DecodesRandomized) {
  EXPECT_TRUE(TestDecodingRandomizedStructures());
}

}  // namespace
}  // namespace test
}  // namespace http2
