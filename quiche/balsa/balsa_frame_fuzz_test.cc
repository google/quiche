// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstddef>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "quiche/balsa/balsa_enums.h"
#include "quiche/balsa/balsa_frame.h"
#include "quiche/balsa/balsa_fuzz_util.h"
#include "quiche/balsa/balsa_headers.h"
#include "quiche/balsa/http_validation_policy.h"
#include "quiche/balsa/simple_buffer.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace quiche {
namespace {

struct FuzzParams {
  // This string is the input to `BalsaFrame::ProcessInput()`.
  std::string input_to_parse;
  HttpValidationPolicy http_validation_policy;
  size_t max_header_length = 0;
  bool is_request = false;
  bool request_was_head = false;
  bool allow_arbitrary_body = false;
  bool allow_reading_until_close_for_request = false;
  bool parse_truncated_headers_even_when_headers_too_long = false;

  // Used by fuzztest as the "human-readable printer".
  template <typename Sink>
  friend void AbslStringify(Sink& sink, const FuzzParams& p) {
    absl::Format(&sink,
                 "(\"%s\", http_validation_policy=%v, max_header_length=%v, "
                 "is_request=%v, request_was_head=%v, allow_arbitrary_body=%v,"
                 "allow_reading_until_close_for_request=%v, "
                 "parse_truncated_headers_even_when_headers_too_long=%v)",
                 absl::CHexEscape(p.input_to_parse), p.http_validation_policy,
                 p.max_header_length, p.is_request, p.request_was_head,
                 p.allow_arbitrary_body,
                 p.allow_reading_until_close_for_request,
                 p.parse_truncated_headers_even_when_headers_too_long);
  }
};

void ConfigureBalsaFrame(const FuzzParams& params, BalsaFrame& out) {
  out.set_http_validation_policy(params.http_validation_policy);
  out.set_is_request(params.is_request);
  out.set_request_was_head(params.request_was_head);
  if (params.allow_arbitrary_body) {
    out.AllowArbitraryBody();
  }
  out.set_max_header_length(params.max_header_length);
  out.set_allow_reading_until_close_for_request(
      params.allow_reading_until_close_for_request);
  out.set_parse_truncated_headers_even_when_headers_too_long(
      params.parse_truncated_headers_even_when_headers_too_long);
}

// This property test configures `BalsaFrame` with arbitrary parameters before
// asking it to parse an arbitrary input.
//
// Besides testing for crashes, this test also checks idempotency properties of
// header serialization and parsing.
//
// Graphically:
//
//    Bytes   BalsaFrame   BalsaHeaders   SimpleBuffer
//      │         │             │              │
//      a ──────> b ──────────> c1 ──────────> d1
//      │         │             c2 <───────────┤
//      │         │             ├────────────> d2
//
// The following properties should be true:
//   1. BalsaHeaders c1 and c2 contain the same headers.
//   2. SimpleBuffer d1 and d2 contain the same bytes.
void BalsaFrameParsesArbitraryInput(const FuzzParams& params) {
  QUICHE_DVLOG(1) << "Input to parse: "
                  << absl::CHexEscape(params.input_to_parse);
  BalsaFrame framer;
  ConfigureBalsaFrame(params, /*out=*/framer);
  BalsaHeaders headers;
  framer.set_balsa_headers(&headers);
  const size_t num_bytes_consumed = framer.ProcessInput(
      params.input_to_parse.data(), params.input_to_parse.size());

  const std::string headers_debug_string = headers.DebugString();
  QUICHE_DVLOG(1) << "Parsed headers: " << headers_debug_string;
  EXPECT_LE(num_bytes_consumed, params.input_to_parse.size());

  if (framer.Error() || !framer.MessageFullyRead() || headers.IsEmpty()) {
    return;
  }

  // Serialize `headers` into `simple_buffer`.
  SimpleBuffer simple_buffer;
  size_t expected_write_buffer_size = headers.GetSizeForWriteBuffer();
  headers.WriteHeaderAndEndingToBuffer(&simple_buffer);

  absl::string_view readable_region = simple_buffer.GetReadableRegion();
  EXPECT_EQ(expected_write_buffer_size,
            static_cast<size_t>(simple_buffer.ReadableBytes()));
  QUICHE_DVLOG(1) << "Serialized headers: "
                  << absl::CHexEscape(readable_region);

  // Parse `simple_buffer` into `headers2`.
  framer.Reset();
  ConfigureBalsaFrame(params, /*out=*/framer);
  BalsaHeaders headers2;
  framer.set_balsa_headers(&headers2);
  const size_t num_bytes_consumed2 =
      framer.ProcessInput(readable_region.data(), readable_region.size());
  EXPECT_LE(num_bytes_consumed2,
            static_cast<size_t>(simple_buffer.ReadableBytes()))
      << "Parsing should not consume more bytes than were serialized.";

  // Usually, we should be able to parse our own serialization. One exception to
  // the rule is that serializing a header can make it longer, so we will fail
  // to parse headers that become longer than `params.max_header_length`.
  if (framer.Error()) {
    EXPECT_EQ(framer.ErrorCode(), BalsaFrameEnums::HEADERS_TOO_LONG)
        << "Unexpectedly failed to parse our own serialization. Parse state: "
        << BalsaFrameEnums::ParseStateToString(framer.ParseState())
        << ", error code: "
        << BalsaFrameEnums::ErrorCodeToString(framer.ErrorCode())
        << ", readable_region.size(): " << readable_region.size()
        << ", max_header_length: " << params.max_header_length
        << ", original input: \"" << absl::CHexEscape(params.input_to_parse)
        << "\", serialization: \"" << absl::CHexEscape(readable_region) << "\"";
    return;
  }

  const std::string headers_debug_string2 = headers2.DebugString();
  QUICHE_DVLOG(1) << "Re-parsed headers: " << headers_debug_string2;
  EXPECT_STREQ(headers_debug_string.c_str(), headers_debug_string2.c_str());
  EXPECT_TRUE(framer.MessageFullyRead());

  // Serialize `headers2` into `simple_buffer2`.
  SimpleBuffer simple_buffer2;
  headers2.WriteHeaderAndEndingToBuffer(&simple_buffer2);
  QUICHE_DVLOG(1) << "Re-serialized headers: "
                  << absl::CHexEscape(simple_buffer2.GetReadableRegion());
  EXPECT_EQ(simple_buffer.GetReadableRegion(),
            simple_buffer2.GetReadableRegion());
}

FUZZ_TEST(BalsaFrameTest, BalsaFrameParsesArbitraryInput)
    .WithDomains(fuzztest::StructOf<FuzzParams>(
        fuzztest::Arbitrary<std::string>(), ArbitraryHttpValidationPolicy(),
        // When `max_header_length` is zero, `BalsaBuffer::StartOfFirstBlock()`
        // hits the QUICHE_BUG named `bug_if_1182_1`. TBD whether this is a real
        // bug or whether `max_header_length` should never be zero.
        /*max_header_length=*/fuzztest::NonZero<size_t>(),
        fuzztest::Arbitrary<bool>(), fuzztest::Arbitrary<bool>(),
        fuzztest::Arbitrary<bool>(), fuzztest::Arbitrary<bool>(),
        fuzztest::Arbitrary<bool>()));

// An earlier version of `BalsaFrameParsesArbitraryInput()` believed that the
// number of bytes returned from `frame.ProcessInput()` would be equal to the
// size of the input when `frame.MessageFullyRead()` is true. Now, it only
// checks that the number of bytes is <= the size of the input.
TEST(BalsaFrameTest, RegressionTestFuzzerBugParsingFewerBytesThanSerialized) {
  FuzzParams params;
  params.input_to_parse = "!\n";
  params.max_header_length = 1024;
  params.is_request = true;
  BalsaFrameParsesArbitraryInput(params);
}

// An earlier version of `BalsaFrameParsesArbitraryInput()` believed that any
// serialization we produced was guaranteed to be parseable. However, it's
// possible for serialization to make the header longer than the max header
// length. In this case, "X\n" serializes to "X\r\n\r\n", which exceeds the max
// length of 2.
TEST(BalsaFrameTest, RegressionTestFuzzerBugHeaderTooLong) {
  FuzzParams params;
  params.input_to_parse = "X\n";
  params.max_header_length = 2;
  params.is_request = true;
  BalsaFrameParsesArbitraryInput(params);
}

}  // namespace
}  // namespace quiche
