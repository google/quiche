// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>

#include "net/third_party/quiche/src/quic/core/qpack/qpack_decoder_test_utils.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_encoder_test_utils.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_utils.h"
#include "net/third_party/quiche/src/quic/core/qpack/value_splitting_header_list.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_fuzzed_data_provider.h"
#include "net/third_party/quiche/src/spdy/core/spdy_header_block.h"

namespace quic {
namespace test {

spdy::SpdyHeaderBlock GenerateHeaderList(QuicFuzzedDataProvider* provider) {
  spdy::SpdyHeaderBlock header_list;
  uint8_t header_count = provider->ConsumeIntegral<uint8_t>();
  for (uint8_t header_index = 0; header_index < header_count; ++header_index) {
    if (provider->remaining_bytes() == 0) {
      // Do not add more headers if there is no more fuzzer data.
      break;
    }

    std::string name;
    std::string value;
    switch (provider->ConsumeIntegral<uint8_t>()) {
      case 0:
        // Static table entry with no header value.
        name = ":authority";
        break;
      case 1:
        // Static table entry with no header value, using non-empty header
        // value.
        name = ":authority";
        value = "www.example.org";
        break;
      case 2:
        // Static table entry with header value, using that header value.
        name = ":accept-encoding";
        value = "gzip, deflate";
        break;
      case 3:
        // Static table entry with header value, using empty header value.
        name = ":accept-encoding";
        break;
      case 4:
        // Static table entry with header value, using different, non-empty
        // header value.
        name = ":accept-encoding";
        value = "brotli";
        break;
      case 5:
        // Header name that has multiple entries in the static table,
        // using header value from one of them.
        name = ":method";
        value = "GET";
        break;
      case 6:
        // Header name that has multiple entries in the static table,
        // using empty header value.
        name = ":method";
        break;
      case 7:
        // Header name that has multiple entries in the static table,
        // using different, non-empty header value.
        name = ":method";
        value = "CONNECT";
        break;
      case 8:
        // Header name not in the static table, empty header value.
        name = "foo";
        value = "";
        break;
      case 9:
        // Header name not in the static table, non-empty fixed header value.
        name = "foo";
        value = "bar";
        break;
      case 10:
        // Header name not in the static table, fuzzed header value.
        name = "foo";
        value = provider->ConsumeRandomLengthString(128);
        break;
      case 11:
        // Another header name not in the static table, empty header value.
        name = "bar";
        value = "";
        break;
      case 12:
        // Another header name not in the static table, non-empty fixed header
        // value.
        name = "bar";
        value = "baz";
        break;
      case 13:
        // Another header name not in the static table, fuzzed header value.
        name = "bar";
        value = provider->ConsumeRandomLengthString(128);
        break;
      default:
        // Fuzzed header name and header value.
        name = provider->ConsumeRandomLengthString(128);
        value = provider->ConsumeRandomLengthString(128);
    }

    header_list.AppendValueOrAddHeader(name, value);
  }

  return header_list;
}

spdy::SpdyHeaderBlock DecodeHeaderBlock(QpackDecoder* decoder,
                                        QuicStreamId stream_id,
                                        const std::string& encoded_header_block,
                                        QuicFuzzedDataProvider* provider) {
  // Process up to 256 bytes at a time.  Such a small size helps test
  // fragmented decoding.
  auto fragment_size_generator =
      std::bind(&QuicFuzzedDataProvider::ConsumeIntegralInRange<uint8_t>,
                provider, 1, std::numeric_limits<uint8_t>::max());

  TestHeadersHandler handler;
  auto progressive_decoder =
      decoder->CreateProgressiveDecoder(stream_id, &handler);
  {
    QuicStringPiece remaining_data = encoded_header_block;
    while (!remaining_data.empty()) {
      size_t fragment_size =
          std::min<size_t>(fragment_size_generator(), remaining_data.size());
      progressive_decoder->Decode(remaining_data.substr(0, fragment_size));
      remaining_data = remaining_data.substr(fragment_size);
    }
  }
  progressive_decoder->EndHeaderBlock();

  // Since header block has been produced by encoding a header list, it must be
  // valid.
  CHECK(handler.decoding_completed());
  CHECK(!handler.decoding_error_detected());

  return handler.ReleaseHeaderList();
}

// Splits |*header_list| header values along '\0' or ';' separators.
spdy::SpdyHeaderBlock SplitHeaderList(
    const spdy::SpdyHeaderBlock& header_list) {
  ValueSplittingHeaderList splitting_header_list(&header_list);
  spdy::SpdyHeaderBlock split_header_list;
  for (const auto& header : splitting_header_list) {
    split_header_list.AppendValueOrAddHeader(header.first, header.second);
  }
  return split_header_list;
}

// This fuzzer exercises QpackEncoder and QpackDecoder.  It should be able to
// cover all possible code paths of QpackEncoder.  However, since the resulting
// header block is always valid and is encoded in a particular way, this fuzzer
// is not expected to cover all code paths of QpackDecoder.  On the other hand,
// encoding then decoding is expected to result in the original header list, and
// this fuzzer checks for that.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  QuicFuzzedDataProvider provider(data, size);

  // Maximum 256 byte dynamic table.  Such a small size helps test draining
  // entries and eviction.
  const uint64_t maximum_dynamic_table_capacity =
      provider.ConsumeIntegral<uint8_t>();
  // Maximum 256 blocked stream.
  const uint64_t maximum_blocked_streams = provider.ConsumeIntegral<uint8_t>();

  // Set up encoder.
  // TODO: crash on decoder stream error
  NoopDecoderStreamErrorDelegate decoder_stream_error_delegate;
  NoopQpackStreamSenderDelegate encoder_stream_sender_delegate;
  QpackEncoder encoder(&decoder_stream_error_delegate);
  encoder.set_qpack_stream_sender_delegate(&encoder_stream_sender_delegate);
  encoder.SetMaximumDynamicTableCapacity(maximum_dynamic_table_capacity);
  encoder.SetMaximumBlockedStreams(maximum_blocked_streams);

  // Set up decoder.
  // TODO: crash on encoder stream error
  NoopEncoderStreamErrorDelegate encoder_stream_error_delegate;
  NoopQpackStreamSenderDelegate decoder_stream_sender_delegate;
  QpackDecoder decoder(maximum_dynamic_table_capacity, maximum_blocked_streams,
                       &encoder_stream_error_delegate);
  decoder.set_qpack_stream_sender_delegate(&decoder_stream_sender_delegate);

  while (provider.remaining_bytes() > 0) {
    const QuicStreamId stream_id = provider.ConsumeIntegral<uint8_t>();

    // Generate header list.
    spdy::SpdyHeaderBlock header_list = GenerateHeaderList(&provider);

    // Encode header list.
    std::string encoded_header_block =
        encoder.EncodeHeaderList(stream_id, &header_list);

    // Decode resulting header block.
    spdy::SpdyHeaderBlock decoded_header_list =
        DecodeHeaderBlock(&decoder, stream_id, encoded_header_block, &provider);

    // Encoder splits |header_list| header values along '\0' or ';' separators.
    // Do the same here so that we get matching results.
    spdy::SpdyHeaderBlock expected_header_list = SplitHeaderList(header_list);

    // Compare resulting header list to original.
    CHECK(expected_header_list == decoded_header_list);
  }

  return 0;
}

}  // namespace test
}  // namespace quic
