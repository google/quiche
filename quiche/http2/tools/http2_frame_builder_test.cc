// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/tools/http2_frame_builder.h"

#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace test {
namespace {

const char kHighBitSetMsg[] = "High-bit of uint32_t should be clear";

TEST(Http2FrameBuilderTest, Constructors) {
  {
    Http2FrameBuilder fb;
    EXPECT_EQ(0u, fb.size());
  }
  {
    Http2FrameBuilder fb(Http2FrameType::DATA, 0, 123);
    EXPECT_EQ(9u, fb.size());

    const char kData[] = {
        0x00, 0x00, 0x00,        // Payload length: 0 (unset)
        0x00,                    // Frame type: DATA
        0x00,                    // Flags: none
        0x00, 0x00, 0x00, 0x7b,  // Stream ID: 123
    };
    EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
  }
  {
    Http2FrameHeader header;
    header.payload_length = (1 << 24) - 1;
    header.type = Http2FrameType::HEADERS;
    header.flags = Http2FrameFlag::END_HEADERS;
    header.stream_id = StreamIdMask();
    Http2FrameBuilder fb(header);
    EXPECT_EQ(9u, fb.size());

    const char kData[] = {
        0xff, 0xff, 0xff,        // Payload length: 2^24 - 1 (max uint24)
        0x01,                    // Frame type: HEADER
        0x04,                    // Flags: END_HEADERS
        0x7f, 0xff, 0xff, 0xff,  // Stream ID: stream id mask
    };
    EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
  }
}

TEST(Http2FrameBuilderTest, SetPayloadLength) {
  Http2FrameBuilder fb(Http2FrameType::DATA, PADDED, 20000);
  EXPECT_EQ(9u, fb.size());

  fb.AppendUInt8(50);  // Trailing payload length
  EXPECT_EQ(10u, fb.size());

  fb.Append("ten bytes.");
  EXPECT_EQ(20u, fb.size());

  fb.AppendZeroes(50);
  EXPECT_EQ(70u, fb.size());

  fb.SetPayloadLength();
  EXPECT_EQ(70u, fb.size());

  // clang-format off
  const char kData[] = {
      0x00, 0x00, 0x3d,              // Payload length: 61
      0x00,                          // Frame type: DATA
      0x08,                          // Flags: PADDED
      0x00, 0x00, 0x4e, 0x20,        // Stream ID: 20000
      0x32,                          // Padding Length: 50
      't', 'e', 'n', ' ', 'b',       // "ten b"
      'y', 't', 'e', 's', '.',       // "ytes."
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // Padding bytes
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // Padding bytes
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // Padding bytes
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // Padding bytes
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // Padding bytes
  };
  // clang-format on
  EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
}

TEST(Http2FrameBuilderTest, Settings) {
  Http2FrameBuilder fb(Http2FrameType::SETTINGS, 0, 0);
  Http2SettingFields sf;

  sf.parameter = Http2SettingsParameter::HEADER_TABLE_SIZE;
  sf.value = 1 << 12;
  fb.Append(sf);

  sf.parameter = Http2SettingsParameter::ENABLE_PUSH;
  sf.value = 0;
  fb.Append(sf);

  sf.parameter = Http2SettingsParameter::MAX_CONCURRENT_STREAMS;
  sf.value = ~0;
  fb.Append(sf);

  sf.parameter = Http2SettingsParameter::INITIAL_WINDOW_SIZE;
  sf.value = 1 << 16;
  fb.Append(sf);

  sf.parameter = Http2SettingsParameter::MAX_FRAME_SIZE;
  sf.value = 1 << 14;
  fb.Append(sf);

  sf.parameter = Http2SettingsParameter::MAX_HEADER_LIST_SIZE;
  sf.value = 1 << 10;
  fb.Append(sf);

  size_t payload_size = 6 * Http2SettingFields::EncodedSize();
  EXPECT_EQ(Http2FrameHeader::EncodedSize() + payload_size, fb.size());

  fb.SetPayloadLength(payload_size);

  // clang-format off
  const char kData[] = {
      0x00, 0x00, 0x24,        // Payload length: 36
      0x04,                    // Frame type: SETTINGS
      0x00,                    // Flags: none
      0x00, 0x00, 0x00, 0x00,  // Stream ID: 0
      0x00, 0x01,              // HEADER_TABLE_SIZE
      0x00, 0x00, 0x10, 0x00,  // 4096
      0x00, 0x02,              // ENABLE_PUSH
      0x00, 0x00, 0x00, 0x00,  // 0
      0x00, 0x03,              // MAX_CONCURRENT_STREAMS
      0xff, 0xff, 0xff, 0xff,  // 0xffffffff (max uint32)
      0x00, 0x04,              // INITIAL_WINDOW_SIZE
      0x00, 0x01, 0x00, 0x00,  // 4096
      0x00, 0x05,              // MAX_FRAME_SIZE
      0x00, 0x00, 0x40, 0x00,  // 4096
      0x00, 0x06,              // MAX_HEADER_LIST_SIZE
      0x00, 0x00, 0x04, 0x00,  // 1024
  };
  // clang-format on
  EXPECT_EQ(absl::string_view(kData, 9), fb.buffer().substr(0, 9));
  for (int n = 0; n < 6; ++n) {
    int offset = 9 + n * 6;
    EXPECT_EQ(absl::string_view(kData + offset, 6),
              fb.buffer().substr(offset, 6))
        << "Setting #" << n;
  }
  EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
}

TEST(Http2FrameBuilderTest, EnhanceYourCalm) {
  const char kData[] = {0x00, 0x00, 0x00, 0x0b};
  const absl::string_view expected(kData, sizeof kData);
  {
    Http2FrameBuilder fb;
    fb.Append(Http2ErrorCode::ENHANCE_YOUR_CALM);
    EXPECT_EQ(expected, fb.buffer());
  }
  {
    Http2FrameBuilder fb;
    Http2RstStreamFields rsp;
    rsp.error_code = Http2ErrorCode::ENHANCE_YOUR_CALM;
    fb.Append(rsp);
    EXPECT_EQ(expected, fb.buffer());
  }
}

TEST(Http2FrameBuilderTest, PushPromise) {
  const char kData[] = {0x7f, 0xff, 0xff, 0xff};
  {
    Http2FrameBuilder fb;
    fb.Append(Http2PushPromiseFields{0x7fffffff});
    EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
  }
  {
    Http2FrameBuilder fb;
    // Will generate an error if the high-bit of the stream id is set.
    EXPECT_NONFATAL_FAILURE(fb.Append(Http2PushPromiseFields{0xffffffff}),
                            kHighBitSetMsg);
    EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
  }
}

TEST(Http2FrameBuilderTest, Ping) {
  Http2FrameBuilder fb;
  Http2PingFields ping{"8 bytes"};
  fb.Append(ping);

  const char kData[] = {'8', ' ', 'b', 'y', 't', 'e', 's', '\0'};
  EXPECT_EQ(sizeof kData, Http2PingFields::EncodedSize());
  EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
}

TEST(Http2FrameBuilderTest, GoAway) {
  const char kData[] = {
      0x12, 0x34, 0x56, 0x78,  // Last Stream Id
      0x00, 0x00, 0x00, 0x01,  // Error code
  };
  EXPECT_EQ(sizeof kData, Http2GoAwayFields::EncodedSize());
  {
    Http2FrameBuilder fb;
    Http2GoAwayFields ga(0x12345678, Http2ErrorCode::PROTOCOL_ERROR);
    fb.Append(ga);
    EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
  }
  {
    Http2FrameBuilder fb;
    // Will generate a test failure if the high-bit of the stream id is set.
    Http2GoAwayFields ga(0x92345678, Http2ErrorCode::PROTOCOL_ERROR);
    EXPECT_NONFATAL_FAILURE(fb.Append(ga), kHighBitSetMsg);
    EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
  }
}

TEST(Http2FrameBuilderTest, WindowUpdate) {
  Http2FrameBuilder fb;
  fb.Append(Http2WindowUpdateFields{123456});

  // Will generate a test failure if the high-bit of the increment is set.
  EXPECT_NONFATAL_FAILURE(fb.Append(Http2WindowUpdateFields{0x80000001}),
                          kHighBitSetMsg);

  // Will generate a test failure if the increment is zero.
  EXPECT_NONFATAL_FAILURE(fb.Append(Http2WindowUpdateFields{0}), "non-zero");

  const char kData[] = {
      0x00, 0x01, 0xe2, 0x40,  // Valid Window Size Increment
      0x00, 0x00, 0x00, 0x01,  // High-bit cleared
      0x00, 0x00, 0x00, 0x00,  // Invalid Window Size Increment
  };
  EXPECT_EQ(sizeof kData, 3 * Http2WindowUpdateFields::EncodedSize());
  EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
}

TEST(Http2FrameBuilderTest, AltSvc) {
  Http2FrameBuilder fb;
  fb.Append(Http2AltSvcFields{99});
  fb.Append(Http2AltSvcFields{0});  // No optional origin
  const char kData[] = {
      0x00, 0x63,  // Has origin.
      0x00, 0x00,  // Doesn't have origin.
  };
  EXPECT_EQ(sizeof kData, 2 * Http2AltSvcFields::EncodedSize());
  EXPECT_EQ(absl::string_view(kData, sizeof kData), fb.buffer());
}

}  // namespace
}  // namespace test
}  // namespace http2
