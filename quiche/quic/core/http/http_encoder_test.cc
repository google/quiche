// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/http_encoder.h"

#include "absl/base/macros.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic {
namespace test {

TEST(HttpEncoderTest, SerializeDataFrameHeader) {
  quiche::QuicheBuffer buffer = HttpEncoder::SerializeDataFrameHeader(
      /* payload_length = */ 5, quiche::SimpleBufferAllocator::Get());
  char output[] = {0x00,   // type (DATA)
                   0x05};  // length
  EXPECT_EQ(ABSL_ARRAYSIZE(output), buffer.size());
  quiche::test::CompareCharArraysWithHexError(
      "DATA", buffer.data(), buffer.size(), output, ABSL_ARRAYSIZE(output));
}

TEST(HttpEncoderTest, SerializeHeadersFrameHeader) {
  std::unique_ptr<char[]> buffer;
  uint64_t length = HttpEncoder::SerializeHeadersFrameHeader(
      /* payload_length = */ 7, &buffer);
  char output[] = {0x01,   // type (HEADERS)
                   0x07};  // length
  EXPECT_EQ(ABSL_ARRAYSIZE(output), length);
  quiche::test::CompareCharArraysWithHexError("HEADERS", buffer.get(), length,
                                              output, ABSL_ARRAYSIZE(output));
}

TEST(HttpEncoderTest, SerializeSettingsFrame) {
  SettingsFrame settings;
  settings.values[1] = 2;
  settings.values[6] = 5;
  settings.values[256] = 4;
  char output[] = {0x04,  // type (SETTINGS)
                   0x07,  // length
                   0x01,  // identifier (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
                   0x02,  // content
                   0x06,  // identifier (SETTINGS_MAX_HEADER_LIST_SIZE)
                   0x05,  // content
                   0x41, 0x00,  // identifier 0x100, varint encoded
                   0x04};       // content
  std::unique_ptr<char[]> buffer;
  uint64_t length = HttpEncoder::SerializeSettingsFrame(settings, &buffer);
  EXPECT_EQ(ABSL_ARRAYSIZE(output), length);
  quiche::test::CompareCharArraysWithHexError("SETTINGS", buffer.get(), length,
                                              output, ABSL_ARRAYSIZE(output));
}

TEST(HttpEncoderTest, SerializeGoAwayFrame) {
  GoAwayFrame goaway;
  goaway.id = 0x1;
  char output[] = {0x07,   // type (GOAWAY)
                   0x1,    // length
                   0x01};  // ID
  std::unique_ptr<char[]> buffer;
  uint64_t length = HttpEncoder::SerializeGoAwayFrame(goaway, &buffer);
  EXPECT_EQ(ABSL_ARRAYSIZE(output), length);
  quiche::test::CompareCharArraysWithHexError("GOAWAY", buffer.get(), length,
                                              output, ABSL_ARRAYSIZE(output));
}

TEST(HttpEncoderTest, SerializePriorityUpdateFrame) {
  PriorityUpdateFrame priority_update1;
  priority_update1.prioritized_element_type = REQUEST_STREAM;
  priority_update1.prioritized_element_id = 0x03;
  uint8_t output1[] = {0x80, 0x0f, 0x07, 0x00,  // type (PRIORITY_UPDATE)
                       0x01,                    // length
                       0x03};                   // prioritized element id

  std::string frame =
      HttpEncoder::SerializePriorityUpdateFrame(priority_update1);
  quiche::test::CompareCharArraysWithHexError(
      "PRIORITY_UPDATE", frame.data(), frame.length(),
      reinterpret_cast<char*>(output1), ABSL_ARRAYSIZE(output1));
}

TEST(HttpEncoderTest, SerializeAcceptChFrame) {
  AcceptChFrame accept_ch;
  uint8_t output1[] = {0x40, 0x89,  // type (ACCEPT_CH)
                       0x00};       // length

  std::unique_ptr<char[]> buffer;
  uint64_t length = HttpEncoder::SerializeAcceptChFrame(accept_ch, &buffer);
  EXPECT_EQ(ABSL_ARRAYSIZE(output1), length);
  quiche::test::CompareCharArraysWithHexError("ACCEPT_CH", buffer.get(), length,
                                              reinterpret_cast<char*>(output1),
                                              ABSL_ARRAYSIZE(output1));

  accept_ch.entries.push_back({"foo", "bar"});
  uint8_t output2[] = {0x40, 0x89,               // type (ACCEPT_CH)
                       0x08,                     // payload length
                       0x03, 0x66, 0x6f, 0x6f,   // length of "foo"; "foo"
                       0x03, 0x62, 0x61, 0x72};  // length of "bar"; "bar"

  length = HttpEncoder::SerializeAcceptChFrame(accept_ch, &buffer);
  EXPECT_EQ(ABSL_ARRAYSIZE(output2), length);
  quiche::test::CompareCharArraysWithHexError("ACCEPT_CH", buffer.get(), length,
                                              reinterpret_cast<char*>(output2),
                                              ABSL_ARRAYSIZE(output2));
}

TEST(HttpEncoderTest, SerializeWebTransportStreamFrameHeader) {
  WebTransportSessionId session_id = 0x17;
  char output[] = {0x40, 0x41,  // type (WEBTRANSPORT_STREAM)
                   0x17};       // session ID

  std::unique_ptr<char[]> buffer;
  uint64_t length =
      HttpEncoder::SerializeWebTransportStreamFrameHeader(session_id, &buffer);
  EXPECT_EQ(sizeof(output), length);
  quiche::test::CompareCharArraysWithHexError(
      "WEBTRANSPORT_STREAM", buffer.get(), length, output, sizeof(output));
}

TEST(HttpEncoderTest, SerializeMetadataFrameHeader) {
  std::unique_ptr<char[]> buffer;
  uint64_t length = HttpEncoder::SerializeMetadataFrameHeader(
      /* payload_length = */ 7, &buffer);
  char output[] = {0x40, 0x4d,  // type (METADATA, 0x4d, varint encoded)
                   0x07};       // length
  EXPECT_EQ(ABSL_ARRAYSIZE(output), length);
  quiche::test::CompareCharArraysWithHexError("METADATA", buffer.get(), length,
                                              output, ABSL_ARRAYSIZE(output));
}

}  // namespace test
}  // namespace quic
