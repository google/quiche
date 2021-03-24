// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "spdy/platform/api/spdy_string_utils.h"

#include <cstdint>

#include "absl/strings/string_view.h"
#include "common/platform/api/quiche_test.h"

namespace spdy {
namespace test {
namespace {

TEST(SpdyStringUtilsTest, SpdyHexDigitToInt) {
  EXPECT_EQ(0, SpdyHexDigitToInt('0'));
  EXPECT_EQ(1, SpdyHexDigitToInt('1'));
  EXPECT_EQ(2, SpdyHexDigitToInt('2'));
  EXPECT_EQ(3, SpdyHexDigitToInt('3'));
  EXPECT_EQ(4, SpdyHexDigitToInt('4'));
  EXPECT_EQ(5, SpdyHexDigitToInt('5'));
  EXPECT_EQ(6, SpdyHexDigitToInt('6'));
  EXPECT_EQ(7, SpdyHexDigitToInt('7'));
  EXPECT_EQ(8, SpdyHexDigitToInt('8'));
  EXPECT_EQ(9, SpdyHexDigitToInt('9'));

  EXPECT_EQ(10, SpdyHexDigitToInt('a'));
  EXPECT_EQ(11, SpdyHexDigitToInt('b'));
  EXPECT_EQ(12, SpdyHexDigitToInt('c'));
  EXPECT_EQ(13, SpdyHexDigitToInt('d'));
  EXPECT_EQ(14, SpdyHexDigitToInt('e'));
  EXPECT_EQ(15, SpdyHexDigitToInt('f'));

  EXPECT_EQ(10, SpdyHexDigitToInt('A'));
  EXPECT_EQ(11, SpdyHexDigitToInt('B'));
  EXPECT_EQ(12, SpdyHexDigitToInt('C'));
  EXPECT_EQ(13, SpdyHexDigitToInt('D'));
  EXPECT_EQ(14, SpdyHexDigitToInt('E'));
  EXPECT_EQ(15, SpdyHexDigitToInt('F'));
}

TEST(SpdyStringUtilsTest, SpdyHexDecodeToUInt32) {
  uint32_t out;
  EXPECT_TRUE(SpdyHexDecodeToUInt32("0", &out));
  EXPECT_EQ(0u, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("00", &out));
  EXPECT_EQ(0u, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("0000000", &out));
  EXPECT_EQ(0u, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("00000000", &out));
  EXPECT_EQ(0u, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("1", &out));
  EXPECT_EQ(1u, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("ffffFFF", &out));
  EXPECT_EQ(0xFFFFFFFu, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("fFfFffFf", &out));
  EXPECT_EQ(0xFFFFFFFFu, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("01AEF", &out));
  EXPECT_EQ(0x1AEFu, out);
  EXPECT_TRUE(SpdyHexDecodeToUInt32("abcde", &out));
  EXPECT_EQ(0xABCDEu, out);

  EXPECT_FALSE(SpdyHexDecodeToUInt32("", &out));
  EXPECT_FALSE(SpdyHexDecodeToUInt32("111111111", &out));
  EXPECT_FALSE(SpdyHexDecodeToUInt32("1111111111", &out));
  EXPECT_FALSE(SpdyHexDecodeToUInt32("0x1111", &out));
}

TEST(SpdyStringUtilsTest, SpdyHexEncode) {
  unsigned char bytes[] = {0x01, 0xff, 0x02, 0xfe, 0x03, 0x80, 0x81};
  EXPECT_EQ("01ff02fe038081",
            SpdyHexEncode(reinterpret_cast<char*>(bytes), sizeof(bytes)));
}

}  // namespace
}  // namespace test
}  // namespace spdy
