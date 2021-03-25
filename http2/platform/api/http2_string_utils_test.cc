// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "http2/platform/api/http2_string_utils.h"

#include "common/platform/api/quiche_test.h"

namespace http2 {
namespace test {
namespace {

TEST(Http2StringUtilsTest, Http2StringPrintf) {
  EXPECT_EQ("", Http2StringPrintf("%s", ""));
  EXPECT_EQ("foobar", Http2StringPrintf("%sbar", "foo"));
  EXPECT_EQ("foobar", Http2StringPrintf("%s%s", "foo", "bar"));
  EXPECT_EQ("foo: 1, bar: 2.0",
            Http2StringPrintf("foo: %d, bar: %.1f", 1, 2.0));
}

}  // namespace
}  // namespace test
}  // namespace http2
