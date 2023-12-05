// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_subscribe_windows.h"

#include "quiche/quic/platform/api/quic_test.h"

namespace moqt {

namespace test {

class MoqtSubscribeWindowsTest : public quic::test::QuicTest {
 public:
  MoqtSubscribeWindows windows_;
};

TEST_F(MoqtSubscribeWindowsTest, IsEmpty) {
  EXPECT_TRUE(windows_.IsEmpty());
  windows_.AddWindow(SubscribeWindow(1, 3));
  EXPECT_FALSE(windows_.IsEmpty());
}

TEST_F(MoqtSubscribeWindowsTest, IsSubscribed) {
  EXPECT_TRUE(windows_.IsEmpty());
  // The first two windows overlap; the third is open-ended.
  windows_.AddWindow(SubscribeWindow(1, 0, 3, 9));
  windows_.AddWindow(SubscribeWindow(2, 4, 4, 3));
  windows_.AddWindow(SubscribeWindow(10, 0));
  EXPECT_FALSE(windows_.IsEmpty());
  EXPECT_FALSE(windows_.SequenceIsSubscribed(0, 8));
  EXPECT_TRUE(windows_.SequenceIsSubscribed(1, 0));
  EXPECT_FALSE(windows_.SequenceIsSubscribed(4, 4));
  EXPECT_FALSE(windows_.SequenceIsSubscribed(8, 3));
  EXPECT_TRUE(windows_.SequenceIsSubscribed(100, 7));
}

}  // namespace test

}  // namespace moqt
