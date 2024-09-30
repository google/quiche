// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_subscribe_windows.h"

#include <cstdint>
#include <optional>

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace moqt {

namespace test {

class QUICHE_EXPORT SubscribeWindowTest : public quic::test::QuicTest {
 public:
  SubscribeWindowTest() {}

  const uint64_t subscribe_id_ = 2;
  const FullSequence start_{4, 0};
  const FullSequence end_{5, 5};
};

TEST_F(SubscribeWindowTest, Queries) {
  SubscribeWindow window(start_, end_);
  EXPECT_TRUE(window.InWindow(FullSequence(4, 0)));
  EXPECT_TRUE(window.InWindow(FullSequence(5, 5)));
  EXPECT_FALSE(window.InWindow(FullSequence(5, 6)));
  EXPECT_FALSE(window.InWindow(FullSequence(6, 0)));
  EXPECT_FALSE(window.InWindow(FullSequence(3, 12)));
}

TEST_F(SubscribeWindowTest, AddQueryRemoveStreamIdTrack) {
  SendStreamMap stream_map(MoqtForwardingPreference::kTrack);
  stream_map.AddStream(FullSequence{4, 0}, 2);
  EXPECT_QUIC_BUG(stream_map.AddStream(FullSequence{5, 2}, 6),
                  "Stream already added");
  EXPECT_EQ(stream_map.GetStreamForSequence(FullSequence(5, 2)), 2);
  stream_map.RemoveStream(FullSequence{7, 2}, 2);
  EXPECT_EQ(stream_map.GetStreamForSequence(FullSequence(4, 0)), std::nullopt);
}

TEST_F(SubscribeWindowTest, AddQueryRemoveStreamIdSubgroup) {
  SendStreamMap stream_map(MoqtForwardingPreference::kSubgroup);
  stream_map.AddStream(FullSequence{4, 0}, 2);
  EXPECT_EQ(stream_map.GetStreamForSequence(FullSequence(5, 0)), std::nullopt);
  stream_map.AddStream(FullSequence{5, 2}, 6);
  EXPECT_QUIC_BUG(stream_map.AddStream(FullSequence{5, 3}, 6),
                  "Stream already added");
  EXPECT_EQ(stream_map.GetStreamForSequence(FullSequence(4, 1)), 2);
  EXPECT_EQ(stream_map.GetStreamForSequence(FullSequence(5, 0)), 6);
  stream_map.RemoveStream(FullSequence{5, 1}, 6);
  EXPECT_EQ(stream_map.GetStreamForSequence(FullSequence(5, 2)), std::nullopt);
}

TEST_F(SubscribeWindowTest, AddQueryRemoveStreamIdDatagram) {
  SendStreamMap stream_map(MoqtForwardingPreference::kDatagram);
  EXPECT_QUIC_BUG(stream_map.AddStream(FullSequence{4, 0}, 2),
                  "Adding a stream for datagram");
}

TEST_F(SubscribeWindowTest, UpdateStartEnd) {
  SubscribeWindow window(start_, end_);
  EXPECT_TRUE(window.UpdateStartEnd(start_.next(),
                                    FullSequence(end_.group, end_.object - 1)));
  EXPECT_FALSE(window.InWindow(FullSequence(start_.group, start_.object)));
  EXPECT_FALSE(window.InWindow(FullSequence(end_.group, end_.object)));
  EXPECT_FALSE(
      window.UpdateStartEnd(start_, FullSequence(end_.group, end_.object - 1)));
  EXPECT_FALSE(window.UpdateStartEnd(start_.next(), end_));
}

TEST_F(SubscribeWindowTest, UpdateStartEndOpenEnded) {
  SubscribeWindow window(start_, std::nullopt);
  EXPECT_TRUE(window.UpdateStartEnd(start_, end_));
  EXPECT_FALSE(window.InWindow(end_.next()));
  EXPECT_FALSE(window.UpdateStartEnd(start_, std::nullopt));
}

}  // namespace test

}  // namespace moqt
