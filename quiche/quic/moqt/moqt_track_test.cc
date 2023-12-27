// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_track.h"

#include <cstdint>
#include <optional>

#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt {

namespace test {

class LocalTrackTest : public quic::test::QuicTest {
 public:
  LocalTrackTest()
      : track_(FullTrackName("foo", "bar"), /*track_alias=*/5, &visitor_,
               FullSequence(4, 1)) {}
  LocalTrack track_;
  MockLocalTrackVisitor visitor_;
};

TEST_F(LocalTrackTest, Queries) {
  EXPECT_EQ(track_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_EQ(track_.track_alias(), 5);
  EXPECT_EQ(track_.visitor(), &visitor_);
  EXPECT_EQ(track_.next_sequence(), FullSequence(4, 1));
  FullSequence& mutable_next = track_.next_sequence_mutable();
  mutable_next.object++;
  EXPECT_EQ(track_.next_sequence(), FullSequence(4, 2));
  EXPECT_FALSE(track_.HasSubscriber());
}

TEST_F(LocalTrackTest, AfterSubscribe) {
  track_.AddWindow(SubscribeWindow(4, 1));
  EXPECT_TRUE(track_.HasSubscriber());
  EXPECT_FALSE(track_.ShouldSend(3, 12));
  EXPECT_FALSE(track_.ShouldSend(4, 0));
  EXPECT_TRUE(track_.ShouldSend(4, 1));
  EXPECT_TRUE(track_.ShouldSend(12, 0));
}

class RemoteTrackTest : public quic::test::QuicTest {
 public:
  RemoteTrackTest() : track_(FullTrackName("foo", "bar"), &visitor_) {}
  RemoteTrack track_;
  MockRemoteTrackVisitor visitor_;
};

TEST_F(RemoteTrackTest, Queries) {
  EXPECT_EQ(track_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_EQ(track_.track_alias(), std::nullopt);
  EXPECT_EQ(track_.visitor(), &visitor_);
}

TEST_F(RemoteTrackTest, SetAlias) {
  track_.set_track_alias(5);
  EXPECT_EQ(track_.track_alias(), 5);
}

}  // namespace test

}  // namespace moqt
