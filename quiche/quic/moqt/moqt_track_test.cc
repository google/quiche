// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_track.h"

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
      : track_(FullTrackName("foo", "bar"), MoqtForwardingPreference::kTrack,
               &visitor_, FullSequence(4, 1)) {}
  LocalTrack track_;
  MockLocalTrackVisitor visitor_;
};

TEST_F(LocalTrackTest, Queries) {
  EXPECT_EQ(track_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_EQ(track_.track_alias(), std::nullopt);
  EXPECT_EQ(track_.visitor(), &visitor_);
  EXPECT_EQ(track_.next_sequence(), FullSequence(4, 1));
  track_.SentSequence(FullSequence(4, 0));
  EXPECT_EQ(track_.next_sequence(), FullSequence(4, 1));  // no change
  track_.SentSequence(FullSequence(4, 1));
  EXPECT_EQ(track_.next_sequence(), FullSequence(4, 2));
  EXPECT_FALSE(track_.HasSubscriber());
  EXPECT_EQ(track_.forwarding_preference(), MoqtForwardingPreference::kTrack);
}

TEST_F(LocalTrackTest, SetTrackAlias) {
  EXPECT_EQ(track_.track_alias(), std::nullopt);
  track_.set_track_alias(6);
  EXPECT_EQ(track_.track_alias(), 6);
}

TEST_F(LocalTrackTest, AddGetDeleteWindow) {
  track_.AddWindow(0, 4, 1);
  EXPECT_EQ(track_.GetWindow(0)->subscribe_id(), 0);
  EXPECT_EQ(track_.GetWindow(1), nullptr);
  track_.DeleteWindow(0);
  EXPECT_EQ(track_.GetWindow(0), nullptr);
}

TEST_F(LocalTrackTest, GroupSubscriptionUsesMaxObjectId) {
  // Populate max_object_ids_
  track_.SentSequence(FullSequence(0, 0));
  track_.SentSequence(FullSequence(1, 0));
  track_.SentSequence(FullSequence(1, 1));
  // Skip Group 2
  track_.SentSequence(FullSequence(3, 0));
  track_.SentSequence(FullSequence(3, 1));
  track_.SentSequence(FullSequence(3, 2));
  track_.SentSequence(FullSequence(3, 3));
  track_.SentSequence(FullSequence(4, 0));
  track_.SentSequence(FullSequence(4, 1));
  track_.SentSequence(FullSequence(4, 2));
  track_.SentSequence(FullSequence(4, 3));
  track_.SentSequence(FullSequence(4, 4));
  EXPECT_EQ(track_.next_sequence(), FullSequence(4, 5));
  track_.AddWindow(0, 1, 1, 3);
  SubscribeWindow* window = track_.GetWindow(0);
  EXPECT_TRUE(window->InWindow(FullSequence(3, 3)));
  EXPECT_FALSE(window->InWindow(FullSequence(3, 4)));
  // End on an empty group.
  track_.AddWindow(1, 1, 1, 2);
  window = track_.GetWindow(1);
  EXPECT_TRUE(window->InWindow(FullSequence(1, 1)));
  EXPECT_FALSE(window->InWindow(FullSequence(1, 2)));
  // End on an group in progress.
  track_.AddWindow(2, 1, 1, 4);
  window = track_.GetWindow(2);
  EXPECT_TRUE(window->InWindow(FullSequence(4, 9)));
  EXPECT_FALSE(window->InWindow(FullSequence(5, 0)));
}

TEST_F(LocalTrackTest, ShouldSend) {
  track_.AddWindow(0, 4, 1);
  EXPECT_TRUE(track_.HasSubscriber());
  EXPECT_TRUE(track_.ShouldSend(FullSequence(3, 12)).empty());
  EXPECT_TRUE(track_.ShouldSend(FullSequence(4, 0)).empty());
  EXPECT_EQ(track_.ShouldSend(FullSequence(4, 1)).size(), 1);
  EXPECT_EQ(track_.ShouldSend(FullSequence(12, 0)).size(), 1);
}

class RemoteTrackTest : public quic::test::QuicTest {
 public:
  RemoteTrackTest()
      : track_(FullTrackName("foo", "bar"), /*track_alias=*/5, &visitor_) {}
  RemoteTrack track_;
  MockRemoteTrackVisitor visitor_;
};

TEST_F(RemoteTrackTest, Queries) {
  EXPECT_EQ(track_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_EQ(track_.track_alias(), 5);
  EXPECT_EQ(track_.visitor(), &visitor_);
}

TEST_F(RemoteTrackTest, UpdateForwardingPreference) {
  EXPECT_TRUE(
      track_.CheckForwardingPreference(MoqtForwardingPreference::kObject));
  EXPECT_TRUE(
      track_.CheckForwardingPreference(MoqtForwardingPreference::kObject));
  EXPECT_FALSE(
      track_.CheckForwardingPreference(MoqtForwardingPreference::kDatagram));
}

// TODO: Write test for GetStreamForSequence.

}  // namespace test

}  // namespace moqt
