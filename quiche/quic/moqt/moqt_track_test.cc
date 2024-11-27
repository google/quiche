// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_track.h"

#include <optional>

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt {

namespace test {

class SubscribeRemoteTrackTest : public quic::test::QuicTest {
 public:
  SubscribeRemoteTrackTest() : track_(subscribe_, &visitor_) {}

  MockSubscribeRemoteTrackVisitor visitor_;
  MoqtSubscribe subscribe_ = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName("foo", "bar"),
      /*subscriber_priority=*/128,
      /*group_order=*/std::nullopt,
      /*ranges=*/2,
      0,
      std::nullopt,
      std::nullopt,
      MoqtSubscribeParameters(),
  };
  SubscribeRemoteTrack track_;
};

TEST_F(SubscribeRemoteTrackTest, Queries) {
  EXPECT_EQ(track_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_EQ(track_.subscribe_id(), 1);
  EXPECT_EQ(track_.track_alias(), 2);
  EXPECT_EQ(track_.visitor(), &visitor_);
  EXPECT_FALSE(track_.is_fetch());
}

TEST_F(SubscribeRemoteTrackTest, UpdateDataStreamType) {
  EXPECT_TRUE(
      track_.CheckDataStreamType(MoqtDataStreamType::kStreamHeaderSubgroup));
  EXPECT_TRUE(
      track_.CheckDataStreamType(MoqtDataStreamType::kStreamHeaderSubgroup));
  EXPECT_FALSE(track_.CheckDataStreamType(MoqtDataStreamType::kObjectDatagram));
}

TEST_F(SubscribeRemoteTrackTest, AllowError) {
  EXPECT_TRUE(track_.ErrorIsAllowed());
  EXPECT_EQ(track_.GetSubscribe().subscribe_id, subscribe_.subscribe_id);
  track_.OnObjectOrOk();
  EXPECT_FALSE(track_.ErrorIsAllowed());
}

TEST_F(SubscribeRemoteTrackTest, Windows) {
  EXPECT_TRUE(track_.InWindow(FullSequence(2, 0)));
  SubscribeWindow new_window(2, 1);
  track_.ChangeWindow(new_window);
  EXPECT_FALSE(track_.InWindow(FullSequence(2, 0)));
}

// TODO: Write test for GetStreamForSequence.

}  // namespace test

}  // namespace moqt
