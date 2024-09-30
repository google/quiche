// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_track.h"

#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt {

namespace test {

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
      track_.CheckForwardingPreference(MoqtForwardingPreference::kSubgroup));
  EXPECT_TRUE(
      track_.CheckForwardingPreference(MoqtForwardingPreference::kSubgroup));
  EXPECT_FALSE(
      track_.CheckForwardingPreference(MoqtForwardingPreference::kDatagram));
}

// TODO: Write test for GetStreamForSequence.

}  // namespace test

}  // namespace moqt
