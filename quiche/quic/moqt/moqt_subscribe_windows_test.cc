// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_subscribe_windows.h"

#include <optional>

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

class QUICHE_EXPORT SubscribeWindowTest : public quic::test::QuicTest {
 public:
  SubscribeWindowTest()
      : window_(/*subscribe_id=*/2, /*start_group=*/4,
                /*start_object=*/0, /*end_group=*/5,
                /*end_object=*/1) {}

  SubscribeWindow window_;
};

TEST_F(SubscribeWindowTest, Queries) {
  EXPECT_EQ(window_.subscribe_id(), 2);
  EXPECT_TRUE(window_.InWindow(FullSequence(4, 0)));
  EXPECT_TRUE(window_.InWindow(FullSequence(5, 1)));
  EXPECT_FALSE(window_.InWindow(FullSequence(5, 2)));
  EXPECT_FALSE(window_.InWindow(FullSequence(6, 0)));
  EXPECT_FALSE(window_.InWindow(FullSequence(3, 12)));
}

TEST_F(SubscribeWindowTest, AddRemoveStream) {
  window_.AddStream(MoqtForwardingPreference::kTrack, 4, 0, 2);
  window_.AddStream(MoqtForwardingPreference::kGroup, 5, 0, 6);
  window_.AddStream(MoqtForwardingPreference::kObject, 5, 1, 10);
  window_.AddStream(MoqtForwardingPreference::kDatagram, 5, 2, 14);
  // This is a no-op; the stream does not exist.
  window_.RemoveStream(MoqtForwardingPreference::kGroup, 6, 0);

  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(4, 0),
                                         MoqtForwardingPreference::kTrack),
            2);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(4, 0),
                                         MoqtForwardingPreference::kGroup),
            std::nullopt);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(4, 0),
                                         MoqtForwardingPreference::kObject),
            std::nullopt);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(4, 0),
                                         MoqtForwardingPreference::kDatagram),
            std::nullopt);

  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 0),
                                         MoqtForwardingPreference::kTrack),
            2);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 0),
                                         MoqtForwardingPreference::kGroup),
            6);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 0),
                                         MoqtForwardingPreference::kObject),
            std::nullopt);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 0),
                                         MoqtForwardingPreference::kDatagram),
            std::nullopt);

  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 1),
                                         MoqtForwardingPreference::kTrack),
            2);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 1),
                                         MoqtForwardingPreference::kGroup),
            6);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 1),
                                         MoqtForwardingPreference::kObject),
            10);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 1),
                                         MoqtForwardingPreference::kDatagram),
            10);

  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 2),
                                         MoqtForwardingPreference::kTrack),
            2);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 2),
                                         MoqtForwardingPreference::kGroup),
            6);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 2),
                                         MoqtForwardingPreference::kObject),
            14);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 2),
                                         MoqtForwardingPreference::kDatagram),
            14);

  window_.RemoveStream(MoqtForwardingPreference::kTrack, 4, 0);
  window_.RemoveStream(MoqtForwardingPreference::kObject, 5, 1);
  // kObject and kDatagram are interchangeable
  window_.RemoveStream(MoqtForwardingPreference::kObject, 5, 2);
  // The two commands above should not have deleted the group stream.
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 2),
                                         MoqtForwardingPreference::kGroup),
            6);
  window_.RemoveStream(MoqtForwardingPreference::kGroup, 5, 0);

  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(4, 0),
                                         MoqtForwardingPreference::kTrack),
            std::nullopt);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 0),
                                         MoqtForwardingPreference::kGroup),
            std::nullopt);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 1),
                                         MoqtForwardingPreference::kObject),
            std::nullopt);
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 2),
                                         MoqtForwardingPreference::kDatagram),
            std::nullopt);
}

TEST_F(SubscribeWindowTest, RemoveGroupBeforeObjects) {
  window_.AddStream(MoqtForwardingPreference::kGroup, 5, 0, 6);
  window_.AddStream(MoqtForwardingPreference::kObject, 5, 1, 10);
  window_.AddStream(MoqtForwardingPreference::kDatagram, 5, 2, 14);
  window_.RemoveStream(MoqtForwardingPreference::kGroup, 5, 0);
  // Object stream is not deleted when the root group stream is.
  EXPECT_EQ(window_.GetStreamForSequence(FullSequence(5, 1),
                                         MoqtForwardingPreference::kObject),
            10);
  EXPECT_FALSE(window_
                   .GetStreamForSequence(FullSequence(5, 0),
                                         MoqtForwardingPreference::kGroup)
                   .has_value());
}

class QUICHE_EXPORT MoqtSubscribeWindowsTest : public quic::test::QuicTest {
 public:
  MoqtSubscribeWindows windows_;
};

TEST_F(MoqtSubscribeWindowsTest, IsEmpty) {
  EXPECT_TRUE(windows_.IsEmpty());
  windows_.AddWindow(SubscribeWindow(0, 1, 3));
  EXPECT_FALSE(windows_.IsEmpty());
}

TEST_F(MoqtSubscribeWindowsTest, IsSubscribed) {
  EXPECT_TRUE(windows_.IsEmpty());
  // The first two windows overlap; the third is open-ended.
  windows_.AddWindow(SubscribeWindow(0, 1, 0, 3, 9));
  windows_.AddWindow(SubscribeWindow(1, 2, 4, 4, 3));
  windows_.AddWindow(SubscribeWindow(2, 10, 0));
  EXPECT_FALSE(windows_.IsEmpty());
  EXPECT_TRUE(windows_.SequenceIsSubscribed(FullSequence(0, 8)).empty());
  auto hits = windows_.SequenceIsSubscribed(FullSequence(1, 0));
  EXPECT_EQ(hits.size(), 1);
  EXPECT_EQ(hits[0]->subscribe_id(), 0);
  EXPECT_TRUE(windows_.SequenceIsSubscribed(FullSequence(4, 4)).empty());
  EXPECT_TRUE(windows_.SequenceIsSubscribed(FullSequence(8, 3)).empty());
  hits = windows_.SequenceIsSubscribed(FullSequence(100, 7));
  EXPECT_EQ(hits.size(), 1);
  EXPECT_EQ(hits[0]->subscribe_id(), 2);
  hits = windows_.SequenceIsSubscribed(FullSequence(3, 0));
  EXPECT_EQ(hits.size(), 2);
  EXPECT_EQ(hits[0]->subscribe_id() + hits[1]->subscribe_id(), 1);
}

TEST_F(MoqtSubscribeWindowsTest, AddGetRemoveWindow) {
  windows_.AddWindow(SubscribeWindow(0, 1, 0, 3, 9));
  SubscribeWindow* window = windows_.GetWindow(0);
  EXPECT_EQ(window->subscribe_id(), 0);
  EXPECT_EQ(windows_.GetWindow(1), nullptr);
  windows_.RemoveWindow(0);
  EXPECT_EQ(windows_.GetWindow(0), nullptr);
}

}  // namespace test

}  // namespace moqt
