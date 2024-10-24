// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_live_relay_queue.h"

#include <cstdint>
#include <optional>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::test {

namespace {

class TestMoqtLiveRelayQueue : public MoqtLiveRelayQueue,
                               public MoqtObjectListener {
 public:
  TestMoqtLiveRelayQueue()
      : MoqtLiveRelayQueue(FullTrackName{"test", "track"},
                           MoqtForwardingPreference::kSubgroup) {
    AddObjectListener(this);
  }

  void OnNewObjectAvailable(FullSequence sequence) {
    std::optional<PublishedObject> object = GetCachedObject(sequence);
    QUICHE_CHECK(object.has_value());
    switch (object->status) {
      case MoqtObjectStatus::kNormal:
        PublishObject(object->sequence.group, object->sequence.object,
                      object->payload.AsStringView());
        break;
      case MoqtObjectStatus::kObjectDoesNotExist:
        SkipObject(object->sequence.group, object->sequence.object);
        break;
      case MoqtObjectStatus::kGroupDoesNotExist:
        SkipGroup(object->sequence.group);
        break;
      case MoqtObjectStatus::kEndOfGroup:
        CloseStreamForGroup(object->sequence.group);
        break;
      case MoqtObjectStatus::kEndOfTrack:
        CloseTrack();
        break;
      case moqt::MoqtObjectStatus::kEndOfSubgroup:
        CloseStreamForSubgroup(object->sequence.group,
                               object->sequence.subgroup);
        break;
      default:
        EXPECT_TRUE(false);
    }
  }

  void CallSubscribeForPast(const SubscribeWindow& window) {
    std::vector<FullSequence> objects =
        GetCachedObjectsInRange(FullSequence(0, 0), GetLargestSequence());
    for (FullSequence object : objects) {
      if (window.InWindow(object)) {
        OnNewObjectAvailable(object);
      }
    }
  }

  MOCK_METHOD(void, CloseStreamForGroup, (uint64_t group_id), ());
  MOCK_METHOD(void, CloseStreamForSubgroup,
              (uint64_t group_id, uint64_t subgroup_id), ());
  MOCK_METHOD(void, PublishObject,
              (uint64_t group_id, uint64_t object_id,
               absl::string_view payload),
              ());
  MOCK_METHOD(void, SkipObject, (uint64_t group_id, uint64_t object_id), ());
  MOCK_METHOD(void, SkipGroup, (uint64_t group_id), ());
  MOCK_METHOD(void, CloseTrack, (), ());
  MOCK_METHOD(void, OnTrackPublisherGone, (), (override));
};

// Duplicates of MoqtOutgoingQueue test cases.
TEST(MoqtLiveRelayQueue, SingleGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
}

TEST(MoqtLiveRelayQueue, SingleGroupPastSubscribeFromZero) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));

    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtLiveRelayQueue, SingleGroupPastSubscribeFromMidGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));

    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 1));
}

TEST(MoqtLiveRelayQueue, TwoGroups) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d"));
    EXPECT_CALL(queue, PublishObject(1, 1, "e"));
    EXPECT_CALL(queue, PublishObject(1, 2, "f"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "d"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 2}, "f"));
}

TEST(MoqtLiveRelayQueue, TwoGroupsPastSubscribe) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d"));
    EXPECT_CALL(queue, PublishObject(1, 1, "e"));
    EXPECT_CALL(queue, PublishObject(1, 2, "f"));

    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d"));
    EXPECT_CALL(queue, PublishObject(1, 1, "e"));
    EXPECT_CALL(queue, PublishObject(1, 2, "f"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "d"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 2}, "f"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 1));
}

TEST(MoqtLiveRelayQueue, FiveGroups) {
  TestMoqtLiveRelayQueue queue;
  ;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "c"));
    EXPECT_CALL(queue, PublishObject(1, 1, "d"));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "c"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "d"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{1, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 0}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 1}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{2, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 0}, "g"));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 1}, "h"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{3, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 0}, "i"));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 1}, "j"));
}

TEST(MoqtLiveRelayQueue, FiveGroupsPastSubscribe) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "c"));
    EXPECT_CALL(queue, PublishObject(1, 1, "d"));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));

    // Past SUBSCRIBE would only get the three most recent groups.
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "c"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "d"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{1, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 0}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 1}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{2, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 0}, "g"));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 1}, "h"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{3, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 0}, "i"));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 1}, "j"));
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtLiveRelayQueue, FiveGroupsPastSubscribeFromMidGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(1, 0, "c"));
    EXPECT_CALL(queue, PublishObject(1, 1, "d"));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e"));
    EXPECT_CALL(queue, PublishObject(2, 1, "f"));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g"));
    EXPECT_CALL(queue, PublishObject(3, 1, "h"));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i"));
    EXPECT_CALL(queue, PublishObject(4, 1, "j"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 0}, "c"));
  EXPECT_TRUE(queue.AddObject(FullSequence{1, 1}, "d"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{1, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 0}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{2, 1}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{2, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 0}, "g"));
  EXPECT_TRUE(queue.AddObject(FullSequence{3, 1}, "h"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{3, 2}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 0}, "i"));
  EXPECT_TRUE(queue.AddObject(FullSequence{4, 1}, "j"));
  // This object will be ignored, but this is not an error.
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2}, MoqtObjectStatus::kEndOfGroup));
}

TEST(MoqtLiveRelayQueue, EndOfTrack) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseTrack());
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_FALSE(
      queue.AddObject(FullSequence{0, 1}, MoqtObjectStatus::kEndOfTrack));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfTrack));
}

TEST(MoqtLiveRelayQueue, EndOfGroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_FALSE(
      queue.AddObject(FullSequence{0, 1}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 4}, "e"));
}

TEST(MoqtLiveRelayQueue, GroupDoesNotExist) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, SkipGroup(0));
  }
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 1},
                               MoqtObjectStatus::kGroupDoesNotExist));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0},
                              MoqtObjectStatus::kGroupDoesNotExist));
}

TEST(MoqtLiveRelayQueue, OverwriteObject) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 3}, MoqtObjectStatus::kEndOfGroup));
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 1}, "invalid"));
}

TEST(MoqtLiveRelayQueue, DifferentSubgroups) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 3, "d"));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 0));
    EXPECT_CALL(queue, PublishObject(0, 5, "e"));
    EXPECT_CALL(queue, PublishObject(0, 7, "f"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 1));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 2));

    // Serve them back in strict subgroup order.
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, PublishObject(0, 3, "d"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 0));
    EXPECT_CALL(queue, PublishObject(0, 1, "b"));
    EXPECT_CALL(queue, PublishObject(0, 5, "e"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 1));
    EXPECT_CALL(queue, PublishObject(0, 2, "c"));
    EXPECT_CALL(queue, PublishObject(0, 7, "f"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 2));
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0, 0}, "a"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1, 1}, "b"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0, 3}, "d"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2, 2}, "c"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 0, 4}, MoqtObjectStatus::kEndOfSubgroup));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 1, 5}, "e"));
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 2, 7}, "f"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 1, 6}, MoqtObjectStatus::kEndOfSubgroup));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 2, 8}, MoqtObjectStatus::kEndOfSubgroup));
  queue.CallSubscribeForPast(SubscribeWindow(0, 0));
}

TEST(MoqtLiveRelayQueue, EndOfSubgroup) {
  TestMoqtLiveRelayQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a"));
    EXPECT_CALL(queue, CloseStreamForSubgroup(0, 0));
    EXPECT_CALL(queue, PublishObject(0, 2, "b")).Times(0);
  }
  EXPECT_TRUE(queue.AddObject(FullSequence{0, 0, 0}, "a"));
  EXPECT_TRUE(
      queue.AddObject(FullSequence{0, 0, 1}, MoqtObjectStatus::kEndOfSubgroup));
  EXPECT_FALSE(queue.AddObject(FullSequence{0, 0, 2}, "b"));
}

}  // namespace

}  // namespace moqt::test
