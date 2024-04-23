// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_outgoing_queue.h"

#include <cstdint>
#include <utility>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt {
namespace {

using ::quic::test::MemSliceFromString;

class TestMoqtOutgoingQueue : public MoqtOutgoingQueue {
 public:
  TestMoqtOutgoingQueue()
      : MoqtOutgoingQueue(nullptr, FullTrackName{"test", "track"}) {}

  void CallSubscribeForPast(const SubscribeWindow& window) {
    absl::StatusOr<PublishPastObjectsCallback> callback =
        OnSubscribeForPast(window);
    QUICHE_CHECK_OK(callback.status());
    (*std::move(callback))();
  }

  MOCK_METHOD(void, CloseStreamForGroup, (uint64_t group_id), (override));
  MOCK_METHOD(void, PublishObject,
              (uint64_t group_id, uint64_t object_id, absl::string_view payload,
               bool close_stream),
              (override));
};

TEST(MoqtOutgoingQueue, FirstObjectNotKeyframe) {
  TestMoqtOutgoingQueue queue;
  EXPECT_QUICHE_BUG(queue.AddObject(MemSliceFromString("a"), false),
                    "The first object");
}

TEST(MoqtOutgoingQueue, SingleGroup) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
}

TEST(MoqtOutgoingQueue, SingleGroupPastSubscribeFromZero) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));

    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.CallSubscribeForPast(
      SubscribeWindow(0, MoqtForwardingPreference::kGroup, 0, 0));
}

TEST(MoqtOutgoingQueue, SingleGroupPastSubscribeFromMidGroup) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));

    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.CallSubscribeForPast(
      SubscribeWindow(0, MoqtForwardingPreference::kGroup, 0, 1));
}

TEST(MoqtOutgoingQueue, TwoGroups) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d", false));
    EXPECT_CALL(queue, PublishObject(1, 1, "e", false));
    EXPECT_CALL(queue, PublishObject(1, 2, "f", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.AddObject(MemSliceFromString("d"), true);
  queue.AddObject(MemSliceFromString("e"), false);
  queue.AddObject(MemSliceFromString("f"), false);
}

TEST(MoqtOutgoingQueue, TwoGroupsPastSubscribe) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", false));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "d", false));
    EXPECT_CALL(queue, PublishObject(1, 1, "e", false));
    EXPECT_CALL(queue, PublishObject(1, 2, "f", false));

    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, PublishObject(0, 2, "c", true));
    EXPECT_CALL(queue, PublishObject(1, 0, "d", false));
    EXPECT_CALL(queue, PublishObject(1, 1, "e", false));
    EXPECT_CALL(queue, PublishObject(1, 2, "f", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), false);
  queue.AddObject(MemSliceFromString("d"), true);
  queue.AddObject(MemSliceFromString("e"), false);
  queue.AddObject(MemSliceFromString("f"), false);
  queue.CallSubscribeForPast(
      SubscribeWindow(0, MoqtForwardingPreference::kGroup, 0, 1));
}

TEST(MoqtOutgoingQueue, FiveGroups) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "c", false));
    EXPECT_CALL(queue, PublishObject(1, 1, "d", false));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e", false));
    EXPECT_CALL(queue, PublishObject(2, 1, "f", false));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g", false));
    EXPECT_CALL(queue, PublishObject(3, 1, "h", false));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i", false));
    EXPECT_CALL(queue, PublishObject(4, 1, "j", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), true);
  queue.AddObject(MemSliceFromString("d"), false);
  queue.AddObject(MemSliceFromString("e"), true);
  queue.AddObject(MemSliceFromString("f"), false);
  queue.AddObject(MemSliceFromString("g"), true);
  queue.AddObject(MemSliceFromString("h"), false);
  queue.AddObject(MemSliceFromString("i"), true);
  queue.AddObject(MemSliceFromString("j"), false);
}

TEST(MoqtOutgoingQueue, FiveGroupsPastSubscribe) {
  TestMoqtOutgoingQueue queue;
  {
    testing::InSequence seq;
    EXPECT_CALL(queue, PublishObject(0, 0, "a", false));
    EXPECT_CALL(queue, PublishObject(0, 1, "b", false));
    EXPECT_CALL(queue, CloseStreamForGroup(0));
    EXPECT_CALL(queue, PublishObject(1, 0, "c", false));
    EXPECT_CALL(queue, PublishObject(1, 1, "d", false));
    EXPECT_CALL(queue, CloseStreamForGroup(1));
    EXPECT_CALL(queue, PublishObject(2, 0, "e", false));
    EXPECT_CALL(queue, PublishObject(2, 1, "f", false));
    EXPECT_CALL(queue, CloseStreamForGroup(2));
    EXPECT_CALL(queue, PublishObject(3, 0, "g", false));
    EXPECT_CALL(queue, PublishObject(3, 1, "h", false));
    EXPECT_CALL(queue, CloseStreamForGroup(3));
    EXPECT_CALL(queue, PublishObject(4, 0, "i", false));
    EXPECT_CALL(queue, PublishObject(4, 1, "j", false));

    // Past SUBSCRIBE would only get the three most recent groups.
    EXPECT_CALL(queue, PublishObject(2, 0, "e", false));
    EXPECT_CALL(queue, PublishObject(2, 1, "f", true));
    EXPECT_CALL(queue, PublishObject(3, 0, "g", false));
    EXPECT_CALL(queue, PublishObject(3, 1, "h", true));
    EXPECT_CALL(queue, PublishObject(4, 0, "i", false));
    EXPECT_CALL(queue, PublishObject(4, 1, "j", false));
  }
  queue.AddObject(MemSliceFromString("a"), true);
  queue.AddObject(MemSliceFromString("b"), false);
  queue.AddObject(MemSliceFromString("c"), true);
  queue.AddObject(MemSliceFromString("d"), false);
  queue.AddObject(MemSliceFromString("e"), true);
  queue.AddObject(MemSliceFromString("f"), false);
  queue.AddObject(MemSliceFromString("g"), true);
  queue.AddObject(MemSliceFromString("h"), false);
  queue.AddObject(MemSliceFromString("i"), true);
  queue.AddObject(MemSliceFromString("j"), false);
  queue.CallSubscribeForPast(
      SubscribeWindow(0, MoqtForwardingPreference::kGroup, 0, 0));
}

}  // namespace
}  // namespace moqt
