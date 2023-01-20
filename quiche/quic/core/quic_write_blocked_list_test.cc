// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_write_blocked_list.h"

#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"

using spdy::kV3HighestPriority;
using spdy::kV3LowestPriority;

namespace quic {
namespace test {
namespace {

constexpr bool kStatic = true;
constexpr bool kNotStatic = false;

constexpr bool kIncremental = true;
constexpr bool kNotIncremental = false;

class QuicWriteBlockedListTest : public QuicTest {
 protected:
  bool HasWriteBlockedDataStreams() const {
    return write_blocked_list_.HasWriteBlockedDataStreams();
  }

  bool HasWriteBlockedSpecialStream() const {
    return write_blocked_list_.HasWriteBlockedSpecialStream();
  }

  size_t NumBlockedSpecialStreams() const {
    return write_blocked_list_.NumBlockedSpecialStreams();
  }

  size_t NumBlockedStreams() const {
    return write_blocked_list_.NumBlockedStreams();
  }

  bool ShouldYield(QuicStreamId id) const {
    return write_blocked_list_.ShouldYield(id);
  }

  QuicStreamPriority GetPriorityofStream(QuicStreamId id) const {
    return write_blocked_list_.GetPriorityofStream(id);
  }

  QuicStreamId PopFront() { return write_blocked_list_.PopFront(); }

  void RegisterStream(QuicStreamId stream_id, bool is_static_stream,
                      const QuicStreamPriority& priority) {
    write_blocked_list_.RegisterStream(stream_id, is_static_stream, priority);
  }

  void UnregisterStream(QuicStreamId stream_id) {
    write_blocked_list_.UnregisterStream(stream_id);
  }

  void UpdateStreamPriority(QuicStreamId stream_id,
                            const QuicStreamPriority& new_priority) {
    write_blocked_list_.UpdateStreamPriority(stream_id, new_priority);
  }

  void UpdateBytesForStream(QuicStreamId stream_id, size_t bytes) {
    write_blocked_list_.UpdateBytesForStream(stream_id, bytes);
  }

  void AddStream(QuicStreamId stream_id) {
    write_blocked_list_.AddStream(stream_id);
  }

  bool IsStreamBlocked(QuicStreamId stream_id) const {
    return write_blocked_list_.IsStreamBlocked(stream_id);
  }

 private:
  QuicWriteBlockedList write_blocked_list_;
};

TEST_F(QuicWriteBlockedListTest, PriorityOrder) {
  // Mark streams blocked in roughly reverse priority order, and
  // verify that streams are sorted.
  RegisterStream(40, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(23, kNotStatic, {kV3HighestPriority, kIncremental});
  RegisterStream(17, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(1, kStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  EXPECT_EQ(kV3LowestPriority, GetPriorityofStream(40).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(40).incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityofStream(23).urgency);
  EXPECT_EQ(kIncremental, GetPriorityofStream(23).incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityofStream(17).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(17).incremental);

  AddStream(40);
  EXPECT_TRUE(IsStreamBlocked(40));
  AddStream(23);
  EXPECT_TRUE(IsStreamBlocked(23));
  AddStream(17);
  EXPECT_TRUE(IsStreamBlocked(17));
  AddStream(3);
  EXPECT_TRUE(IsStreamBlocked(3));
  AddStream(1);
  EXPECT_TRUE(IsStreamBlocked(1));

  EXPECT_EQ(5u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedSpecialStream());
  EXPECT_EQ(2u, NumBlockedSpecialStreams());
  EXPECT_TRUE(HasWriteBlockedDataStreams());

  // Static streams are highest priority, regardless of priority value.
  EXPECT_EQ(1u, PopFront());
  EXPECT_EQ(1u, NumBlockedSpecialStreams());
  EXPECT_FALSE(IsStreamBlocked(1));

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(0u, NumBlockedSpecialStreams());
  EXPECT_FALSE(IsStreamBlocked(3));

  // Streams with same priority are popped in the order they were inserted.
  EXPECT_EQ(23u, PopFront());
  EXPECT_FALSE(IsStreamBlocked(23));
  EXPECT_EQ(17u, PopFront());
  EXPECT_FALSE(IsStreamBlocked(17));

  // Low priority stream appears last.
  EXPECT_EQ(40u, PopFront());
  EXPECT_FALSE(IsStreamBlocked(40));

  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedSpecialStream());
  EXPECT_FALSE(HasWriteBlockedDataStreams());
}

TEST_F(QuicWriteBlockedListTest, SingleStaticStream) {
  RegisterStream(5, kStatic, {kV3HighestPriority, kNotIncremental});
  AddStream(5);

  EXPECT_EQ(1u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedSpecialStream());
  EXPECT_EQ(5u, PopFront());
  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedSpecialStream());
}

TEST_F(QuicWriteBlockedListTest, StaticStreamsComeFirst) {
  RegisterStream(5, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3LowestPriority, kNotIncremental});
  AddStream(5);
  AddStream(3);

  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedSpecialStream());
  EXPECT_TRUE(HasWriteBlockedDataStreams());

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(5u, PopFront());

  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedSpecialStream());
  EXPECT_FALSE(HasWriteBlockedDataStreams());
}

TEST_F(QuicWriteBlockedListTest, NoDuplicateEntries) {
  // Test that QuicWriteBlockedList doesn't allow duplicate entries.
  // Try to add a stream to the write blocked list multiple times at the same
  // priority.
  const QuicStreamId kBlockedId = 5;
  RegisterStream(kBlockedId, kNotStatic, {kV3HighestPriority, kNotIncremental});
  AddStream(kBlockedId);
  AddStream(kBlockedId);
  AddStream(kBlockedId);

  // This should only result in one blocked stream being added.
  EXPECT_EQ(1u, NumBlockedStreams());
  EXPECT_TRUE(HasWriteBlockedDataStreams());

  // There should only be one stream to pop off the front.
  EXPECT_EQ(kBlockedId, PopFront());
  EXPECT_EQ(0u, NumBlockedStreams());
  EXPECT_FALSE(HasWriteBlockedDataStreams());
}

TEST_F(QuicWriteBlockedListTest, BatchingWrites) {
  const QuicStreamId id1 = 5;
  const QuicStreamId id2 = 7;
  const QuicStreamId id3 = 9;
  RegisterStream(id1, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(id2, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(id3, kNotStatic, {kV3HighestPriority, kNotIncremental});

  AddStream(id1);
  AddStream(id2);
  EXPECT_EQ(2u, NumBlockedStreams());

  // The first stream we push back should stay at the front until 16k is
  // written.
  EXPECT_EQ(id1, PopFront());
  UpdateBytesForStream(id1, 15999);
  AddStream(id1);
  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_EQ(id1, PopFront());

  // Once 16k is written the first stream will yield to the next.
  UpdateBytesForStream(id1, 1);
  AddStream(id1);
  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_EQ(id2, PopFront());

  // Set the new stream to have written all but one byte.
  UpdateBytesForStream(id2, 15999);
  AddStream(id2);
  EXPECT_EQ(2u, NumBlockedStreams());

  // Ensure higher priority streams are popped first.
  AddStream(id3);
  EXPECT_EQ(id3, PopFront());

  // Higher priority streams will always be popped first, even if using their
  // byte quota
  UpdateBytesForStream(id3, 20000);
  AddStream(id3);
  EXPECT_EQ(id3, PopFront());

  // Once the higher priority stream is out of the way, id2 will resume its 16k
  // write, with only 1 byte remaining of its guaranteed write allocation.
  EXPECT_EQ(id2, PopFront());
  UpdateBytesForStream(id2, 1);
  AddStream(id2);
  EXPECT_EQ(2u, NumBlockedStreams());
  EXPECT_EQ(id1, PopFront());
}

TEST_F(QuicWriteBlockedListTest, Ceding) {
  RegisterStream(15, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(16, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(5, kNotStatic, {5, kNotIncremental});
  RegisterStream(4, kNotStatic, {5, kNotIncremental});
  RegisterStream(7, kNotStatic, {7, kNotIncremental});
  RegisterStream(1, kStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  // When nothing is on the list, nothing yields.
  EXPECT_FALSE(ShouldYield(5));

  AddStream(5);
  // 5 should not yield to itself.
  EXPECT_FALSE(ShouldYield(5));
  // 4 and 7 are equal or lower priority and should yield to 5.
  EXPECT_TRUE(ShouldYield(4));
  EXPECT_TRUE(ShouldYield(7));
  // Stream 15 and static streams should preempt 5.
  EXPECT_FALSE(ShouldYield(15));
  EXPECT_FALSE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));

  // Block a high priority stream.
  AddStream(15);
  // 16 should yield (same priority) but static streams will still not.
  EXPECT_TRUE(ShouldYield(16));
  EXPECT_FALSE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));

  // Block a static stream.  All non-static streams should yield.
  AddStream(3);
  EXPECT_TRUE(ShouldYield(16));
  EXPECT_TRUE(ShouldYield(15));
  EXPECT_FALSE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));

  // Block the other static stream.  All other streams should yield.
  AddStream(1);
  EXPECT_TRUE(ShouldYield(16));
  EXPECT_TRUE(ShouldYield(15));
  EXPECT_TRUE(ShouldYield(3));
  EXPECT_FALSE(ShouldYield(1));
}

TEST_F(QuicWriteBlockedListTest, UnregisterStream) {
  RegisterStream(40, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(23, kNotStatic, {6, kNotIncremental});
  RegisterStream(12, kNotStatic, {3, kNotIncremental});
  RegisterStream(17, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(1, kStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  AddStream(40);
  AddStream(23);
  AddStream(12);
  AddStream(17);
  AddStream(1);
  AddStream(3);

  UnregisterStream(23);
  UnregisterStream(1);

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(17u, PopFront());
  EXPECT_EQ(12u, PopFront());
  EXPECT_EQ(40, PopFront());
}

TEST_F(QuicWriteBlockedListTest, UnregisterNotRegisteredStream) {
  EXPECT_QUICHE_BUG(UnregisterStream(1), "Stream 1 not registered");

  RegisterStream(2, kNotStatic, {kV3HighestPriority, kIncremental});
  UnregisterStream(2);
  EXPECT_QUICHE_BUG(UnregisterStream(2), "Stream 2 not registered");
}

TEST_F(QuicWriteBlockedListTest, UpdateStreamPriority) {
  RegisterStream(40, kNotStatic, {kV3LowestPriority, kNotIncremental});
  RegisterStream(23, kNotStatic, {6, kIncremental});
  RegisterStream(17, kNotStatic, {kV3HighestPriority, kNotIncremental});
  RegisterStream(1, kStatic, {2, kNotIncremental});
  RegisterStream(3, kStatic, {kV3HighestPriority, kNotIncremental});

  EXPECT_EQ(kV3LowestPriority, GetPriorityofStream(40).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(40).incremental);

  EXPECT_EQ(6, GetPriorityofStream(23).urgency);
  EXPECT_EQ(kIncremental, GetPriorityofStream(23).incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityofStream(17).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(17).incremental);

  UpdateStreamPriority(40, {3, kIncremental});
  UpdateStreamPriority(23, {kV3HighestPriority, kNotIncremental});
  UpdateStreamPriority(17, {5, kNotIncremental});

  EXPECT_EQ(3, GetPriorityofStream(40).urgency);
  EXPECT_EQ(kIncremental, GetPriorityofStream(40).incremental);

  EXPECT_EQ(kV3HighestPriority, GetPriorityofStream(23).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(23).incremental);

  EXPECT_EQ(5, GetPriorityofStream(17).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(17).incremental);

  AddStream(40);
  AddStream(23);
  AddStream(17);
  AddStream(1);
  AddStream(3);

  EXPECT_EQ(1u, PopFront());
  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(23u, PopFront());
  EXPECT_EQ(40u, PopFront());
  EXPECT_EQ(17u, PopFront());
}

// UpdateStreamPriority() must not be called for static streams.
TEST_F(QuicWriteBlockedListTest, UpdateStaticStreamPriority) {
  RegisterStream(2, kStatic, {kV3LowestPriority, kNotIncremental});
  EXPECT_QUICHE_DEBUG_DEATH(
      UpdateStreamPriority(2, {kV3HighestPriority, kNotIncremental}),
      "IsRegistered");
}

TEST_F(QuicWriteBlockedListTest, UpdateStreamPrioritySameUrgency) {
  // Streams with same urgency are returned by PopFront() in the order they were
  // added by AddStream().
  RegisterStream(1, kNotStatic, {6, kNotIncremental});
  RegisterStream(2, kNotStatic, {6, kNotIncremental});

  AddStream(1);
  AddStream(2);

  EXPECT_EQ(1u, PopFront());
  EXPECT_EQ(2u, PopFront());

  // Calling UpdateStreamPriority() on the first stream does not change the
  // order.
  RegisterStream(3, kNotStatic, {6, kNotIncremental});
  RegisterStream(4, kNotStatic, {6, kNotIncremental});

  EXPECT_EQ(6, GetPriorityofStream(3).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(3).incremental);

  UpdateStreamPriority(3, {6, kIncremental});

  EXPECT_EQ(6, GetPriorityofStream(3).urgency);
  EXPECT_EQ(kIncremental, GetPriorityofStream(3).incremental);

  AddStream(3);
  AddStream(4);

  EXPECT_EQ(3u, PopFront());
  EXPECT_EQ(4u, PopFront());

  // Calling UpdateStreamPriority() on the second stream does not change the
  // order.
  RegisterStream(5, kNotStatic, {6, kIncremental});
  RegisterStream(6, kNotStatic, {6, kIncremental});

  EXPECT_EQ(6, GetPriorityofStream(6).urgency);
  EXPECT_EQ(kIncremental, GetPriorityofStream(6).incremental);

  UpdateStreamPriority(6, {6, kNotIncremental});

  EXPECT_EQ(6, GetPriorityofStream(6).urgency);
  EXPECT_EQ(kNotIncremental, GetPriorityofStream(6).incremental);

  AddStream(5);
  AddStream(6);

  EXPECT_EQ(5u, PopFront());
  EXPECT_EQ(6u, PopFront());
}

}  // namespace
}  // namespace test
}  // namespace quic
