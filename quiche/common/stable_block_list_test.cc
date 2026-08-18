// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/stable_block_list.h"

#include <memory>
#include <vector>

#include "quiche/common/platform/api/quiche_test.h"

namespace quiche {
namespace {

struct AllocStats {
  size_t allocs = 0;
  size_t deallocs = 0;
};

template <typename T>
struct TrackingAllocator {
  using value_type = T;

  std::shared_ptr<AllocStats> stats;

  TrackingAllocator() = default;
  explicit TrackingAllocator(std::shared_ptr<AllocStats> s)
      : stats(std::move(s)) {}

  template <typename U>
  TrackingAllocator(const TrackingAllocator<U>& other) : stats(other.stats) {}

  T* allocate(std::size_t n) {
    if (stats) stats->allocs++;
    return std::allocator<T>().allocate(n);
  }

  void deallocate(T* p, std::size_t n) {
    if (stats) stats->deallocs++;
    std::allocator<T>().deallocate(p, n);
  }

  template <typename U>
  bool operator==(const TrackingAllocator<U>& other) const {
    return stats == other.stats;
  }
  template <typename U>
  bool operator!=(const TrackingAllocator<U>& other) const {
    return stats != other.stats;
  }
};

TEST(StableBlockListTest, BasicOps) {
  StableBlockList<int> list;
  EXPECT_TRUE(list.empty());
  EXPECT_EQ(list.size(), 0);

  list.push_back(1);
  list.push_back(2);
  list.push_back(3);

  EXPECT_FALSE(list.empty());
  EXPECT_EQ(list.size(), 3);
  EXPECT_EQ(list.front(), 1);
  EXPECT_EQ(list.back(), 3);

  StableBlockList<int> list2 = std::move(list);
  EXPECT_FALSE(list2.empty());
  EXPECT_EQ(list2.size(), 3);
  EXPECT_EQ(list2.front(), 1);
  EXPECT_EQ(list2.back(), 3);

  list2.clear();
  EXPECT_TRUE(list2.empty());
  EXPECT_EQ(list2.size(), 0);
}

TEST(StableBlockListTest, Traversal) {
  StableBlockList<int> list;
  list.push_back(1);
  list.push_back(2);
  list.push_back(3);

  auto it = list.begin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_EQ(*it, 2);
  ++it;
  EXPECT_EQ(*it, 3);
  ++it;
  EXPECT_TRUE(it == list.end());

  --it;
  EXPECT_EQ(*it, 3);
  --it;
  EXPECT_EQ(*it, 2);
  --it;
  EXPECT_EQ(*it, 1);
  EXPECT_TRUE(it == list.begin());
}

TEST(StableBlockListTest, IteratorStabilityOnPushBack) {
  StableBlockList<int, 4>
      list;  // Small capacity to force multi-block allocations
  // Fill one chunk (4 elements)
  for (int i = 0; i < 4; ++i) {
    list.push_back(i * 10);  // 0, 10, 20, 30
  }

  // Store iterators
  std::vector<StableBlockList<int, 4>::iterator> iters;
  for (auto it = list.begin(); it != list.end(); ++it) {
    iters.push_back(it);
  }

  // Push back more elements to force allocation of a new block
  list.push_back(40);
  list.push_back(50);

  EXPECT_EQ(list.size(), 6);

  // Verify stored iterators are still valid and point to the same values
  EXPECT_EQ(*iters[0], 0);
  EXPECT_EQ(*iters[1], 10);
  EXPECT_EQ(*iters[2], 20);
  EXPECT_EQ(*iters[3], 30);

  // Verify traversal order
  std::vector<int> elements;
  for (int x : list) {
    elements.push_back(x);
  }
  EXPECT_THAT(elements, ::testing::ElementsAre(0, 10, 20, 30, 40, 50));
}

TEST(StableBlockListTest, IteratorStabilityOnErase) {
  StableBlockList<int, 4> list;
  for (int i = 0; i < 8; ++i) {
    list.push_back(i * 10);  // 0, 10, 20, 30, 40, 50, 60, 70
  }

  std::vector<StableBlockList<int, 4>::iterator> iters;
  for (auto it = list.begin(); it != list.end(); ++it) {
    iters.push_back(it);
  }

  // Erase 30 (index 3, which is the last element of first block)
  auto erase_pos = iters[3];
  auto next_it = list.erase(erase_pos);
  EXPECT_EQ(*next_it, 40);
  EXPECT_EQ(list.size(), 7);

  // Verify other iterators are still valid
  EXPECT_EQ(*iters[0], 0);
  EXPECT_EQ(*iters[1], 10);
  EXPECT_EQ(*iters[2], 20);
  // iters[3] is invalid (erased), we shouldn't dereference it.
  EXPECT_EQ(*iters[4], 40);
  EXPECT_EQ(*iters[5], 50);
  EXPECT_EQ(*iters[6], 60);
  EXPECT_EQ(*iters[7], 70);

  std::vector<int> elements;
  for (int x : list) {
    elements.push_back(x);
  }
  EXPECT_THAT(elements, ::testing::ElementsAre(0, 10, 20, 40, 50, 60, 70));
}

TEST(StableBlockListTest, MoveOnlyType) {
  StableBlockList<std::unique_ptr<int>> list;
  list.push_back(std::make_unique<int>(1));
  list.push_back(std::make_unique<int>(2));

  EXPECT_EQ(list.size(), 2);
  EXPECT_EQ(*list.front(), 1);
  EXPECT_EQ(*list.back(), 2);

  list.push_back(std::make_unique<int>(3));  // [1, 2, 3]

  EXPECT_EQ(list.size(), 3);
  auto it = list.begin();
  EXPECT_EQ(**it, 1);
  ++it;
  EXPECT_EQ(**it, 2);
  ++it;
  EXPECT_EQ(**it, 3);

  it = list.begin();
  ++it;            // points to 2
  list.erase(it);  // [1, 3]
  EXPECT_EQ(list.size(), 2);
  EXPECT_EQ(*list.front(), 1);
  EXPECT_EQ(*list.back(), 3);
}

TEST(StableBlockListTest, MultiBlockPushBackAndBackwardTraversal) {
  StableBlockList<int, 8> list;
  const int num_elements = 100;
  for (int i = 0; i < num_elements; ++i) {
    list.push_back(i);
  }
  EXPECT_EQ(list.size(), num_elements);
  EXPECT_EQ(list.front(), 0);
  EXPECT_EQ(list.back(), num_elements - 1);

  // Forward traversal across multiple blocks
  int expected = 0;
  for (int val : list) {
    EXPECT_EQ(val, expected++);
  }
  EXPECT_EQ(expected, num_elements);

  // Backward traversal across multiple blocks
  auto it = list.end();
  for (int i = num_elements - 1; i >= 0; --i) {
    --it;
    EXPECT_EQ(*it, i);
  }
  EXPECT_TRUE(it == list.begin());
}

TEST(StableBlockListTest, SingleBlockReverseIteration) {
  StableBlockList<int, 4> list;
  list.push_back(1);
  list.push_back(2);

  auto it = list.rbegin();
  EXPECT_EQ(*it, 2);
  ++it;
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_TRUE(it == list.rend());
}

TEST(StableBlockListTest, SingleElementReverseIteration) {
  StableBlockList<int, 4> list;
  list.push_back(1);

  auto it = list.rbegin();
  EXPECT_EQ(*it, 1);
  ++it;
  EXPECT_TRUE(it == list.rend());
}

TEST(StableBlockListTest, EmptyReverseIteration) {
  StableBlockList<int, 4> list;

  auto it = list.rbegin();
  EXPECT_TRUE(it == list.rend());
}

TEST(StableBlockListTest, EraseLastElementOfMultiBlockList) {
  StableBlockList<int, 4> list;
  // Push 5 elements. Block capacity is 4.
  // Block 0 will have 4 elements (0..3).
  // Block 1 will have 1 element (4).
  for (int i = 0; i < 5; ++i) {
    list.push_back(i);
  }
  // Now erase the last element (4).
  auto it = std::prev(list.end());
  EXPECT_EQ(*it, 4);
  list.erase(it);

  // Check size
  EXPECT_EQ(list.size(), 4);
  // Check back
  EXPECT_EQ(list.back(), 3);

  // Verify we can still traverse
  int expected = 0;
  for (int val : list) {
    EXPECT_EQ(val, expected++);
  }
  EXPECT_EQ(expected, 4);
}

TEST(StableBlockListTest, BlockDeallocationAndReallocation) {
  StableBlockList<int, 2> list;
  list.push_back(1);
  list.push_back(2);
  list.push_back(3);  // Allocates 2nd block

  EXPECT_EQ(list.size(), 3);

  auto it = list.begin();  // points to 1
  list.erase(it);          // 1 is erased
  it = list.begin();       // points to 2
  list.erase(it);  // 2 is erased, 1st block becomes empty and is deallocated!

  EXPECT_EQ(list.size(), 1);
  EXPECT_EQ(list.front(), 3);

  // Now push back another element, it should go to the 2nd block if it has
  // space, or allocate a new block. Since 2nd block has '3' at index 0, it has
  // space at index 1.
  list.push_back(4);
  EXPECT_EQ(list.size(), 2);
  EXPECT_EQ(list.back(), 4);

  // Now 2nd block is full (3, 4). Push another to allocate a new block.
  list.push_back(5);
  EXPECT_EQ(list.size(), 3);
  EXPECT_EQ(list.back(), 5);

  std::vector<int> elements;
  for (int x : list) {
    elements.push_back(x);
  }
  EXPECT_THAT(elements, ::testing::ElementsAre(3, 4, 5));
}

TEST(StableBlockListTest, IteratorBoundaryCases) {
  StableBlockList<int> empty_list;

  // 1. Decrementing end() on empty list should return end() (covers line 505)
  auto empty_it = empty_list.end();
  --empty_it;
  EXPECT_TRUE(empty_it == empty_list.end());

  // 2. Decrementing a default-constructed iterator should return itself (covers
  // line 505)
  StableBlockList<int>::iterator default_it;
  --default_it;
  EXPECT_TRUE(default_it == StableBlockList<int>::iterator());

  // 3. Decrementing begin() on non-empty list should return end() (covers line
  // 530)
  StableBlockList<int> list;
  list.push_back(10);
  auto it = list.begin();
  --it;
  EXPECT_TRUE(it == list.end());
}

TEST(StableBlockListTest, ShrinkToFitReleasesMemory) {
  auto stats = std::make_shared<AllocStats>();
  {
    StableBlockList<int, 2, TrackingAllocator<int>> list(
        (TrackingAllocator<int>(stats)));

    // Push 2 elements. Capacity is 2, so this allocates 1 block.
    list.push_back(1);
    list.push_back(2);
    EXPECT_EQ(stats->allocs, 1);
    EXPECT_EQ(stats->deallocs, 0);

    // Push 3rd element. Allocates 2nd block.
    list.push_back(3);
    EXPECT_EQ(stats->allocs, 2);
    EXPECT_EQ(stats->deallocs, 0);

    // Erase 1st and 2nd elements. 1st block becomes empty and is unlinked.
    // It should be moved to the free list, NOT deallocated.
    auto it = list.begin();
    list.erase(it);
    it = list.begin();
    list.erase(it);

    EXPECT_EQ(stats->allocs, 2);
    EXPECT_EQ(stats->deallocs, 0);

    // Call shrink_to_fit(). This should deallocate the block in the free list.
    list.shrink_to_fit();
    EXPECT_EQ(stats->allocs, 2);
    EXPECT_EQ(stats->deallocs, 1);

    // Push 4th element. Goes to 2nd block (which contains 3 and has space).
    // No new allocation.
    list.push_back(4);
    EXPECT_EQ(stats->allocs, 2);
    EXPECT_EQ(stats->deallocs, 1);

    // Push 5th element. 2nd block is full [3, 4], allocates 3rd block.
    list.push_back(5);
    EXPECT_EQ(stats->allocs, 3);
    EXPECT_EQ(stats->deallocs, 1);
  }
  // Destructor deallocates the remaining active blocks (Block 2 and Block 3).
  EXPECT_EQ(stats->allocs, 3);
  EXPECT_EQ(stats->deallocs, 3);
}

TEST(StableBlockListTest, FreeListCorruptionRegressionTest) {
  // Uses a small block capacity (2) to easily force multi-block behavior.
  StableBlockList<int, 2> list;

  // 1. Initial state: block1 [10, 20] -> block2 [30, _]
  list.push_back(10);
  list.push_back(20);
  list.push_back(30);

  // 2. Erases elements in block1 to deallocate it.
  // block1 becomes empty and is moved to the free list.
  // If the compiler optimized away the write to block1->next during destroy,
  // block1->next will still point to block2 (which is active).
  auto it = list.begin();
  list.erase(it);  // erases 10
  it = list.begin();
  list.erase(it);  // erases 20

  // Now list is: block2 [30, _]
  // free_blocks -> block1

  // 3. Pushes 40. Goes to block2 (has space).
  // List: block2 [30, 40]
  list.push_back(40);

  // 4. Pushes 50. block2 is full. Needs a new block.
  // Reuses block1 from free_blocks.
  // If corrupted, free_blocks is set to block1->next (which points to block2).
  // List: block2 [30, 40] -> block1 [50, _]
  list.push_back(50);

  // 5. Pushes 60. Goes to block1 (has space).
  // List: block2 [30, 40] -> block1 [50, 60]
  list.push_back(60);

  // 6. Pushes 70. block1 is full. Needs a new block.
  // If free_blocks was corrupted to point to block2 (which is active),
  // it will reuse block2 and overwrite it, corrupting the list structure.
  list.push_back(70);

  // Verifies size and elements.
  // If corruption occurred, the list will be truncated or contain garbage.
  EXPECT_EQ(list.size(), 5);

  std::vector<int> elements;
  for (int x : list) {
    elements.push_back(x);
  }
  EXPECT_THAT(elements, ::testing::ElementsAre(30, 40, 50, 60, 70));
}

}  // namespace
}  // namespace quiche
