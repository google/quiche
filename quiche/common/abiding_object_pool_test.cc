// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/abiding_object_pool.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "quiche/common/platform/api/quiche_test.h"

namespace quiche {
namespace test {
namespace {

struct DestructionTracker {
  int value;
  int* destruction_count;

  DestructionTracker(int val, int* d_count)
      : value(val), destruction_count(d_count) {}

  ~DestructionTracker() {
    if (destruction_count != nullptr) {
      ++(*destruction_count);
    }
  }
};

class Base {
 public:
  virtual ~Base() = default;
  virtual std::string Name() const = 0;

 protected:
  const char* name_ = nullptr;
  int* destruction_count_ = nullptr;
};

class Derived : public Base {
 public:
  explicit Derived(const char* name, int* destruction_count = nullptr) {
    name_ = name;
    destruction_count_ = destruction_count;
  }

  ~Derived() override {
    if (destruction_count_ != nullptr) {
      ++(*destruction_count_);
    }
  }

  std::string Name() const override { return name_ != nullptr ? name_ : ""; }
};

struct alignas(64) OveralignedStruct {
  uint64_t a;
  uint64_t b;
};

TEST(AbidingObjectPoolTest, BasicAllocationAndDestruction) {
  AbidingObjectPool<DestructionTracker, 1024> pool;
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 0u);
  EXPECT_EQ(pool.total_capacity(), 0u);

  int destructions = 0;
  {
    auto ptr = pool.Create(42, &destructions);
    ASSERT_NE(ptr, nullptr);
    EXPECT_EQ(ptr->value, 42);
    EXPECT_FALSE(pool.empty());
    EXPECT_EQ(pool.allocated_slabs(), 1u);
    EXPECT_GT(pool.total_capacity(), 0u);
    EXPECT_EQ(destructions, 0);
  }

  EXPECT_EQ(destructions, 1);
  EXPECT_TRUE(pool.empty());
  // 1 spare empty slab is retained in reserve.
  EXPECT_EQ(pool.allocated_slabs(), 1u);
  EXPECT_EQ(pool.num_free_slots(), pool.total_capacity());
}

TEST(AbidingObjectPoolTest, FreelistReuse) {
  AbidingObjectPool<int64_t, 256> pool;
  void* first_address = nullptr;

  {
    auto ptr = pool.Create(100);
    first_address = static_cast<void*>(ptr.get());
    EXPECT_EQ(*ptr, 100);
  }

  // The next allocation should reuse the most recently deallocated slot (LIFO).
  {
    auto ptr = pool.Create(200);
    EXPECT_EQ(static_cast<void*>(ptr.get()), first_address);
    EXPECT_EQ(*ptr, 200);
  }
}

TEST(AbidingObjectPoolTest, PolymorphicDerivedCreation) {
  AbidingObjectPool<Base, 1024> pool;
  int destructions = 0;

  {
    AbidingObjectPool<Base, 1024>::Ptr<Derived> derived_ptr =
        pool.Create<Derived>("quiche_test", &destructions);
    ASSERT_NE(derived_ptr, nullptr);
    EXPECT_EQ(derived_ptr->Name(), "quiche_test");
    EXPECT_EQ(destructions, 0);
  }

  EXPECT_EQ(destructions, 1);
}

TEST(AbidingObjectPoolTest, AutomaticSlabDrainingAndCompaction) {
  constexpr size_t kSlabSize = 256;
  AbidingObjectPool<int64_t, kSlabSize> pool;

  std::vector<AbidingObjectPool<int64_t, kSlabSize>::Ptr<int64_t>> objects;

  // Allocate enough objects to span multiple slabs (5 slabs at ~27 slots/slab).
  for (int i = 0; i < 120; ++i) {
    objects.push_back(pool.Create(i));
  }

  size_t peak_slabs = pool.allocated_slabs();
  EXPECT_GE(peak_slabs, 4u);

  // Free most objects, leaving 20 active (fits within 1 slab).
  objects.resize(20);

  // Excess drained slabs are destroyed, leaving 1 active slab + 1 spare slab.
  EXPECT_LT(pool.allocated_slabs(), peak_slabs);
  EXPECT_EQ(pool.allocated_slabs(), 2u);

  // Free all remaining objects.
  objects.clear();
  // Exactly 1 spare empty slab is retained in cache.
  EXPECT_EQ(pool.allocated_slabs(), 1u);
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.num_free_slots(), pool.total_capacity());
}

TEST(AbidingObjectPoolTest, Preallocation) {
  constexpr size_t kInitialSlabs = 3;
  constexpr size_t kSlabSize = 512;
  AbidingObjectPool<int64_t, kSlabSize> pool(kInitialSlabs);

  EXPECT_EQ(pool.allocated_slabs(), kInitialSlabs);
  EXPECT_GT(pool.total_capacity(), 0u);
  EXPECT_EQ(pool.num_free_slots(), pool.total_capacity());
  EXPECT_TRUE(pool.empty());
}

TEST(AbidingObjectPoolTest, MovePtrMaintainsDeleter) {
  AbidingObjectPool<int64_t, 256> pool;
  auto ptr1 = pool.Create(12345);
  ASSERT_NE(ptr1, nullptr);

  auto ptr2 = std::move(ptr1);
  EXPECT_EQ(ptr1, nullptr);
  ASSERT_NE(ptr2, nullptr);
  EXPECT_EQ(*ptr2, 12345);
  EXPECT_FALSE(pool.empty());

  ptr2.reset();
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 1u);
}

TEST(AbidingObjectPoolTest, OveralignedObject) {
  AbidingObjectPool<OveralignedStruct, 1024> pool;
  auto ptr = pool.Create();
  ASSERT_NE(ptr, nullptr);

  auto address = reinterpret_cast<uintptr_t>(ptr.get());
  EXPECT_EQ(address % alignof(OveralignedStruct), 0u);
}

constinit thread_local AbidingObjectPool<int64_t, 256> kConstinitPool;

TEST(AbidingObjectPoolTest, ConstinitThreadLocal) {
  auto ptr = kConstinitPool.Create(42);
  ASSERT_NE(ptr, nullptr);
  EXPECT_EQ(*ptr, 42);
}

}  // namespace
}  // namespace test
}  // namespace quiche
