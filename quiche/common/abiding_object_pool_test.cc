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

TEST(AbidingObjectPoolTest, ConstinitStaticInitialization) {
  static constinit AbidingObjectPool<int64_t, 256> kPool;
  EXPECT_TRUE(kPool.empty());
  EXPECT_EQ(kPool.allocated_slabs(), 0u);
}

TEST(AbidingObjectPoolTest, SingleSlotPerSlab) {
  struct LargeObject {
    uint64_t value;
    char padding[184];
  };
  // Slab header is 40 bytes; 256 - 40 = 216 bytes fits exactly 1 LargeObject.
  constexpr size_t kSlabSize = 256;
  AbidingObjectPool<LargeObject, kSlabSize> pool;

  std::vector<AbidingObjectPool<LargeObject, kSlabSize>::Ptr<LargeObject>> ptrs;
  for (uint64_t i = 0; i < 5; ++i) {
    ptrs.push_back(pool.Create(LargeObject{i, {}}));
  }
  EXPECT_EQ(pool.allocated_slabs(), 5u);
  EXPECT_EQ(pool.total_capacity(), 5u);
  EXPECT_EQ(pool.num_free_slots(), 0u);

  // Deallocate in arbitrary order: first retains 1 spare slab, rest destroy.
  ptrs[2].reset();
  EXPECT_EQ(pool.allocated_slabs(), 5u);
  EXPECT_EQ(pool.num_free_slots(), 1u);

  ptrs[0].reset();
  EXPECT_EQ(pool.allocated_slabs(), 4u);
  EXPECT_EQ(pool.num_free_slots(), 1u);

  // Reallocating reuses the spare empty slab without creating a new one.
  ptrs[0] = pool.Create(LargeObject{99, {}});
  EXPECT_EQ(pool.allocated_slabs(), 4u);
  EXPECT_EQ(pool.num_free_slots(), 0u);
  EXPECT_EQ(ptrs[0]->value, 99u);

  ptrs.clear();
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 1u);
}

TEST(AbidingObjectPoolTest, SingleSlotPerSlabPreallocation) {
  struct LargeObject {
    uint64_t value;
    char padding[184];
  };
  constexpr size_t kSlabSize = 256;
  AbidingObjectPool<LargeObject, kSlabSize> pool(3);
  EXPECT_EQ(pool.allocated_slabs(), 3u);
  EXPECT_EQ(pool.total_capacity(), 3u);
  EXPECT_EQ(pool.num_free_slots(), 3u);

  auto p1 = pool.Create(LargeObject{1, {}});
  auto p2 = pool.Create(LargeObject{2, {}});
  auto p3 = pool.Create(LargeObject{3, {}});
  EXPECT_EQ(pool.allocated_slabs(), 3u);
  EXPECT_EQ(pool.num_free_slots(), 0u);

  p1.reset();
  p2.reset();
  p3.reset();
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 1u);
}

TEST(AbidingObjectPoolTest, DeallocateNullptrIsNoOp) {
  AbidingObjectPool<int64_t, 256> pool;
  pool.Deallocate(nullptr);
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 0u);
}

TEST(AbidingObjectPoolTest, MultiSlabBucketedChurnAndCompaction) {
  // 27 slots/slab (> 16 buckets), exercising quantized bucket transitions
  // across many slabs (40-byte Slab header + 27 * 8-byte slots = 256 bytes).
  constexpr size_t kSlabSize = 256;
  AbidingObjectPool<int64_t, kSlabSize> pool;

  constexpr size_t kNumObjects = 27 * 100;
  std::vector<AbidingObjectPool<int64_t, kSlabSize>::Ptr<int64_t>> objects;
  objects.reserve(kNumObjects);
  for (size_t i = 0; i < kNumObjects; ++i) {
    objects.push_back(pool.Create(static_cast<int64_t>(i)));
  }
  EXPECT_EQ(pool.allocated_slabs(), 100u);
  EXPECT_EQ(pool.num_free_slots(), 0u);

  // Deallocate half the objects in a strided pattern across all slabs.
  for (size_t i = 0; i < kNumObjects; i += 2) {
    objects[i].reset();
  }
  EXPECT_EQ(pool.num_free_slots(), kNumObjects / 2);

  // Reallocate half as many objects; they should fill higher-occupancy buckets
  // without allocating new slabs.
  for (size_t i = 0; i < kNumObjects / 2; i += 2) {
    objects[i] = pool.Create(static_cast<int64_t>(i));
  }
  EXPECT_LE(pool.allocated_slabs(), 100u);

  // Free everything and verify compaction back to 1 spare slab.
  objects.clear();
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 1u);
}

TEST(AbidingObjectPoolTest, SmallSlabPrefersFullerBucket) {
  // 40-byte header + 4 * 48-byte objects = 232 <= 256 bytes -> 4 slots/slab.
  struct MediumObject {
    uint64_t a[6];
  };
  constexpr size_t kSlabSize = 256;
  AbidingObjectPool<MediumObject, kSlabSize> pool;

  // Fill 2 slabs (8 objects).
  std::vector<AbidingObjectPool<MediumObject, kSlabSize>::Ptr<MediumObject>>
      objs;
  for (int i = 0; i < 8; ++i) {
    objs.push_back(pool.Create(MediumObject{{static_cast<uint64_t>(i)}}));
  }
  EXPECT_EQ(pool.allocated_slabs(), 2u);

  // Leave 1 object in slab 0 (bucket 1) and 3 objects in slab 1 (bucket 3).
  objs[0].reset();
  objs[1].reset();
  objs[2].reset();
  objs[4].reset();
  EXPECT_EQ(pool.num_free_slots(), 4u);

  // Next allocation must go to slab 1 (the fuller bucket), filling it to 4/4,
  // before touching slab 0.
  objs[4] = pool.Create(MediumObject{{42}});
  // Now slab 1 is full (4/4) and slab 0 has 1/4. Freeing slab 0's remaining
  // object should drain slab 0 to spare_empty_slab_.
  objs[3].reset();
  EXPECT_EQ(pool.allocated_slabs(), 2u);
  EXPECT_EQ(pool.num_free_slots(), 4u);

  objs.clear();
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 1u);
}

TEST(AbidingObjectPoolTest, TwoSlotsPerSlabWithPreallocation) {
  // 40-byte header + 2 * 96-byte objects = 232 <= 256 bytes -> 2 slots/slab.
  struct TwoPerSlabObject {
    uint64_t a[12];
  };
  constexpr size_t kSlabSize = 256;
  AbidingObjectPool<TwoPerSlabObject, kSlabSize> pool(2);
  EXPECT_EQ(pool.allocated_slabs(), 2u);
  EXPECT_EQ(pool.total_capacity(), 4u);

  auto p1 = pool.Create();
  auto p2 = pool.Create();
  // Both allocations should land in the same slab before touching the second.
  auto p3 = pool.Create();
  EXPECT_EQ(pool.allocated_slabs(), 2u);
  EXPECT_EQ(pool.num_free_slots(), 1u);

  // Freeing p3 leaves slab 1 empty (drained to spare_empty_slab_), while slab 0
  // stays full with p1 and p2.
  p3.reset();
  EXPECT_EQ(pool.allocated_slabs(), 2u);
  EXPECT_EQ(pool.num_free_slots(), 2u);

  p1.reset();
  p2.reset();
  EXPECT_TRUE(pool.empty());
  EXPECT_EQ(pool.allocated_slabs(), 1u);
}

}  // namespace
}  // namespace test
}  // namespace quiche
