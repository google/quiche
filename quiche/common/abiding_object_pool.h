// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_ABIDING_OBJECT_POOL_H_
#define QUICHE_COMMON_ABIDING_OBJECT_POOL_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <new>
#include <type_traits>
#include <utility>

#include "absl/base/config.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"

#ifdef ABSL_HAVE_ADDRESS_SANITIZER
#include <sanitizer/asan_interface.h>
#endif

namespace quiche {

// A cache-friendly, thread-local slab object pool with automatic memory
// reclamation and compaction over time.
//
// Slabs are naturally power-of-two aligned for O(1) pointer-to-slab resolution.
// Allocations prioritize the most full non-full slab to concentrate object
// density, allowing emptier slabs to drain to zero and be released to the heap.
// Maintains 1 spare empty slab in reserve to prevent allocation hysteresis
// on slab boundaries.
template <typename T, size_t SlabSizeBytes = 64 * 1024>
class QUICHE_NO_EXPORT AbidingObjectPool {
  static_assert((SlabSizeBytes & (SlabSizeBytes - 1)) == 0,
                "Slab size must be a power of 2");

 public:
  struct Deleter {
    AbidingObjectPool* pool = nullptr;

    template <typename U>
    void operator()(U* ptr) const noexcept {
      if (ptr == nullptr) {
        return;
      }
      ptr->~U();
      QUICHE_DCHECK(pool != nullptr);
      if (pool != nullptr) {
        pool->Deallocate(static_cast<void*>(ptr));
      }
    }
  };

  template <typename U = T>
  using Ptr = std::unique_ptr<U, Deleter>;

  constexpr AbidingObjectPool() = default;

  explicit AbidingObjectPool(size_t initial_slabs) {
    for (size_t i = 0; i < initial_slabs; ++i) {
      Slab* slab = CreateSlab();
      PushFront(non_full_slabs_, slab);
    }
  }

  ~AbidingObjectPool() {
    while (non_full_slabs_ != nullptr) {
      Slab* slab = non_full_slabs_;
      RemoveFromList(non_full_slabs_, slab);
      DestroySlab(slab);
    }
    while (full_slabs_ != nullptr) {
      Slab* slab = full_slabs_;
      RemoveFromList(full_slabs_, slab);
      DestroySlab(slab);
    }
    if (spare_empty_slab_ != nullptr) {
      DestroySlab(spare_empty_slab_);
      spare_empty_slab_ = nullptr;
    }
  }

  // Non-copyable and non-movable: Outstanding Ptr instances hold a raw pointer
  // to `this` inside their Deleter, so the pool must remain pinned in memory.
  AbidingObjectPool(const AbidingObjectPool&) = delete;
  AbidingObjectPool& operator=(const AbidingObjectPool&) = delete;
  AbidingObjectPool(AbidingObjectPool&&) = delete;
  AbidingObjectPool& operator=(AbidingObjectPool&&) = delete;

  // Constructs an instance of Derived (defaults to T) using pooled memory.
  template <typename Derived = T, typename... Args>
  Ptr<Derived> Create(Args&&... args) {
    static_assert(std::is_same_v<T, Derived> || std::is_base_of_v<T, Derived>,
                  "Derived must inherit from or be T");
    static_assert(sizeof(Derived) <= kSlotSize,
                  "Derived exceeds allocated slot size");
    static_assert(alignof(Derived) <= kAlignment,
                  "Derived exceeds alignment constraint");

    void* slot = Allocate();
    Derived* object = ::new (slot) Derived(std::forward<Args>(args)...);
    return Ptr<Derived>(object, Deleter{this});
  }

  size_t total_capacity() const noexcept {
    return allocated_slabs_count_ * kSlotsPerSlab;
  }
  size_t allocated_slabs() const noexcept { return allocated_slabs_count_; }
  size_t num_free_slots() const noexcept { return total_free_slots_; }
  bool empty() const noexcept { return total_free_slots_ == total_capacity(); }

 private:
  // Intrusive node overlaid on unallocated slot memory.
  struct FreeNode {
    // If non-nullptr, points to the next free slot within the Slab.
    FreeNode* next;
  };

  struct Slab {
    // Pointers to the next/previous elements in the doubly-linked list.
    Slab* prev = nullptr;
    Slab* next = nullptr;
    // If non-nullptr, points to the first free slot within the Slab.
    FreeNode* free_head = nullptr;
    // The number of slots that have been handed out so far within this Slab.
    size_t allocated_high_watermark = 0;
    // The number of slots currently occupied by live objects.
    size_t live_objects = 0;
  };

  // Compile-time assertions and layout constants.

  // Disallow small objects; it would be space-inefficient.
  static_assert(sizeof(T) >= sizeof(FreeNode),
                "Objects stored in AbidingObjectPool should be at least the "
                "size of a pointer.");
  // Allocations must be aligned at least with `FreeNode`.
  static constexpr size_t kAlignment = std::max(alignof(T), alignof(FreeNode));
  // If the type to store is smaller than a pointer, this data structure will
  // waste memory.
  static constexpr size_t kRawSlotSize = sizeof(T);
  // Pads slot size to preserve alignment across consecutive array elements.
  static constexpr size_t kSlotSize =
      (kRawSlotSize + kAlignment - 1) & ~(kAlignment - 1);
  // The first slot is after the slab header.
  static constexpr size_t kFirstSlotOffset =
      (sizeof(Slab) + kAlignment - 1) & ~(kAlignment - 1);
  static constexpr size_t kSlotsPerSlab =
      (SlabSizeBytes > kFirstSlotOffset)
          ? (SlabSizeBytes - kFirstSlotOffset) / kSlotSize
          : 0;

  static_assert(kSlotsPerSlab > 0, "Slab size must fit at least one object");

  // Helper methods.

  // Calculates the memory address for a given slot index in a given Slab.
  static void* SlotAddress(Slab* slab, size_t index) {
    auto* base = reinterpret_cast<std::byte*>(slab);
    return static_cast<void*>(base + kFirstSlotOffset + (index * kSlotSize));
  }

  // Pushes a Slab on the front of a doubly-linked list.
  static void PushFront(Slab*& head, Slab* slab) {
    slab->prev = nullptr;
    slab->next = head;
    if (head != nullptr) {
      head->prev = slab;
    }
    head = slab;
  }

  // Removes a Slab from a doubly-linked list.
  static void RemoveFromList(Slab*& head, Slab* slab) {
    if (slab->prev != nullptr) {
      slab->prev->next = slab->next;
    } else {
      head = slab->next;
    }
    if (slab->next != nullptr) {
      slab->next->prev = slab->prev;
    }
    slab->prev = nullptr;
    slab->next = nullptr;
  }

  // Swaps a Slab in a doubly-linked list with the next element.
  static void SwapWithNext(Slab*& head, Slab* a) {
    Slab* b = a->next;
    if (b == nullptr) {
      return;
    }
    Slab* prev = a->prev;
    Slab* next = b->next;

    if (prev != nullptr) {
      prev->next = b;
    } else {
      head = b;
    }
    b->prev = prev;

    b->next = a;
    a->prev = b;

    a->next = next;
    if (next != nullptr) {
      next->prev = a;
    }
  }

  // Returns the next available slot, allocating a new Slab if necessary.
  void* Allocate() {
    if (non_full_slabs_ == nullptr) {
      Slab* slab = nullptr;
      if (spare_empty_slab_ != nullptr) {
        slab = spare_empty_slab_;
        spare_empty_slab_ = nullptr;
      } else {
        slab = CreateSlab();
      }
      PushFront(non_full_slabs_, slab);
    }
    Slab* slab = non_full_slabs_;
    void* slot = nullptr;

    // 1. Reuse from intrusive freelist if available.
    if (slab->free_head != nullptr) {
      FreeNode* node = slab->free_head;

#ifdef ABSL_HAVE_ADDRESS_SANITIZER
      ASAN_UNPOISON_MEMORY_REGION(node, kSlotSize);
#endif

      slab->free_head = node->next;
      slot = static_cast<void*>(node);
    } else {
      // 2. Bump-allocate from uninitialized slot range.
      QUICHE_DCHECK(slab->allocated_high_watermark < kSlotsPerSlab);
      slot = SlotAddress(slab, slab->allocated_high_watermark);

#ifdef ABSL_HAVE_ADDRESS_SANITIZER
      ASAN_UNPOISON_MEMORY_REGION(slot, kSlotSize);
#endif

      ++slab->allocated_high_watermark;
    }

    ++slab->live_objects;
    --total_free_slots_;

    // If slab reached capacity, move it to full_slabs_.
    if (slab->live_objects == kSlotsPerSlab) {
      RemoveFromList(non_full_slabs_, slab);
      PushFront(full_slabs_, slab);
    }

    return slot;
  }

  // Deallocates a slot. May result in the owning Slab being freed.
  void Deallocate(void* ptr) noexcept {
    // The owning slab can be found with a simple bitmask operation.
    Slab* slab = reinterpret_cast<Slab*>(reinterpret_cast<uintptr_t>(ptr) &
                                         ~(SlabSizeBytes - 1));
    QUICHE_DCHECK(slab != nullptr);

    auto* node = static_cast<FreeNode*>(ptr);
    node->next = slab->free_head;
    slab->free_head = node;

#ifdef ABSL_HAVE_ADDRESS_SANITIZER
    ASAN_POISON_MEMORY_REGION(ptr, kSlotSize);
#endif

    const bool was_full = (slab->live_objects == kSlotsPerSlab);
    --slab->live_objects;
    ++total_free_slots_;

    if (slab->live_objects == 0) {
      // Slab has no more live objects.
      if (was_full) {
        RemoveFromList(full_slabs_, slab);
      } else {
        RemoveFromList(non_full_slabs_, slab);
      }
      if (spare_empty_slab_ == nullptr) {
        spare_empty_slab_ = slab;
      } else {
        DestroySlab(slab);
      }
      return;
    }

    if (was_full) {
      // Move from full_slabs_ to front of non_full_slabs_ (as the fullest
      // partial slab).
      RemoveFromList(full_slabs_, slab);
      PushFront(non_full_slabs_, slab);
    } else {
      // Keep non_full_slabs_ ordered by descending live_objects.
      while (slab->next != nullptr &&
             slab->live_objects < slab->next->live_objects) {
        SwapWithNext(non_full_slabs_, slab);
      }
    }
  }

  // Allocates memory for and initializes a Slab.
  Slab* CreateSlab() {
    void* memory =
        ::operator new(SlabSizeBytes, std::align_val_t(SlabSizeBytes));
    Slab* slab = ::new (memory) Slab();

#ifdef ABSL_HAVE_ADDRESS_SANITIZER
    ASAN_POISON_MEMORY_REGION(
        reinterpret_cast<std::byte*>(memory) + kFirstSlotOffset,
        SlabSizeBytes - kFirstSlotOffset);
#endif

    ++allocated_slabs_count_;
    total_free_slots_ += kSlotsPerSlab;
    return slab;
  }

  // Deallocates memory for a given Slab.
  void DestroySlab(Slab* slab) noexcept {
    --allocated_slabs_count_;
    total_free_slots_ -= kSlotsPerSlab;
    slab->~Slab();
    ::operator delete(slab, std::align_val_t(SlabSizeBytes));
  }

  Slab* non_full_slabs_ = nullptr;
  Slab* full_slabs_ = nullptr;
  Slab* spare_empty_slab_ = nullptr;
  size_t allocated_slabs_count_ = 0;
  size_t total_free_slots_ = 0;
};

}  // namespace quiche

#endif  // QUICHE_COMMON_ABIDING_OBJECT_POOL_H_
