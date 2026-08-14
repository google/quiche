// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Differential property-based fuzz test comparing quiche::StableBlockList
// against std::list.
//
// The test executes randomized sequences of container operations (push_back,
// emplace_back, insert at end, single-element erase, range erase including
// empty ranges, pop_front, pop_back, clear, shrink_to_fit, move, and swap)
// across various block capacities (1, 2, 4, 16, 32, 64).
//
// After every operation, it rigorously verifies container invariants:
//  - Element order, empty(), and size() parity with std::list.
//  - Forward and reverse iterator traversal parity.
//  - Bidirectional iterator step navigation across erased holes and block
//    boundaries.
//  - Pointer and reference stability: surviving element addresses remain
//    stable across arbitrary insertions, deletions, block deallocations, and
//    memory shrink operations.
//  - Iterator stability: saved iterators to surviving elements remain valid,
//    dereference to the correct values, and step correctly to surviving
//    neighbors.

#include <cstddef>
#include <iterator>
#include <list>
#include <utility>
#include <variant>
#include <vector>

#include "absl/functional/overload.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/stable_block_list.h"

namespace quiche {
namespace {

using ::fuzztest::Arbitrary;
using ::fuzztest::Domain;
using ::fuzztest::VariantOf;
using ::fuzztest::VectorOf;

struct PushBackOp {
  int value;
};
struct EmplaceBackOp {
  int value;
};
struct InsertEndOp {
  int value;
};
struct EraseIndexOp {
  size_t index;
};
struct EraseRangeOp {
  size_t start_index;
  size_t count;
};
struct PopFrontOp {};
struct PopBackOp {};
struct ClearOp {};
struct ShrinkToFitOp {};
struct MoveOp {};
struct SwapOp {};

using Op = std::variant<PushBackOp, EmplaceBackOp, InsertEndOp, EraseIndexOp,
                        EraseRangeOp, PopFrontOp, PopBackOp, ClearOp,
                        ShrinkToFitOp, MoveOp, SwapOp>;

Domain<Op> AnyOpDomain() {
  return VariantOf(Arbitrary<PushBackOp>(), Arbitrary<EmplaceBackOp>(),
                   Arbitrary<InsertEndOp>(), Arbitrary<EraseIndexOp>(),
                   Arbitrary<EraseRangeOp>(), Arbitrary<PopFrontOp>(),
                   Arbitrary<PopBackOp>(), Arbitrary<ClearOp>(),
                   Arbitrary<ShrinkToFitOp>(), Arbitrary<MoveOp>(),
                   Arbitrary<SwapOp>());
}

template <size_t BlockCapacity>
struct ElementTracker {
  int value;
  const int* sbl_ptr;
  typename StableBlockList<int, BlockCapacity>::iterator sbl_it;
  const int* std_ptr;
  std::list<int>::iterator std_it;
};

template <size_t BlockCapacity>
void VerifyInvariants(
    const StableBlockList<int, BlockCapacity>& sbl,
    const std::list<int>& std_list,
    const std::vector<ElementTracker<BlockCapacity>>& active_trackers) {
  // 1. Size & Empty parity
  ASSERT_EQ(sbl.size(), std_list.size());
  ASSERT_EQ(sbl.size(), active_trackers.size());
  ASSERT_EQ(sbl.empty(), std_list.empty());
  ASSERT_EQ(sbl.empty(), active_trackers.empty());

  if (sbl.empty()) {
    EXPECT_TRUE(sbl.begin() == sbl.end());
    EXPECT_TRUE(sbl.cbegin() == sbl.cend());
    EXPECT_TRUE(sbl.rbegin() == sbl.rend());
    EXPECT_TRUE(sbl.crbegin() == sbl.crend());
    return;
  }

  // 2. Front & Back parity
  EXPECT_EQ(sbl.front(), std_list.front());
  EXPECT_EQ(sbl.front(), active_trackers.front().value);
  EXPECT_EQ(sbl.back(), std_list.back());
  EXPECT_EQ(sbl.back(), active_trackers.back().value);

  // 3. Forward iterator traversal and element order
  auto sbl_it = sbl.begin();
  auto std_it = std_list.begin();
  size_t idx = 0;
  while (sbl_it != sbl.end() && std_it != std_list.end()) {
    EXPECT_EQ(*sbl_it, *std_it);
    EXPECT_EQ(*sbl_it, active_trackers[idx].value);
    EXPECT_EQ(&*sbl_it, active_trackers[idx].sbl_ptr);
    EXPECT_EQ(&*std_it, active_trackers[idx].std_ptr);
    EXPECT_TRUE(sbl_it == active_trackers[idx].sbl_it);
    EXPECT_TRUE(std_it == active_trackers[idx].std_it);
    ++sbl_it;
    ++std_it;
    ++idx;
  }
  EXPECT_TRUE(sbl_it == sbl.end());
  EXPECT_TRUE(std_it == std_list.end());
  EXPECT_EQ(idx, active_trackers.size());

  // 4. Const forward iterator traversal
  auto sbl_cit = sbl.cbegin();
  auto std_cit = std_list.cbegin();
  size_t cidx = 0;
  while (sbl_cit != sbl.cend() && std_cit != std_list.cend()) {
    EXPECT_EQ(*sbl_cit, *std_cit);
    EXPECT_EQ(*sbl_cit, active_trackers[cidx].value);
    EXPECT_EQ(&*sbl_cit, active_trackers[cidx].sbl_ptr);
    EXPECT_EQ(&*std_cit, active_trackers[cidx].std_ptr);
    ++sbl_cit;
    ++std_cit;
    ++cidx;
  }
  EXPECT_TRUE(sbl_cit == sbl.cend());
  EXPECT_TRUE(std_cit == std_list.cend());
  EXPECT_EQ(cidx, active_trackers.size());

  // 5. Reverse iterator traversal
  auto sbl_rit = sbl.rbegin();
  auto std_rit = std_list.rbegin();
  size_t ridx = active_trackers.size();
  while (sbl_rit != sbl.rend() && std_rit != std_list.rend()) {
    --ridx;
    EXPECT_EQ(*sbl_rit, *std_rit);
    EXPECT_EQ(*sbl_rit, active_trackers[ridx].value);
    EXPECT_EQ(&*sbl_rit, active_trackers[ridx].sbl_ptr);
    EXPECT_EQ(&*std_rit, active_trackers[ridx].std_ptr);
    ++sbl_rit;
    ++std_rit;
  }
  EXPECT_TRUE(sbl_rit == sbl.rend());
  EXPECT_TRUE(std_rit == std_list.rend());
  EXPECT_EQ(ridx, 0);

  // 6. Const reverse iterator traversal
  auto sbl_crit = sbl.crbegin();
  auto std_crit = std_list.crbegin();
  size_t cridx = active_trackers.size();
  while (sbl_crit != sbl.crend() && std_crit != std_list.crend()) {
    --cridx;
    EXPECT_EQ(*sbl_crit, *std_crit);
    EXPECT_EQ(*sbl_crit, active_trackers[cridx].value);
    EXPECT_EQ(&*sbl_crit, active_trackers[cridx].sbl_ptr);
    EXPECT_EQ(&*std_crit, active_trackers[cridx].std_ptr);
    ++sbl_crit;
    ++std_crit;
  }
  EXPECT_TRUE(sbl_crit == sbl.crend());
  EXPECT_TRUE(std_crit == std_list.crend());
  EXPECT_EQ(cridx, 0);

  // 7. Bidirectional stepping (decrementing from end())
  {
    auto b_sbl_it = sbl.end();
    auto b_std_it = std_list.end();
    size_t b_idx = active_trackers.size();
    do {
      --b_sbl_it;
      --b_std_it;
      --b_idx;
      EXPECT_EQ(*b_sbl_it, *b_std_it);
      EXPECT_EQ(*b_sbl_it, active_trackers[b_idx].value);
      EXPECT_EQ(&*b_sbl_it, active_trackers[b_idx].sbl_ptr);
      EXPECT_EQ(&*b_std_it, active_trackers[b_idx].std_ptr);
    } while (b_sbl_it != sbl.begin() && b_std_it != std_list.begin());
    EXPECT_TRUE(b_sbl_it == sbl.begin());
    EXPECT_TRUE(b_std_it == std_list.begin());
    EXPECT_EQ(b_idx, 0);
  }

  // 8. Individual pointer & iterator stability and neighbor connectivity
  for (size_t i = 0; i < active_trackers.size(); ++i) {
    const auto& tracker = active_trackers[i];
    EXPECT_EQ(*tracker.sbl_ptr, tracker.value);
    EXPECT_EQ(*tracker.std_ptr, tracker.value);
    EXPECT_EQ(*tracker.sbl_it, tracker.value);
    EXPECT_EQ(*tracker.std_it, tracker.value);
    EXPECT_EQ(&*tracker.sbl_it, tracker.sbl_ptr);
    EXPECT_EQ(&*tracker.std_it, tracker.std_ptr);

    if (i + 1 < active_trackers.size()) {
      EXPECT_TRUE(std::next(tracker.sbl_it) == active_trackers[i + 1].sbl_it);
      EXPECT_TRUE(std::next(tracker.std_it) == active_trackers[i + 1].std_it);
    } else {
      EXPECT_TRUE(std::next(tracker.sbl_it) == sbl.end());
      EXPECT_TRUE(std::next(tracker.std_it) == std_list.end());
    }

    if (i > 0) {
      EXPECT_TRUE(std::prev(tracker.sbl_it) == active_trackers[i - 1].sbl_it);
      EXPECT_TRUE(std::prev(tracker.std_it) == active_trackers[i - 1].std_it);
    } else {
      EXPECT_TRUE(tracker.sbl_it == sbl.begin());
      EXPECT_TRUE(tracker.std_it == std_list.begin());
    }
  }
}

template <size_t BlockCapacity>
void StableBlockListMatchesStdList(const std::vector<Op>& ops) {
  StableBlockList<int, BlockCapacity> sbl;
  std::list<int> std_list;
  std::vector<ElementTracker<BlockCapacity>> active_trackers;

  StableBlockList<int, BlockCapacity> secondary_sbl;
  std::list<int> secondary_std;
  std::vector<ElementTracker<BlockCapacity>> secondary_trackers;

  VerifyInvariants(sbl, std_list, active_trackers);

  for (const Op& op : ops) {
    std::visit(
        absl::Overload{
            [&](const PushBackOp& op) {
              sbl.push_back(op.value);
              std_list.push_back(op.value);
              auto sbl_it = std::prev(sbl.end());
              auto std_it = std::prev(std_list.end());
              active_trackers.push_back(
                  {op.value, &*sbl_it, sbl_it, &*std_it, std_it});
            },
            [&](const EmplaceBackOp& op) {
              auto sbl_it = sbl.emplace(sbl.end(), op.value);
              auto std_it = std_list.emplace(std_list.end(), op.value);
              active_trackers.push_back(
                  {op.value, &*sbl_it, sbl_it, &*std_it, std_it});
            },
            [&](const InsertEndOp& op) {
              auto sbl_it = sbl.insert(sbl.end(), op.value);
              auto std_it = std_list.insert(std_list.end(), op.value);
              active_trackers.push_back(
                  {op.value, &*sbl_it, sbl_it, &*std_it, std_it});
            },
            [&](const EraseIndexOp& op) {
              if (active_trackers.empty()) {
                return;
              }
              size_t target_idx = op.index % active_trackers.size();
              auto sbl_ret = sbl.erase(active_trackers[target_idx].sbl_it);
              auto std_ret = std_list.erase(active_trackers[target_idx].std_it);
              if (target_idx + 1 < active_trackers.size()) {
                EXPECT_EQ(*sbl_ret, *std_ret);
                EXPECT_EQ(*sbl_ret, active_trackers[target_idx + 1].value);
              } else {
                EXPECT_TRUE(sbl_ret == sbl.end());
                EXPECT_TRUE(std_ret == std_list.end());
              }
              active_trackers.erase(active_trackers.begin() + target_idx);
            },
            [&](const EraseRangeOp& op) {
              if (active_trackers.empty()) {
                auto sbl_ret = sbl.erase(sbl.begin(), sbl.end());
                auto std_ret = std_list.erase(std_list.begin(), std_list.end());
                EXPECT_TRUE(sbl_ret == sbl.end());
                EXPECT_TRUE(std_ret == std_list.end());
                return;
              }
              size_t start = op.start_index % (active_trackers.size() + 1);
              size_t max_count = active_trackers.size() - start;
              size_t num_to_erase = op.count % (max_count + 1);

              auto sbl_first = (start == active_trackers.size())
                                   ? sbl.end()
                                   : active_trackers[start].sbl_it;
              auto std_first = (start == active_trackers.size())
                                   ? std_list.end()
                                   : active_trackers[start].std_it;
              auto sbl_last =
                  (start + num_to_erase == active_trackers.size())
                      ? sbl.end()
                      : active_trackers[start + num_to_erase].sbl_it;
              auto std_last =
                  (start + num_to_erase == active_trackers.size())
                      ? std_list.end()
                      : active_trackers[start + num_to_erase].std_it;
              auto sbl_ret = sbl.erase(sbl_first, sbl_last);
              auto std_ret = std_list.erase(std_first, std_last);
              if (start + num_to_erase < active_trackers.size()) {
                EXPECT_EQ(*sbl_ret, *std_ret);
                EXPECT_EQ(*sbl_ret,
                          active_trackers[start + num_to_erase].value);
              } else {
                EXPECT_TRUE(sbl_ret == sbl.end());
                EXPECT_TRUE(std_ret == std_list.end());
              }
              active_trackers.erase(
                  active_trackers.begin() + start,
                  active_trackers.begin() + start + num_to_erase);
            },
            [&](const PopFrontOp&) {
              if (active_trackers.empty()) {
                return;
              }
              sbl.erase(sbl.begin());
              std_list.pop_front();
              active_trackers.erase(active_trackers.begin());
            },
            [&](const PopBackOp&) {
              if (active_trackers.empty()) {
                return;
              }
              sbl.erase(std::prev(sbl.end()));
              std_list.pop_back();
              active_trackers.pop_back();
            },
            [&](const ClearOp&) {
              sbl.clear();
              std_list.clear();
              active_trackers.clear();
            },
            [&](const ShrinkToFitOp&) { sbl.shrink_to_fit(); },
            [&](const MoveOp&) {
              StableBlockList<int, BlockCapacity> temp_sbl = std::move(sbl);
              std::list<int> temp_std = std::move(std_list);
              sbl = std::move(temp_sbl);
              std_list = std::move(temp_std);
            },
            [&](const SwapOp&) {
              sbl.swap(secondary_sbl);
              std_list.swap(secondary_std);
              active_trackers.swap(secondary_trackers);
            },
        },
        op);

    VerifyInvariants(sbl, std_list, active_trackers);
    VerifyInvariants(secondary_sbl, secondary_std, secondary_trackers);
  }
}

void StableBlockListMatchesStdListCap1(
    const std::vector<Op>& ops) {  // NOLINT(readability-redundant-declaration)
  StableBlockListMatchesStdList<1>(ops);
}

void StableBlockListMatchesStdListCap2(
    const std::vector<Op>& ops) {  // NOLINT(readability-redundant-declaration)
  StableBlockListMatchesStdList<2>(ops);
}

void StableBlockListMatchesStdListCap4(
    const std::vector<Op>& ops) {  // NOLINT(readability-redundant-declaration)
  StableBlockListMatchesStdList<4>(ops);
}

void StableBlockListMatchesStdListCap16(
    const std::vector<Op>& ops) {  // NOLINT(readability-redundant-declaration)
  StableBlockListMatchesStdList<16>(ops);
}

void StableBlockListMatchesStdListCap32(
    const std::vector<Op>& ops) {  // NOLINT(readability-redundant-declaration)
  StableBlockListMatchesStdList<32>(ops);
}

void StableBlockListMatchesStdListCap64(
    const std::vector<Op>& ops) {  // NOLINT(readability-redundant-declaration)
  StableBlockListMatchesStdList<64>(ops);
}

FUZZ_TEST(StableBlockListFuzzTest,  // NOLINT(readability-redundant-declaration)
          StableBlockListMatchesStdListCap1)
    .WithDomains(VectorOf(AnyOpDomain()).WithMinSize(100));

FUZZ_TEST(StableBlockListFuzzTest,  // NOLINT(readability-redundant-declaration)
          StableBlockListMatchesStdListCap2)
    .WithDomains(VectorOf(AnyOpDomain()).WithMinSize(100));

FUZZ_TEST(StableBlockListFuzzTest,  // NOLINT(readability-redundant-declaration)
          StableBlockListMatchesStdListCap4)
    .WithDomains(VectorOf(AnyOpDomain()).WithMinSize(100));

FUZZ_TEST(StableBlockListFuzzTest,  // NOLINT(readability-redundant-declaration)
          StableBlockListMatchesStdListCap16)
    .WithDomains(VectorOf(AnyOpDomain()).WithMinSize(100));

FUZZ_TEST(StableBlockListFuzzTest,  // NOLINT(readability-redundant-declaration)
          StableBlockListMatchesStdListCap32)
    .WithDomains(VectorOf(AnyOpDomain()).WithMinSize(100));

FUZZ_TEST(StableBlockListFuzzTest,  // NOLINT(readability-redundant-declaration)
          StableBlockListMatchesStdListCap64)
    .WithDomains(VectorOf(AnyOpDomain()).WithMinSize(100));

TEST(StableBlockListFuzzTest, DeterministicBasicParity) {
  std::vector<Op> ops = {
      PushBackOp{10},     PushBackOp{20},  PushBackOp{30},  PopFrontOp{},
      PushBackOp{40},     EraseIndexOp{0}, InsertEndOp{50}, EmplaceBackOp{60},
      EraseRangeOp{0, 2}, ShrinkToFitOp{}, ClearOp{},       PushBackOp{70},
  };
  StableBlockListMatchesStdList<4>(ops);
  StableBlockListMatchesStdList<16>(ops);
}

TEST(StableBlockListFuzzTest, EmptyRangeErasureParity) {
  std::vector<Op> ops = {
      EraseRangeOp{0, 0},  // On empty container
      PushBackOp{10},     PushBackOp{20},
      PushBackOp{30},     EraseRangeOp{0, 0},  // Empty range at begin
      EraseRangeOp{1, 0},                      // Empty range in middle
      EraseRangeOp{2, 0},                      // Empty range before end
      EraseRangeOp{3, 0},                      // Empty range at end
      PushBackOp{40},
  };
  StableBlockListMatchesStdList<1>(ops);
  StableBlockListMatchesStdList<2>(ops);
  StableBlockListMatchesStdList<4>(ops);
  StableBlockListMatchesStdList<16>(ops);
  StableBlockListMatchesStdList<32>(ops);
  StableBlockListMatchesStdList<64>(ops);
}

}  // namespace
}  // namespace quiche
