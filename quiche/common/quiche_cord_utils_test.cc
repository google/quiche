// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/quiche_cord_utils.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/cord.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_mem_slice.h"

namespace quiche::test {
namespace {

TEST(QuicheCordUtilsTest, MemSliceToCord) {
  QuicheMemSlice slice1 = QuicheMemSlice::Copy("foo");
  QuicheMemSlice slice2 = QuicheMemSlice::Copy("bar");
  absl::Cord cord = MemSliceToCord(std::move(slice1));
  cord.Append(MemSliceToCord(std::move(slice2)));
  EXPECT_EQ(cord, "foobar");
}

TEST(QuicheCordUtilsTest, MemSliceToCordEmpty) {
  absl::Cord cord = MemSliceToCord(QuicheMemSlice());
  EXPECT_TRUE(cord.empty());
}

TEST(QuicheCordUtilsTest, MemSliceToCordNullDeleter) {
  absl::string_view kText = "test";
  absl::Cord cord =
      MemSliceToCord(QuicheMemSlice(kText.data(), kText.size(), nullptr));
  EXPECT_EQ(cord, kText);
}

TEST(QuicheCordUtilsTest, MemSliceSpanToCord) {
  std::array<QuicheMemSlice, 2> slices = {QuicheMemSlice::Copy("foo"),
                                          QuicheMemSlice::Copy("bar")};
  absl::Cord cord = MemSliceSpanToCord(absl::MakeSpan(slices));
  EXPECT_EQ(cord, "foobar");
}

TEST(QuicheCordUtilsTest, CordToMemSlicesInlined) {
  absl::Cord cord("test");
  std::vector<QuicheMemSlice> slices;
  CordToMemSlicesTo(cord, slices);
  ASSERT_EQ(slices.size(), 1);
  EXPECT_EQ(slices[0].AsStringView(), "test");
}

TEST(QuicheCordUtilsTest, CordToMemSlicesNotInlined) {
  constexpr size_t kSize = 8192;
  auto buffer = std::make_unique<char[]>(kSize);
  uintptr_t original_address = reinterpret_cast<uintptr_t>(buffer.get());
  memset(buffer.get(), 'a', kSize);
  absl::Cord cord = absl::MakeCordFromExternal(
      absl::string_view(buffer.release(), kSize),
      [](absl::string_view data) { delete[] data.data(); });
  std::vector<QuicheMemSlice> slices;
  CordToMemSlicesTo(cord, slices);
  cord.Clear();

  ASSERT_EQ(slices.size(), 1);
  EXPECT_EQ(slices[0].length(), kSize);
  EXPECT_EQ(reinterpret_cast<uintptr_t>(slices[0].data()), original_address);
  EXPECT_EQ(slices[0].AsStringView(), std::string(kSize, 'a'));
}

TEST(QuicheCordUtilsTest, CordToMemSlicesLarge) {
  const std::string kBlock(1024, 'a');
  constexpr size_t kBlockCount = 128;
  absl::Cord cord;
  for (size_t i = 0; i < kBlockCount; ++i) {
    cord.Append(kBlock);
  }

  std::vector<QuicheMemSlice> slices;
  CordToMemSlicesTo(cord, slices);
  cord.Clear();

  ASSERT_GT(slices.size(), 1);
  size_t total_size = 0;
  for (const QuicheMemSlice& slice : slices) {
    total_size += slice.length();
  }
  EXPECT_EQ(total_size, kBlock.size() * kBlockCount);
  for (const QuicheMemSlice& slice : slices) {
    ASSERT_THAT(slice.AsStringView(), testing::Each('a'));
  }
}

TEST(QuicheCordUtilsTest, CordWithMixedTypes) {
  absl::Cord cord("bar");
  cord.Prepend("foo");

  auto block_before = std::make_unique<std::string>(8192, 'a');
  absl::string_view block_before_view(*block_before);
  cord.Prepend(absl::MakeCordFromExternal(
      block_before_view,
      [ptr = block_before.release()](absl::string_view) { delete ptr; }));

  auto block_after = std::make_unique<std::string>(8192, 'b');
  absl::string_view block_after_view(*block_after);
  cord.Append(absl::MakeCordFromExternal(
      block_after_view,
      [ptr = block_after.release()](absl::string_view) { delete ptr; }));

  std::vector<QuicheMemSlice> slices;
  CordToMemSlicesTo(cord, slices);
  cord.Clear();

  ASSERT_GT(slices.size(), 1);
  std::string concatenated;
  for (const QuicheMemSlice& slice : slices) {
    absl::StrAppend(&concatenated, slice.AsStringView());
  }
  EXPECT_EQ(concatenated, absl::StrCat(std::string(8192, 'a'), "foobar",
                                       std::string(8192, 'b')));
}

TEST(QuicheCordUtilsTest, Subcord) {
  constexpr size_t kCount = 100;
  absl::Cord cord;
  for (size_t i = 0; i < kCount; ++i) {
    cord.Append("foobar");
  }
  absl::Cord subcord = cord.Subcord(99, 6);
  std::vector<QuicheMemSlice> slices;
  CordToMemSlicesTo(subcord, slices);
  ASSERT_EQ(slices.size(), 1);
  EXPECT_EQ(slices[0].AsStringView(), "barfoo");  // 99 = 16 * 6 + 3
  cord.Clear();
  subcord.Clear();
  EXPECT_EQ(slices[0].AsStringView(), "barfoo");
}

}  // namespace
}  // namespace quiche::test
