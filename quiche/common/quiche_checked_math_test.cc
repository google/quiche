// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/quiche_checked_math.h"

#include <cstdint>
#include <limits>
#include <optional>

#include "quiche/common/platform/api/quiche_test.h"

namespace quiche {
namespace {

template <typename Int>
void RunAddTests() {
  constexpr Int kMax = std::numeric_limits<Int>::max();
  EXPECT_EQ(SafeAdd<Int>(0, 0), 0);
  EXPECT_EQ(SafeAdd<Int>(2, 2), 4);
  EXPECT_EQ(SafeAdd<Int>(kMax - 1, 1), kMax);
  EXPECT_EQ(SafeAdd<Int>(kMax, 0), kMax);
  EXPECT_EQ(SafeAdd<Int>(kMax - 1, 2), std::nullopt);
  EXPECT_EQ(SafeAdd<Int>(kMax, 1), std::nullopt);
  EXPECT_EQ(SafeAdd<Int>(kMax, kMax), std::nullopt);
}

TEST(QuicheCheckedMathTest, Add) {
  // Spell out uint8_t tests explicitly to make them easier to follow.
  EXPECT_EQ(SafeAdd<uint8_t>(0, 0), 0);
  EXPECT_EQ(SafeAdd<uint8_t>(2, 2), 4);
  EXPECT_EQ(SafeAdd<uint8_t>(254, 1), 255);
  EXPECT_EQ(SafeAdd<uint8_t>(255, 0), 255);
  EXPECT_EQ(SafeAdd<uint8_t>(254, 2), std::nullopt);
  EXPECT_EQ(SafeAdd<uint8_t>(255, 1), std::nullopt);
  EXPECT_EQ(SafeAdd<uint8_t>(255, 255), std::nullopt);

  // Run the remainder of tests through a templated function.
  RunAddTests<uint16_t>();
  RunAddTests<uint32_t>();
  RunAddTests<uint64_t>();
}

template <typename Int>
void RunIncrementTests() {
  constexpr Int kMax = std::numeric_limits<Int>::max();
  Int var = kMax - 5;
  EXPECT_TRUE(SafeIncrementBy<Int>(var, 0));
  EXPECT_EQ(var, kMax - 5);

  EXPECT_TRUE(SafeIncrementBy<Int>(var, 5));
  EXPECT_EQ(var, kMax);

  EXPECT_FALSE(SafeIncrementBy<Int>(var, 1));
  EXPECT_EQ(var, kMax);
}

TEST(QuicheCheckedMathTest, IncrementBy) {
  // Spell out uint8_t tests explicitly to make them easier to follow.
  uint8_t var8 = 250;
  EXPECT_TRUE(SafeIncrementBy<uint8_t>(var8, 0));
  EXPECT_EQ(var8, 250);

  EXPECT_TRUE(SafeIncrementBy<uint8_t>(var8, 2));
  EXPECT_EQ(var8, 252);

  EXPECT_TRUE(SafeIncrementBy<uint8_t>(var8, 3));
  EXPECT_EQ(var8, 255);

  EXPECT_FALSE(SafeIncrementBy<uint8_t>(var8, 1));
  EXPECT_EQ(var8, 255);

  EXPECT_FALSE(SafeIncrementBy<uint8_t>(var8, 255));
  EXPECT_EQ(var8, 255);

  // Run the remainder of tests through a templated function.
  RunIncrementTests<uint16_t>();
  RunIncrementTests<uint32_t>();
  RunIncrementTests<uint64_t>();
}

TEST(QuicheCheckedMathTest, Sum) {
  EXPECT_EQ(SafeSum<uint8_t>({}), 0);
  EXPECT_EQ(SafeSum<uint8_t>({2, 2}), 4);
  EXPECT_EQ(SafeSum<uint8_t>({1, 2, 3}), 6);
  EXPECT_EQ(SafeSum<uint8_t>({200, 200}), std::nullopt);
  EXPECT_EQ(SafeSum<uint8_t>({200, 200, 200}), std::nullopt);
  EXPECT_EQ(SafeSum<uint8_t>({100, 100, 100}), std::nullopt);
  EXPECT_EQ(SafeSum<uint8_t>({128, 126, 1}), 255);
  EXPECT_EQ(SafeSum<uint8_t>({128, 126, 2}), std::nullopt);
}

}  // namespace
}  // namespace quiche
