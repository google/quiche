// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_server_id.h"

#include "absl/hash/hash_testing.h"

#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {

namespace test {

namespace {

class LoadBalancerServerIdTest : public QuicTest {};

constexpr uint8_t kRawServerId[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                    0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                    0x0c, 0x0d, 0x0e, 0x0f};

TEST_F(LoadBalancerServerIdTest, CreateReturnsNullIfTooLong) {
  EXPECT_QUIC_BUG(EXPECT_FALSE(LoadBalancerServerId::Create(
                                   absl::Span<const uint8_t>(kRawServerId, 16))
                                   .has_value()),
                  "Attempted to create LoadBalancerServerId with length 16");
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerServerId::Create(absl::Span<const uint8_t>())
                       .has_value()),
      "Attempted to create LoadBalancerServerId with length 0");
}

TEST_F(LoadBalancerServerIdTest, CompareIdenticalExceptLength) {
  auto server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 15));
  ASSERT_TRUE(server_id.has_value());
  EXPECT_EQ(server_id->length(), 15);
  auto shorter_server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 5));
  ASSERT_TRUE(shorter_server_id.has_value());
  EXPECT_EQ(shorter_server_id->length(), 5);
  // Shorter comes before longer if all bits match
  EXPECT_TRUE(shorter_server_id < server_id);
  EXPECT_FALSE(server_id < shorter_server_id);
  // Different lengths are never equal.
  EXPECT_FALSE(shorter_server_id == server_id);
}

TEST_F(LoadBalancerServerIdTest, AccessorFunctions) {
  auto server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 5));
  EXPECT_TRUE(server_id.has_value());
  EXPECT_EQ(server_id->length(), 5);
  EXPECT_EQ(memcmp(server_id->data().data(), kRawServerId, 5), 0);
  EXPECT_EQ(server_id->ToString(), "0001020304");
}

TEST_F(LoadBalancerServerIdTest, CompareDifferentServerIds) {
  auto server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 5));
  ASSERT_TRUE(server_id.has_value());
  auto reverse = LoadBalancerServerId::Create({0x0f, 0x0e, 0x0d, 0x0c, 0x0b});
  ASSERT_TRUE(reverse.has_value());
  EXPECT_TRUE(server_id < reverse);
  auto long_server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 15));
  EXPECT_TRUE(long_server_id < reverse);
}

TEST_F(LoadBalancerServerIdTest, EqualityOperators) {
  auto server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 15));
  ASSERT_TRUE(server_id.has_value());
  auto shorter_server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 5));
  ASSERT_TRUE(shorter_server_id.has_value());
  EXPECT_FALSE(server_id == shorter_server_id);
  auto server_id2 = server_id;
  EXPECT_TRUE(server_id == server_id2);
}

TEST_F(LoadBalancerServerIdTest, SupportsHash) {
  auto server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 15));
  ASSERT_TRUE(server_id.has_value());
  auto shorter_server_id =
      LoadBalancerServerId::Create(absl::Span<const uint8_t>(kRawServerId, 5));
  ASSERT_TRUE(shorter_server_id.has_value());
  auto different_server_id =
      LoadBalancerServerId::Create({0x0f, 0x0e, 0x0d, 0x0c, 0x0b});
  ASSERT_TRUE(different_server_id.has_value());
  EXPECT_TRUE(absl::VerifyTypeImplementsAbslHashCorrectly({
      *server_id,
      *shorter_server_id,
      *different_server_id,
  }));
}

}  // namespace

}  // namespace test

}  // namespace quic
