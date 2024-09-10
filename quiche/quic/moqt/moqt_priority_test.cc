// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_priority.h"

#include "quiche/common/platform/api/quiche_test.h"

namespace moqt {
namespace {

TEST(MoqtPrioirtyTest, TrackPriorities) {
  // MoQT track priorities are descending (0 is highest), but WebTransport send
  // order is ascending.
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 0, MoqtDeliveryOrder::kAscending),
            SendOrderForStream(0x80, 0x80, 0, MoqtDeliveryOrder::kAscending));
  EXPECT_GT(SendOrderForStream(0x80, 0x10, 0, MoqtDeliveryOrder::kAscending),
            SendOrderForStream(0x80, 0x80, 0, MoqtDeliveryOrder::kAscending));
  // Subscriber priority takes precedence over the sender priority.
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 0, MoqtDeliveryOrder::kAscending),
            SendOrderForStream(0x80, 0x10, 0, MoqtDeliveryOrder::kAscending));
  // Test extreme priority values (0x00 and 0xff).
  EXPECT_GT(SendOrderForStream(0x00, 0x80, 0, MoqtDeliveryOrder::kAscending),
            SendOrderForStream(0xff, 0x80, 0, MoqtDeliveryOrder::kAscending));
  EXPECT_GT(SendOrderForStream(0x80, 0x00, 0, MoqtDeliveryOrder::kAscending),
            SendOrderForStream(0x80, 0xff, 0, MoqtDeliveryOrder::kAscending));
}

TEST(MoqtPrioirtyTest, ControlStream) {
  EXPECT_GT(kMoqtControlStreamSendOrder,
            SendOrderForStream(0x00, 0x00, 0, MoqtDeliveryOrder::kAscending));
}

TEST(MoqtPriorityTest, StreamPerGroup) {
  EXPECT_GT(SendOrderForStream(0x80, 0x80, 0, MoqtDeliveryOrder::kAscending),
            SendOrderForStream(0x80, 0x80, 1, MoqtDeliveryOrder::kAscending));
  EXPECT_GT(SendOrderForStream(0x80, 0x80, 1, MoqtDeliveryOrder::kDescending),
            SendOrderForStream(0x80, 0x80, 0, MoqtDeliveryOrder::kDescending));
}

TEST(MoqtPriorityTest, StreamPerObject) {
  // Objects within the same group.
  EXPECT_GT(
      SendOrderForStream(0x80, 0x80, 0, 0, MoqtDeliveryOrder::kAscending),
      SendOrderForStream(0x80, 0x80, 0, 1, MoqtDeliveryOrder::kAscending));
  EXPECT_GT(
      SendOrderForStream(0x80, 0x80, 0, 0, MoqtDeliveryOrder::kDescending),
      SendOrderForStream(0x80, 0x80, 0, 1, MoqtDeliveryOrder::kDescending));
  // Objects of different groups.
  EXPECT_GT(
      SendOrderForStream(0x80, 0x80, 0, 1, MoqtDeliveryOrder::kAscending),
      SendOrderForStream(0x80, 0x80, 1, 0, MoqtDeliveryOrder::kAscending));
  EXPECT_GT(
      SendOrderForStream(0x80, 0x80, 1, 1, MoqtDeliveryOrder::kDescending),
      SendOrderForStream(0x80, 0x80, 0, 0, MoqtDeliveryOrder::kDescending));
}

TEST(MoqtPriorityTest, UpdateSendOrderForSubscriberPriority) {
  EXPECT_EQ(
      UpdateSendOrderForSubscriberPriority(
          SendOrderForStream(0x80, 0x80, 0, MoqtDeliveryOrder::kAscending),
          0x10),
      SendOrderForStream(0x10, 0x80, 0, MoqtDeliveryOrder::kAscending));
}

}  // namespace
}  // namespace moqt
