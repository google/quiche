// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_priority.h"

#include "quiche/common/platform/api/quiche_test.h"

namespace moqt {
namespace {

TEST(MoqtPriorityTest, SubgroupPriorities) {
  // MoQT track priorities are descending (0 is highest), but WebTransport send
  // order is ascending.
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0x80, 0x80, 0, 0, MoqtGroupOrder::kAscending));
  EXPECT_GT(SendOrderForStream(0x80, 0x10, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0x80, 0x80, 0, 0, MoqtGroupOrder::kAscending));
  // Subscriber priority takes precedence over the sender priority.
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0x80, 0x10, 0, 0, MoqtGroupOrder::kAscending));
  // Group order breaks ties.
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0x80, 0x10, 1, 0, MoqtGroupOrder::kAscending));
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 1, 0, MoqtGroupOrder::kDescending),
            SendOrderForStream(0x80, 0x10, 0, 0, MoqtGroupOrder::kDescending));
  // Subgroup order breaks tied group IDs.
  EXPECT_GT(SendOrderForStream(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0x80, 0x10, 0, 1, MoqtGroupOrder::kAscending));
  // Test extreme priority values (0x00 and 0xff).
  EXPECT_GT(SendOrderForStream(0x00, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0xff, 0x80, 0, 0, MoqtGroupOrder::kAscending));
  EXPECT_GT(SendOrderForStream(0x80, 0x00, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForStream(0x80, 0xff, 0, 0, MoqtGroupOrder::kAscending));
}

TEST(MoqtPriorityTest, DatagramPriorities) {
  // MoQT track priorities are descending (0 is highest), but WebTransport send
  // order is ascending.
  EXPECT_GT(SendOrderForDatagram(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0x80, 0x80, 0, 0, MoqtGroupOrder::kAscending));
  EXPECT_GT(SendOrderForDatagram(0x80, 0x10, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0x80, 0x80, 0, 0, MoqtGroupOrder::kAscending));
  // Subscriber priority takes precedence over the sender priority.
  EXPECT_GT(SendOrderForDatagram(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0x80, 0x10, 0, 0, MoqtGroupOrder::kAscending));
  // Group order breaks ties.
  EXPECT_GT(SendOrderForDatagram(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0x80, 0x10, 1, 0, MoqtGroupOrder::kAscending));
  EXPECT_GT(
      SendOrderForDatagram(0x10, 0x80, 1, 0, MoqtGroupOrder::kDescending),
      SendOrderForDatagram(0x80, 0x10, 0, 0, MoqtGroupOrder::kDescending));
  // Object ID breaks tied group IDs.
  EXPECT_GT(SendOrderForDatagram(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0x80, 0x10, 0, 1, MoqtGroupOrder::kAscending));
  // Test extreme priority values (0x00 and 0xff).
  EXPECT_GT(SendOrderForDatagram(0x00, 0x80, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0xff, 0x80, 0, 0, MoqtGroupOrder::kAscending));
  EXPECT_GT(SendOrderForDatagram(0x80, 0x00, 0, 0, MoqtGroupOrder::kAscending),
            SendOrderForDatagram(0x80, 0xff, 0, 0, MoqtGroupOrder::kAscending));
}

TEST(MoqtPriorityTest, FetchPriorities) {
  EXPECT_LT(
      SendOrderForFetch(0x10),
      SendOrderForStream(0x10, 0x05, 0x06, 0x03, MoqtGroupOrder::kDescending));
  EXPECT_LT(
      SendOrderForFetch(0x10),
      SendOrderForStream(0x09, 0x05, 0x06, 0x03, MoqtGroupOrder::kDescending));
  EXPECT_GT(
      SendOrderForFetch(0x10),
      SendOrderForStream(0x11, 0x05, 0x06, 0x03, MoqtGroupOrder::kDescending));
  EXPECT_GT(SendOrderForFetch(0x10), SendOrderForFetch(0x11));
}

TEST(MoqtPriorityTest, ControlStream) {
  EXPECT_GT(kMoqtControlStreamSendOrder,
            SendOrderForStream(0x00, 0x00, 0, 0, MoqtGroupOrder::kAscending));
}

TEST(MoqtPriorityTest, UpdateSendOrderForSubscriberPriority) {
  EXPECT_EQ(
      UpdateSendOrderForSubscriberPriority(
          SendOrderForStream(0x80, 0x80, 0, 0, MoqtGroupOrder::kAscending),
          0x10),
      SendOrderForStream(0x10, 0x80, 0, 0, MoqtGroupOrder::kAscending));
}

}  // namespace
}  // namespace moqt
