// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_stream_priority.h"

#include "quiche/common/platform/api/quiche_test.h"

namespace quic::test {

TEST(QuicStreamPriority, DefaultConstructed) {
  QuicStreamPriority priority;

  EXPECT_EQ(QuicStreamPriority::kDefaultUrgency, priority.urgency);
  EXPECT_EQ(QuicStreamPriority::kDefaultIncremental, priority.incremental);
}

TEST(QuicStreamPriority, Equals) {
  EXPECT_EQ((QuicStreamPriority()),
            (QuicStreamPriority{QuicStreamPriority::kDefaultUrgency,
                                QuicStreamPriority::kDefaultIncremental}));
  EXPECT_EQ((QuicStreamPriority{5, true}), (QuicStreamPriority{5, true}));
  EXPECT_EQ((QuicStreamPriority{2, false}), (QuicStreamPriority{2, false}));

  EXPECT_NE((QuicStreamPriority{1, true}), (QuicStreamPriority{3, true}));
  EXPECT_NE((QuicStreamPriority{4, false}), (QuicStreamPriority{4, true}));
  EXPECT_NE((QuicStreamPriority{6, true}), (QuicStreamPriority{2, false}));
}

TEST(SerializePriorityFieldValueTest, SerializePriorityFieldValue) {
  // Default value is omitted.
  EXPECT_EQ("", SerializePriorityFieldValue(
                    {/* urgency = */ 3, /* incremental = */ false}));
  EXPECT_EQ("u=5", SerializePriorityFieldValue(
                       {/* urgency = */ 5, /* incremental = */ false}));
  EXPECT_EQ("i", SerializePriorityFieldValue(
                     {/* urgency = */ 3, /* incremental = */ true}));
  EXPECT_EQ("u=0, i", SerializePriorityFieldValue(
                          {/* urgency = */ 0, /* incremental = */ true}));
  // Out-of-bound value is ignored.
  EXPECT_EQ("i", SerializePriorityFieldValue(
                     {/* urgency = */ 9, /* incremental = */ true}));
}

TEST(ParsePriorityFieldValueTest, ParsePriorityFieldValue) {
  // Default values
  ParsePriorityFieldValueResult result = ParsePriorityFieldValue("");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(3, result.priority.urgency);
  EXPECT_FALSE(result.priority.incremental);

  result = ParsePriorityFieldValue("i=?1");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(3, result.priority.urgency);
  EXPECT_TRUE(result.priority.incremental);

  result = ParsePriorityFieldValue("u=5");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(5, result.priority.urgency);
  EXPECT_FALSE(result.priority.incremental);

  result = ParsePriorityFieldValue("u=5, i");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(5, result.priority.urgency);
  EXPECT_TRUE(result.priority.incremental);

  result = ParsePriorityFieldValue("i, u=1");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(1, result.priority.urgency);
  EXPECT_TRUE(result.priority.incremental);

  // Duplicate values are allowed.
  result = ParsePriorityFieldValue("u=5, i=?1, i=?0, u=2");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(2, result.priority.urgency);
  EXPECT_FALSE(result.priority.incremental);

  // Unknown parameters MUST be ignored.
  result = ParsePriorityFieldValue("a=42, u=4, i=?0");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(4, result.priority.urgency);
  EXPECT_FALSE(result.priority.incremental);

  // Out-of-range values MUST be ignored.
  result = ParsePriorityFieldValue("u=-2, i");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(3, result.priority.urgency);
  EXPECT_TRUE(result.priority.incremental);

  // Values of unexpected types MUST be ignored.
  result = ParsePriorityFieldValue("u=4.2, i=\"foo\"");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(3, result.priority.urgency);
  EXPECT_FALSE(result.priority.incremental);

  // Values of the right type but different names are ignored.
  result = ParsePriorityFieldValue("a=4, b=?1");
  EXPECT_TRUE(result.success);
  EXPECT_EQ(3, result.priority.urgency);
  EXPECT_FALSE(result.priority.incremental);

  // Cannot be parsed as structured headers.
  result = ParsePriorityFieldValue("000");
  EXPECT_FALSE(result.success);
}

}  // namespace quic::test
