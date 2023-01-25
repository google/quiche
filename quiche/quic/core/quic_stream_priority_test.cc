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
  EXPECT_EQ((QuicStreamPriority{11, true}), (QuicStreamPriority{11, true}));

  EXPECT_NE((QuicStreamPriority{1, true}), (QuicStreamPriority{3, true}));
  EXPECT_NE((QuicStreamPriority{4, false}), (QuicStreamPriority{4, true}));
  EXPECT_NE((QuicStreamPriority{6, true}), (QuicStreamPriority{2, false}));
  EXPECT_NE((QuicStreamPriority{12, true}), (QuicStreamPriority{9, true}));
  EXPECT_NE((QuicStreamPriority{2, false}), (QuicStreamPriority{8, false}));
}

TEST(SerializePriorityFieldValueTest, SerializePriorityFieldValue) {
  // Default value is omitted.
  EXPECT_EQ("", SerializePriorityFieldValue(
                    {/* urgency = */ 3, /* incremental = */ false}));
  EXPECT_EQ("u=5", SerializePriorityFieldValue(
                       {/* urgency = */ 5, /* incremental = */ false}));
  // TODO(b/266722347): Never send `urgency` if value equals default value.
  EXPECT_EQ("u=3, i", SerializePriorityFieldValue(
                          {/* urgency = */ 3, /* incremental = */ true}));
  EXPECT_EQ("u=0, i", SerializePriorityFieldValue(
                          {/* urgency = */ 0, /* incremental = */ true}));
  // Out-of-bound value is ignored.
  EXPECT_EQ("i", SerializePriorityFieldValue(
                     {/* urgency = */ 9, /* incremental = */ true}));
}

TEST(ParsePriorityFieldValueTest, ParsePriorityFieldValue) {
  // Default values
  absl::optional<QuicStreamPriority> result = ParsePriorityFieldValue("");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(3, result->urgency);
  EXPECT_FALSE(result->incremental);

  result = ParsePriorityFieldValue("i=?1");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(3, result->urgency);
  EXPECT_TRUE(result->incremental);

  result = ParsePriorityFieldValue("u=5");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(5, result->urgency);
  EXPECT_FALSE(result->incremental);

  result = ParsePriorityFieldValue("u=5, i");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(5, result->urgency);
  EXPECT_TRUE(result->incremental);

  result = ParsePriorityFieldValue("i, u=1");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(1, result->urgency);
  EXPECT_TRUE(result->incremental);

  // Duplicate values are allowed.
  result = ParsePriorityFieldValue("u=5, i=?1, i=?0, u=2");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(2, result->urgency);
  EXPECT_FALSE(result->incremental);

  // Unknown parameters MUST be ignored.
  result = ParsePriorityFieldValue("a=42, u=4, i=?0");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(4, result->urgency);
  EXPECT_FALSE(result->incremental);

  // Out-of-range values MUST be ignored.
  result = ParsePriorityFieldValue("u=-2, i");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(3, result->urgency);
  EXPECT_TRUE(result->incremental);

  // Values of unexpected types MUST be ignored.
  result = ParsePriorityFieldValue("u=4.2, i=\"foo\"");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(3, result->urgency);
  EXPECT_FALSE(result->incremental);

  // Values of the right type but different names are ignored.
  result = ParsePriorityFieldValue("a=4, b=?1");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(3, result->urgency);
  EXPECT_FALSE(result->incremental);

  // Cannot be parsed as structured headers.
  result = ParsePriorityFieldValue("000");
  EXPECT_FALSE(result.has_value());

  // Inner list dictionary values are ignored.
  result = ParsePriorityFieldValue("a=(1 2), u=1");
  ASSERT_TRUE(result.has_value());
  EXPECT_EQ(1, result->urgency);
  EXPECT_FALSE(result->incremental);
}

}  // namespace quic::test
