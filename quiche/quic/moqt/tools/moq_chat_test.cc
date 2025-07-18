// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/tools/moq_chat.h"

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::moq_chat {
namespace {

class MoqChatTest : public quiche::test::QuicheTest {};

TEST_F(MoqChatTest, IsValidPath) {
  EXPECT_TRUE(IsValidPath("/moq-relay"));
  EXPECT_FALSE(IsValidPath("moq-relay"));
  EXPECT_FALSE(IsValidPath("/moq-rela"));
  EXPECT_FALSE(IsValidPath("/moq-relays"));
  EXPECT_FALSE(IsValidPath("/moq-relay/"));
}

TEST_F(MoqChatTest, ConstructNameForUser) {
  FullTrackName name = ConstructTrackName("chat-id", "user", "device");

  EXPECT_EQ(GetChatId(name), "chat-id");
  EXPECT_EQ(GetUsername(name), "user");
  // Check that the namespace passes validation.
  EXPECT_TRUE(ConstructTrackNameFromNamespace(GetUserNamespace(name), "chat-id")
                  .has_value());
}

TEST_F(MoqChatTest, InvalidNamespace) {
  TrackNamespace track_namespace(
      {kBasePath, "chat-id", "username", "device", "timestamp"});
  // Wrong chat ID.
  EXPECT_FALSE(
      ConstructTrackNameFromNamespace(track_namespace, "chat-id2").has_value());
  // Namespace too short.
  TrackNamespace short_base_path({"moq-chat2", "chat-id", "user", "device"});
  EXPECT_FALSE(
      ConstructTrackNameFromNamespace(short_base_path, "chat-id").has_value());
  track_namespace.AddElement("chat");  // Restore to correct value.
  // Base Path is wrong.
  TrackNamespace bad_base_path(
      {"moq-chat2", "chat-id", "user", "device", "timestamp"});
  EXPECT_FALSE(
      ConstructTrackNameFromNamespace(bad_base_path, "chat-id").has_value());
}

TEST_F(MoqChatTest, Queries) {
  FullTrackName local_name(
      TrackNamespace({kBasePath, "chat-id", "user", "device", "timestamp"}),
      kNameField);
  EXPECT_EQ(GetChatId(local_name), "chat-id");
  EXPECT_EQ(GetUsername(local_name), "user");
  TrackNamespace track_namespace(
      {"moq-chat", "chat-id", "user", "device", "timestamp"});
  EXPECT_EQ(GetUserNamespace(local_name), track_namespace);
  TrackNamespace chat_namespace({kBasePath, "chat-id"});
  EXPECT_EQ(GetChatNamespace(local_name), chat_namespace);
}

}  // namespace
}  // namespace moqt::moq_chat
