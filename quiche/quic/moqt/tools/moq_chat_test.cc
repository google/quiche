// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/tools/moq_chat.h"

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt {
namespace {

class MoqChatStringsTest : public quiche::test::QuicheTest {
 public:
  MoqChatStrings strings_{"chat-id"};
};

TEST_F(MoqChatStringsTest, IsValidPath) {
  EXPECT_TRUE(strings_.IsValidPath("/moq-chat"));
  EXPECT_FALSE(strings_.IsValidPath("moq-chat"));
  EXPECT_FALSE(strings_.IsValidPath("/moq-cha"));
  EXPECT_FALSE(strings_.IsValidPath("/moq-chats"));
  EXPECT_FALSE(strings_.IsValidPath("/moq-chat/"));
}

TEST_F(MoqChatStringsTest, GetUsernameFromFullTrackName) {
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/participant/user", ""}),
            "user");
}

TEST_F(MoqChatStringsTest, GetUsernameFromFullTrackNameInvalidInput) {
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"/moq-chat/chat-id/participant/user", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/participant/user/", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-cha/chat-id/participant/user", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-i/participant/user", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/participan/user", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/user", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/participant/foo/user", ""}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/participant/user", "foo"}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"moq-chat/chat-id/participant/user"}),
            "");
  EXPECT_EQ(strings_.GetUsernameFromFullTrackName(
                FullTrackName{"foo", "moq-chat/chat-id/participant/user", ""}),
            "");
}

TEST_F(MoqChatStringsTest, GetFullTrackNameFromUsername) {
  EXPECT_EQ(strings_.GetFullTrackNameFromUsername("user"),
            FullTrackName("moq-chat/chat-id/participant/user", ""));
}

TEST_F(MoqChatStringsTest, GetCatalogName) {
  EXPECT_EQ(strings_.GetCatalogName(),
            FullTrackName("moq-chat/chat-id", "/catalog"));
}

}  // namespace
}  // namespace moqt
