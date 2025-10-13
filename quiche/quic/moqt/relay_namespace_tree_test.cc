// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/relay_namespace_tree.h"

#include <memory>

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt {
namespace test {

class TestRelayNamespaceTree : public RelayNamespaceTree {
 public:
  using RelayNamespaceTree::NumNamespaces;
};

using ::testing::_;

class RelayNamespaceTreeTest : public quiche::test::QuicheTest {
 public:
  RelayNamespaceTreeTest() : session_(std::make_unique<MockMoqtSession>()) {}

  TestRelayNamespaceTree tree_;
  TrackNamespace a_{"a"}, ab_{"a", "b"}, abc_{"a", "b", "c"};
  std::unique_ptr<MockMoqtSession> session_;
};

TEST_F(RelayNamespaceTreeTest, AddGetRemovePublisher) {
  EXPECT_EQ(tree_.NumNamespaces(), 0u);
  EXPECT_EQ(tree_.GetValidPublisher(ab_), nullptr);
  tree_.AddPublisher(ab_, session_.get());
  EXPECT_EQ(tree_.NumNamespaces(), 2u);
  EXPECT_EQ(tree_.GetValidPublisher(a_), nullptr);
  EXPECT_EQ(tree_.GetValidPublisher(ab_), session_.get());
  EXPECT_EQ(tree_.GetValidPublisher(abc_), session_.get());
  tree_.RemovePublisher(ab_, session_.get());
  EXPECT_EQ(tree_.NumNamespaces(), 0u);
  EXPECT_EQ(tree_.GetValidPublisher(ab_), nullptr);
}

TEST_F(RelayNamespaceTreeTest, AddGetRemoveListener) {
  // Add a listener to a namespace that has no publishers.
  EXPECT_EQ(tree_.NumNamespaces(), 0u);
  tree_.AddSubscriber(ab_, session_.get());
  EXPECT_EQ(tree_.NumNamespaces(), 2u);
  EXPECT_CALL(*session_, PublishNamespace).Times(0);
  tree_.AddPublisher(a_, session_.get());
  EXPECT_CALL(*session_, PublishNamespace(ab_, _, _));
  tree_.AddPublisher(ab_, session_.get());
  EXPECT_CALL(*session_, PublishNamespace(abc_, _, _));
  tree_.AddPublisher(abc_, session_.get());
  EXPECT_EQ(tree_.NumNamespaces(), 3u);

  // Second publisher creates no new notifications, and delays OnNamespaceDone.
  auto session2 = std::make_unique<MockMoqtSession>();
  EXPECT_CALL(*session_, PublishNamespace).Times(0);
  tree_.AddPublisher(ab_, session2.get());
  EXPECT_CALL(*session_, PublishNamespaceDone).Times(0);
  tree_.RemovePublisher(ab_, session_.get());
  EXPECT_CALL(*session_, PublishNamespaceDone(ab_));
  tree_.RemovePublisher(ab_, session2.get());

  // Removing the listener disables notifications.
  tree_.RemoveSubscriber(ab_, session_.get());
  EXPECT_CALL(*session_, PublishNamespace).Times(0);
  tree_.AddPublisher(ab_, session2.get());
}

TEST_F(RelayNamespaceTreeTest, SessionDestroyed) {
  tree_.AddSubscriber(ab_, session_.get());
  EXPECT_CALL(*session_, PublishNamespace(ab_, _, _));
  tree_.AddPublisher(ab_, session_.get());
  EXPECT_NE(tree_.GetValidPublisher(ab_), nullptr);
  // First session dies. It should have removed the namespace!
  session_.reset();
  EXPECT_QUICHE_BUG(
      tree_.GetValidPublisher(ab_),
      "Publisher WeakPtr is invalid but not removed from the set");
}

TEST_F(RelayNamespaceTreeTest, AddListenerToExistingPublisher) {
  tree_.AddPublisher(a_, session_.get());
  tree_.AddPublisher(ab_, session_.get());
  tree_.AddPublisher(abc_, session_.get());
  EXPECT_CALL(*session_, PublishNamespace(ab_, _, _));
  EXPECT_CALL(*session_, PublishNamespace(abc_, _, _));
  tree_.AddSubscriber(ab_, session_.get());
}

TEST_F(RelayNamespaceTreeTest, MaxSizeNamespace) {
  tree_.AddSubscriber(a_, session_.get());
  TrackNamespace big_namespace{"a", "b", "c", "d", "e", "f", "g", "h",
                               "i", "j", "k", "l", "m", "n", "o", "p",
                               "q", "r", "s", "t", "u", "v", "w", "x",
                               "y", "z", "1", "2", "3", "4", "5", "6"};
  EXPECT_CALL(*session_, PublishNamespace(big_namespace, _, _));
  tree_.AddPublisher(big_namespace, session_.get());
}

// TODO(martinduke): Add tests for published tracks.

}  // namespace test
}  // namespace moqt
