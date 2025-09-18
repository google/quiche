// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/namespace_publisher_multimap.h"

#include <memory>

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt {
namespace test {

class NamespacePublisherMultimapTest : public quiche::test::QuicheTest {
 public:
  NamespacePublisherMultimapTest()
      : session_(std::make_unique<MockMoqtSession>()) {}

  NamespacePublisherMultimap multimap_;
  TrackNamespace ns1_{"foo", "bar"}, ns2_{"foo"}, ns3_{"foo", "bar", "baz"};
  std::unique_ptr<MockMoqtSession> session_;
};

TEST_F(NamespacePublisherMultimapTest, AddGetRemovePublisher) {
  EXPECT_EQ(multimap_.GetValidPublisher(ns1_).GetIfAvailable(), nullptr);
  multimap_.AddPublisher(ns1_, session_.get());
  EXPECT_EQ(multimap_.GetValidPublisher(ns1_).GetIfAvailable(), session_.get());
  EXPECT_EQ(multimap_.GetValidPublisher(ns2_).GetIfAvailable(), nullptr);
  EXPECT_EQ(multimap_.GetValidPublisher(ns3_).GetIfAvailable(), nullptr);
  multimap_.RemovePublisher(ns1_, session_.get());
  EXPECT_EQ(multimap_.GetValidPublisher(ns1_).GetIfAvailable(), nullptr);
}

TEST_F(NamespacePublisherMultimapTest, SessionDestroyed) {
  EXPECT_EQ(multimap_.GetValidPublisher(ns1_).GetIfAvailable(), nullptr);
  multimap_.AddPublisher(ns1_, session_.get());
  EXPECT_EQ(multimap_.GetValidPublisher(ns1_).GetIfAvailable(), session_.get());
  session_.reset();
  EXPECT_EQ(multimap_.GetValidPublisher(ns1_).GetIfAvailable(), nullptr);
}

}  // namespace test
}  // namespace moqt
