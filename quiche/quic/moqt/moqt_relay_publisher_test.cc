// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_relay_publisher.h"

#include <cstdint>
#include <optional>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {
namespace test {

class MockMoqtSession : public MoqtSessionInterface {
 public:
  MOCK_METHOD(MoqtSessionCallbacks&, callbacks, (), (override));
  MOCK_METHOD(void, Error, (MoqtError code, absl::string_view error),
              (override));
  MOCK_METHOD(bool, SubscribeAbsolute,
              (const FullTrackName& name, uint64_t start_group,
               uint64_t start_object, SubscribeRemoteTrack::Visitor* visitor,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(bool, SubscribeAbsolute,
              (const FullTrackName& name, uint64_t start_group,
               uint64_t start_object, uint64_t end_group,
               SubscribeRemoteTrack::Visitor* visitor,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(bool, SubscribeCurrentObject,
              (const FullTrackName& name,
               SubscribeRemoteTrack::Visitor* visitor,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(bool, SubscribeNextGroup,
              (const FullTrackName& name,
               SubscribeRemoteTrack::Visitor* visitor,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(bool, SubscribeUpdate,
              (const FullTrackName& name, std::optional<Location> start,
               std::optional<uint64_t> end_group,
               std::optional<MoqtPriority> subscriber_priority,
               std::optional<bool> forward,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(void, Unsubscribe, (const FullTrackName& name), (override));
  MOCK_METHOD(bool, Fetch,
              (const FullTrackName& name, FetchResponseCallback callback,
               Location start, uint64_t end_group,
               std::optional<uint64_t> end_object, MoqtPriority priority,
               std::optional<MoqtDeliveryOrder> delivery_order,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(bool, RelativeJoiningFetch,
              (const FullTrackName& name,
               SubscribeRemoteTrack::Visitor* visitor,
               uint64_t num_previous_groups,
               VersionSpecificParameters parameters),
              (override));
  MOCK_METHOD(bool, RelativeJoiningFetch,
              (const FullTrackName& name,
               SubscribeRemoteTrack::Visitor* visitor,
               FetchResponseCallback callback, uint64_t num_previous_groups,
               MoqtPriority priority,
               std::optional<MoqtDeliveryOrder> delivery_order,
               VersionSpecificParameters parameters),
              (override));

  quiche::QuicheWeakPtr<MoqtSessionInterface> GetWeakPtr() override {
    return weak_factory_.Create();
  }
  quiche::QuicheWeakPtrFactory<MoqtSessionInterface> weak_factory_{this};
};

class MoqtRelayPublisherTest : public quiche::test::QuicheTest {
 public:
  MoqtRelayPublisherTest() : publisher_(false) {}

  MoqtSessionCallbacks callbacks_;
  MockMoqtSession session_;
  MoqtRelayPublisher publisher_;
};

TEST_F(MoqtRelayPublisherTest, SetDefaultUpstreamSession) {
  EXPECT_FALSE(publisher_.GetDefaultUpstreamSession().IsValid());
  EXPECT_CALL(session_, callbacks).WillOnce(testing::ReturnRef(callbacks_));
  publisher_.SetDefaultUpstreamSession(&session_);
  EXPECT_TRUE(publisher_.GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(publisher_.GetDefaultUpstreamSession().GetIfAvailable(), &session_);
  // Destroy the session.
  std::move(callbacks_.session_terminated_callback)("test");
  EXPECT_FALSE(publisher_.GetDefaultUpstreamSession().IsValid());
}

TEST_F(MoqtRelayPublisherTest, SetDefaultUpstreamSessionTwice) {
  EXPECT_FALSE(publisher_.GetDefaultUpstreamSession().IsValid());
  EXPECT_CALL(session_, callbacks()).WillOnce(testing::ReturnRef(callbacks_));
  publisher_.SetDefaultUpstreamSession(&session_);
  EXPECT_TRUE(publisher_.GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(publisher_.GetDefaultUpstreamSession().GetIfAvailable(), &session_);

  MockMoqtSession session2;
  MoqtSessionCallbacks callbacks2;
  EXPECT_CALL(session_, callbacks).WillOnce(testing::ReturnRef(callbacks_));
  EXPECT_CALL(session2, callbacks).WillOnce(testing::ReturnRef(callbacks2));
  publisher_.SetDefaultUpstreamSession(&session2);
  EXPECT_TRUE(publisher_.GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(publisher_.GetDefaultUpstreamSession().GetIfAvailable(), &session2);

  // Destroying the old session doesn't affect the publisher.
  std::move(callbacks_.session_terminated_callback)("test");
  EXPECT_TRUE(publisher_.GetDefaultUpstreamSession().IsValid());

  // Destroying the new session does.
  std::move(callbacks2.session_terminated_callback)("test");
  EXPECT_FALSE(publisher_.GetDefaultUpstreamSession().IsValid());
}

}  // namespace test
}  // namespace moqt
