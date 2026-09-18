// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_relay_track_publisher.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace moqt::test {

namespace {

using ::testing::Optional;

const FullTrackName kTrackName = {"test", "track"};

class MoqtRelayTrackPublisherTest : public quiche::test::QuicheTest {
 public:
  MoqtRelayTrackPublisherTest()
      : session_(std::make_unique<MockMoqtSession>()),
        publisher_(
            kTrackName, session_->GetWeakPtr(),
            [this]() { track_deleted_ = true; }, std::nullopt) {}

  void SubscribeAndOk() {
    EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
    publisher_.AddObjectListener(&listener_, MessageParameters());
    EXPECT_CALL(listener_, OnSubscribeAccepted);
    MessageParameters parameters;
    parameters.largest_object = kLargestLocation;
    parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
    publisher_.OnReply(kTrackName,
                       SubscribeOkData{parameters, TrackProperties()});
  }

  void ObjectArrives(Location location, uint64_t subgroup,
                     MoqtObjectStatus status, absl::string_view payload,
                     bool fin_after_this = false) {
    EXPECT_CALL(listener_,
                OnNewObjectAvailable(location, Optional(subgroup), 128));
    publisher_.OnObjectFragment(
        kTrackName,
        PublishedObjectMetadata{location, subgroup, "", status, 128,
                                location.object == 0, payload.length()},
        payload, /*offset=*/0);
    std::optional<PublishedObject> object =
        publisher_.GetCachedObject(location.group, subgroup, location.object);
    ASSERT_TRUE(object.has_value());
    if (object.has_value()) {
      EXPECT_EQ(object->metadata.location, location);
      EXPECT_EQ(object->metadata.subgroup, subgroup);
      EXPECT_EQ(object->metadata.status, status);
      EXPECT_EQ(object->metadata.publisher_priority, 128);
      std::string full_payload;
      for (const auto& slice : object->payload) {
        full_payload += slice.AsStringView();
      }
      EXPECT_EQ(full_payload, payload);
      EXPECT_EQ(object->fin_after_this, fin_after_this);
    }
  }

  const Location kLargestLocation = Location(3, 2);

  bool track_deleted_ = false;
  std::unique_ptr<MockMoqtSession> session_;
  MockMoqtObjectListener listener_;
  MoqtRelayTrackPublisher publisher_;
};

TEST_F(MoqtRelayTrackPublisherTest, Queries) {
  EXPECT_EQ(publisher_.GetTrackName(), kTrackName);
  EXPECT_EQ(publisher_.largest_location(), std::nullopt);
  EXPECT_EQ(publisher_.expiration(), std::nullopt);

  SubscribeAndOk();
  EXPECT_EQ(publisher_.largest_location(), kLargestLocation);
  EXPECT_TRUE(publisher_.expiration().has_value() &&
              *publisher_.expiration() <= quic::QuicTimeDelta::FromSeconds(30));
}

TEST_F(MoqtRelayTrackPublisherTest, FiniteExpiration) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(listener_, OnSubscribeAccepted);
  MessageParameters parameters;
  parameters.largest_object = kLargestLocation;
  parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  publisher_.OnReply(kTrackName,
                     SubscribeOkData{parameters, TrackProperties()});
  EXPECT_LT(publisher_.expiration(), quic::QuicTimeDelta::FromSeconds(31));
}

// TODO(martinduke): Write a test for track expiration. It will require
// altering private members in publisher_.

TEST_F(MoqtRelayTrackPublisherTest, SubscribeLifeCycle) {
  SubscribeAndOk();
  uint64_t subgroup = 0;
  Location last_location(3, 6);
  std::optional<PublishedObject> object;
  for (Location location = kLargestLocation.Next(); location < last_location;
       location = location.Next()) {
    ObjectArrives(location, subgroup, MoqtObjectStatus::kNormal, "object");
    // Two objects per subgroup.
    if (location.object % 2 == 0) {
      ++subgroup;
    }
  }
  // End of Group object.
  ObjectArrives(last_location, subgroup, MoqtObjectStatus::kEndOfGroup, "",
                true);
  // End of Track object.
  last_location = Location(4, 0);
  subgroup = 0;
  ObjectArrives(last_location, subgroup, MoqtObjectStatus::kEndOfTrack, "",
                true);

  // TODO(martinduke): Gracefully close the subscription.
}

TEST_F(MoqtRelayTrackPublisherTest, GroupAbandoned) {
  SubscribeAndOk();
  for (uint64_t group = kLargestLocation.group + 1;
       group < kLargestLocation.group + 5; ++group) {
    if (group - kLargestLocation.group > 3) {
      EXPECT_CALL(listener_, OnGroupAbandoned(group - 3));
    }
    EXPECT_CALL(listener_,
                OnNewObjectAvailable(Location(group, 0), Optional(0), 128));
    publisher_.OnObjectFragment(
        kTrackName,
        PublishedObjectMetadata{Location(group, 0), 0, "",
                                MoqtObjectStatus::kEndOfGroup, 128, true, 0},
        "", /*offset=*/0);
  }
}

TEST_F(MoqtRelayTrackPublisherTest, BeyondEndOfTrack) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  ObjectArrives(location, 0, MoqtObjectStatus::kEndOfTrack, "", true);
  EXPECT_FALSE(track_deleted_);
  location = location.Next();
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "", MoqtObjectStatus::kNormal, 128,
                              location.object == 0, 6},
      "object", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, EndOfTrackTooEarly) {
  SubscribeAndOk();
  Location first_location = kLargestLocation.Next();
  Location second_location = first_location.Next();
  ObjectArrives(second_location, 0, MoqtObjectStatus::kNormal, "object", false);
  EXPECT_FALSE(track_deleted_);
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{first_location, 0, "",
                              MoqtObjectStatus::kEndOfTrack, 128,
                              first_location.object == 0, 0},
      "", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, BeyondEndOfGroup) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  ObjectArrives(location, 0, MoqtObjectStatus::kEndOfGroup, "", true);
  EXPECT_FALSE(track_deleted_);
  location = location.Next();
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 1, "", MoqtObjectStatus::kEndOfGroup,
                              128, location.object == 0, 6},
      "object", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, EndOfGroupTooEarly) {
  SubscribeAndOk();
  Location first_location = kLargestLocation.Next();
  Location second_location = first_location.Next();
  ObjectArrives(second_location, 0, MoqtObjectStatus::kNormal, "object", false);
  EXPECT_FALSE(track_deleted_);
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{first_location, 1, "",
                              MoqtObjectStatus::kEndOfGroup, 128,
                              first_location.object == 0, 0},
      "", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, PriorityChange) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  ObjectArrives(location, 0, MoqtObjectStatus::kNormal, "object", false);
  EXPECT_FALSE(track_deleted_);
  location = location.Next();
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "", MoqtObjectStatus::kNormal, 200,
                              location.object == 0, 6},
      "object", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

// TODO(martinduke): Enable this test once the class supports explicit FIN.
#if 0
TEST_F(MoqtRelayTrackPublisherTest, ObjectAfterFin) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  ObjectArrives(location, 0, MoqtObjectStatus::kNormal, "object", true);
  EXPECT_FALSE(track_deleted_);
  location = location.Next();
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "", MoqtObjectStatus::kNormal, 128,
                              location.object == 0, 6},
      "object", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}
#endif

TEST_F(MoqtRelayTrackPublisherTest, ObjectOutOfOrder) {
  SubscribeAndOk();
  Location first_location = kLargestLocation.Next();
  Location second_location = first_location.Next();
  ObjectArrives(second_location, 0, MoqtObjectStatus::kNormal, "object", false);
  EXPECT_FALSE(track_deleted_);
  EXPECT_CALL(listener_, OnNewObjectAvailable).Times(0);
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{first_location, 0, "", MoqtObjectStatus::kNormal,
                              128, first_location.object == 0, 6},
      "object", /*offset=*/0);
  // Object is simply ignored; track is not malformed.
  EXPECT_FALSE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, CacheMisses) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  ObjectArrives(location, 0, MoqtObjectStatus::kNormal, "object", false);
  // Nonexistent group.
  EXPECT_FALSE(
      publisher_.GetCachedObject(location.group + 1, 0, location.object)
          .has_value());
  // Nonexistent subgroup.
  EXPECT_FALSE(publisher_.GetCachedObject(location.group, 1, location.object)
                   .has_value());
  // Object ID too high.
  EXPECT_FALSE(
      publisher_.GetCachedObject(location.group, 0, location.object + 1)
          .has_value());
}

TEST_F(MoqtRelayTrackPublisherTest, SubscribeRejected) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(listener_, OnSubscribeRejected).WillOnce([this] {
    publisher_.RemoveObjectListener(&listener_);
  });
  publisher_.OnReply(kTrackName,
                     MoqtRequestErrorInfo{RequestErrorCode::kUnauthorized,
                                          std::nullopt, "Unauthorized"});
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, LastListenerGone) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(*session_, Unsubscribe(kTrackName));
  publisher_.RemoveObjectListener(&listener_);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, SessionDies) {
  session_.reset();
  EXPECT_CALL(listener_, OnSubscribeRejected);
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, SecondListenerNoSubscribe) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(*session_, Subscribe).Times(0);
  EXPECT_CALL(listener_, OnSubscribeAccepted).Times(0);
  MockMoqtObjectListener listener2;
  publisher_.AddObjectListener(&listener2, MessageParameters());
  EXPECT_CALL(listener_, OnSubscribeAccepted);
  EXPECT_CALL(listener2, OnSubscribeAccepted);
  MessageParameters parameters;
  parameters.largest_object = kLargestLocation;
  publisher_.OnReply(kTrackName,
                     SubscribeOkData{parameters, TrackProperties()});
}

TEST_F(MoqtRelayTrackPublisherTest, OnMalformedObject) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  publisher_.OnMalformedTrack(kTrackName);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, DuplicateObject) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  Location location = kLargestLocation.Next();
  EXPECT_CALL(listener_, OnNewObjectAvailable(location, Optional(0),
                                              /*publisher_priority=*/128));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "foo", MoqtObjectStatus::kNormal,
                              128, location.object == 0, 6},
      "object", /*offset=*/0);
  // Exact duplicate is ignored. It doesn't matter that the arrival time
  // changed.
  EXPECT_CALL(listener_, OnNewObjectAvailable).Times(0);
  EXPECT_CALL(listener_, OnTrackPublisherGone).Times(0);
  EXPECT_FALSE(track_deleted_);
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "foo", MoqtObjectStatus::kNormal,
                              128, location.object == 0, 6,
                              quic::QuicTime::Infinite()},
      "object", /*offset=*/0);
}

TEST_F(MoqtRelayTrackPublisherTest, DuplicateObjectChangedMetadata) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  Location location = kLargestLocation.Next();
  EXPECT_CALL(listener_, OnNewObjectAvailable(location, Optional(0),
                                              /*publisher_priority=*/128));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "foo", MoqtObjectStatus::kNormal,
                              128, location.object == 0, 6},
      "object", /*offset=*/0);
  // Priority change; malformed track.
  EXPECT_CALL(listener_, OnNewObjectAvailable).Times(0);
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "foo", MoqtObjectStatus::kNormal, 64,
                              location.object == 0, 6},
      "object", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, DuplicateObjectChangedPayload) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  Location location = kLargestLocation.Next();
  EXPECT_CALL(listener_, OnNewObjectAvailable(location, Optional(0),
                                              /*publisher_priority=*/128));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "foo", MoqtObjectStatus::kNormal,
                              128, location.object == 0, 7},
      "payload", /*offset=*/0);
  // Payload change; malformed track.
  EXPECT_CALL(listener_, OnNewObjectAvailable).Times(0);
  EXPECT_CALL(listener_, OnTrackPublisherGone);
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, 0, "foo", MoqtObjectStatus::kNormal,
                              128, location.object == 0, 6},
      "foobar", /*offset=*/0);
  EXPECT_TRUE(track_deleted_);
}

TEST_F(MoqtRelayTrackPublisherTest, Fin) {
  SubscribeAndOk();

  // No stream to FIN.
  EXPECT_CALL(listener_, OnNewFinAvailable).Times(0);
  publisher_.OnStreamFin(kTrackName, DataStreamIndex{2, 0});

  ObjectArrives(Location(4, 0), 0, MoqtObjectStatus::kNormal, "object", false);
  std::optional<PublishedObject> object = publisher_.GetCachedObject(4, 0, 0);
  EXPECT_FALSE(object.has_value() && object->fin_after_this);

  EXPECT_CALL(listener_, OnNewFinAvailable(Location(4, 0), 0));
  publisher_.OnStreamFin(kTrackName, DataStreamIndex{4, 0});
  // Object now has fin_after_this set.
  object = publisher_.GetCachedObject(4, 0, 0);
  EXPECT_TRUE(object.has_value() && object->fin_after_this);
}

TEST_F(MoqtRelayTrackPublisherTest, Reset) {
  SubscribeAndOk();

  EXPECT_CALL(listener_, OnSubgroupAbandoned(2, 0, kResetCodeCancelled));
  publisher_.OnStreamReset(kTrackName, DataStreamIndex{2, 0});
}

TEST_F(MoqtRelayTrackPublisherTest, SecondSubscribeAfterOk) {
  SubscribeAndOk();
  EXPECT_CALL(*session_, Subscribe).Times(0);
  MockMoqtObjectListener listener2;
  EXPECT_CALL(listener2, OnSubscribeAccepted);
  publisher_.AddObjectListener(&listener2, MessageParameters());
}

TEST_F(MoqtRelayTrackPublisherTest, DatagramPreference) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  EXPECT_CALL(listener_,
              OnNewObjectAvailable(location, testing::Eq(std::nullopt),
                                   /*publisher_priority=*/128));
  publisher_.OnObjectFragment(
      kTrackName,
      PublishedObjectMetadata{location, std::nullopt, "",
                              MoqtObjectStatus::kNormal, 128, std::nullopt, 6},
      "object", /*offset=*/0);
  std::optional<PublishedObject> object =
      publisher_.GetCachedObject(location.group, std::nullopt, 0);
  EXPECT_TRUE(object.has_value() && !object->metadata.subgroup.has_value());
}

TEST_F(MoqtRelayTrackPublisherTest, ObjectArrivalInFragments) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  uint64_t subgroup = 0;
  // Total size is 15 bytes.
  PublishedObjectMetadata metadata = {location, subgroup,
                                      "",       MoqtObjectStatus::kNormal,
                                      128,      location.object == 0,
                                      15};

  // Fragment 1 arrives.
  EXPECT_CALL(listener_,
              OnNewObjectAvailable(location, Optional(subgroup), 128));
  publisher_.OnObjectFragment(kTrackName, metadata, "frag1", 0);

  // Fragment 2 arrives.
  EXPECT_CALL(listener_,
              OnNewObjectAvailable(location, Optional(subgroup), 128));
  publisher_.OnObjectFragment(kTrackName, metadata, "frag2", 5);

  // Session retrieves the object with two fragments.
  std::optional<PublishedObject> object =
      publisher_.GetCachedObject(location.group, subgroup, location.object, 0);
  ASSERT_TRUE(object.has_value());
  std::string payload;
  for (const auto& slice : object->payload) {
    payload += std::string(slice.AsStringView());
  }
  EXPECT_EQ(payload, "frag1frag2");

  // Fragment 3 arrives.
  EXPECT_CALL(listener_,
              OnNewObjectAvailable(location, Optional(subgroup), 128));
  publisher_.OnObjectFragment(kTrackName, metadata, "frag3", 10);

  // Third fragment retrieved separately.
  object =
      publisher_.GetCachedObject(location.group, subgroup, location.object, 10);
  ASSERT_TRUE(object.has_value());
  payload.clear();
  for (const auto& slice : object->payload) {
    payload += std::string(slice.AsStringView());
  }
  EXPECT_EQ(payload, "frag3");
}

TEST_F(MoqtRelayTrackPublisherTest, IncompleteDatagram) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  PublishedObjectMetadata metadata = {
      location, std::nullopt, "", MoqtObjectStatus::kNormal,
      128,      std::nullopt, 10};
  // Fragment length mismatch.
  EXPECT_QUICHE_BUG(
      publisher_.OnObjectFragment(kTrackName, metadata, "short", 0),
      "Received a partial datagram.");
  // Non-zero offset for datagram.
  EXPECT_QUICHE_BUG(
      publisher_.OnObjectFragment(kTrackName, metadata, "payload10", 1),
      "Received a partial datagram.");
}

TEST_F(MoqtRelayTrackPublisherTest, AlreadyReceivedFragment) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  uint64_t subgroup = 0;
  // Total size is 15 bytes.
  PublishedObjectMetadata metadata = {location, subgroup,
                                      "",       MoqtObjectStatus::kNormal,
                                      128,      location.object == 0,
                                      15};

  // Fragment 1 arrives (first 10 bytes).
  EXPECT_CALL(listener_,
              OnNewObjectAvailable(location, Optional(subgroup), 128));
  publisher_.OnObjectFragment(kTrackName, metadata, "0123456789", 0);

  // Send a fragment that has already been fully received.
  // Partial overlap, matches earlier data. Append() will be called with
  // (0, "01234").
  // Since payload_received_ (10) > 0 + 5, Append() returns false.
  // OnObjectFragment should just return without notifying listeners.
  EXPECT_CALL(listener_, OnNewObjectAvailable).Times(0);
  publisher_.OnObjectFragment(kTrackName, metadata, "01234", 0);

  std::optional<PublishedObject> object =
      publisher_.GetCachedObject(location.group, subgroup, location.object, 0);
  ASSERT_TRUE(object.has_value());
  // Verify that only the first 10 bytes are cached.
  std::string payload;
  for (const auto& slice : object->payload) {
    payload += std::string(slice.AsStringView());
  }
  EXPECT_EQ(payload, "0123456789");
}

// Repro for b/539633547.
TEST_F(MoqtRelayTrackPublisherTest,
       GetCachedObjectWithOffsetReturnsNulloptAtEnd) {
  SubscribeAndOk();
  Location location = kLargestLocation.Next();
  uint64_t subgroup = 0;
  PublishedObjectMetadata metadata = {location, subgroup,
                                      "",       MoqtObjectStatus::kNormal,
                                      128,      location.object == 0,
                                      1000};
  EXPECT_CALL(listener_,
              OnNewObjectAvailable(location, Optional(subgroup), 128));
  publisher_.OnObjectFragment(kTrackName, metadata, std::string(900, 'a'), 0);
  std::optional<PublishedObject> object =
      publisher_.GetCachedObject(location.group, subgroup, location.object, 0);
  ASSERT_TRUE(object.has_value());
  object = publisher_.GetCachedObject(location.group, subgroup, location.object,
                                      900);
  EXPECT_FALSE(object.has_value());
}

TEST_F(MoqtRelayTrackPublisherTest, ForwardObjectAck) {
  SubscribeAndOk();
  EXPECT_NE(publisher_.GetMonitoringInterface(), nullptr);

  bool ack_received = false;
  MoqtObjectAckFunction ack_function = [&](uint64_t group, uint64_t object,
                                           quic::QuicTimeDelta delta) {
    EXPECT_EQ(group, 10);
    EXPECT_EQ(object, 20);
    EXPECT_EQ(delta, quic::QuicTimeDelta::FromMilliseconds(50));
    ack_received = true;
  };
  publisher_.OnCanAckObjects(std::move(ack_function));

  publisher_.GetMonitoringInterface()->OnObjectAckReceived(
      Location(10, 20), quic::QuicTimeDelta::FromMilliseconds(50));
  EXPECT_TRUE(ack_received);
}

TEST_F(MoqtRelayTrackPublisherTest, ObjectAckBeforeCanAck) {
  SubscribeAndOk();
  // OnObjectAckReceived called before OnCanAckObjects should not crash.
  publisher_.GetMonitoringInterface()->OnObjectAckReceived(
      Location(1, 2), quic::QuicTimeDelta::FromMilliseconds(10));
}

TEST_F(MoqtRelayTrackPublisherTest, ObjectAckAfterTrackDeleted) {
  SubscribeAndOk();
  bool ack_called = false;
  publisher_.OnCanAckObjects(
      [&](uint64_t, uint64_t, quic::QuicTimeDelta) { ack_called = true; });

  publisher_.RemoveObjectListener(&listener_);
  EXPECT_TRUE(track_deleted_);

  // Subsequent ACK received should not call ack_function.
  publisher_.GetMonitoringInterface()->OnObjectAckReceived(
      Location(1, 2), quic::QuicTimeDelta::FromMilliseconds(10));
  EXPECT_FALSE(ack_called);
}

TEST_F(MoqtRelayTrackPublisherTest, ForwardsOackWindowSize) {
  publisher_.set_oack_window_size(quic::QuicTimeDelta::FromMilliseconds(50));
  EXPECT_EQ(publisher_.oack_window_size(),
            quic::QuicTimeDelta::FromMilliseconds(50));
  EXPECT_CALL(
      *session_,
      Subscribe(kTrackName, &publisher_,
                testing::Field(&MessageParameters::oack_window_size,
                               quic::QuicTimeDelta::FromMilliseconds(50))))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
}

TEST_F(MoqtRelayTrackPublisherTest, NewGroupRequestFirstListener) {
  MessageParameters parameters;
  parameters.new_group_request = 4;
  EXPECT_CALL(*session_,
              Subscribe(kTrackName, &publisher_,
                        testing::Field(&MessageParameters::new_group_request,
                                       Optional(4))))
      .WillOnce(testing::Return(true));
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener_, parameters);

  // Receive OnReply with largest_object (3, 2) and dynamic_groups = true.
  // Because pending_new_group_request_ (4) > next_location_.group (3),
  // pending_new_group_request_ is NOT cleared.
  EXPECT_CALL(listener_, OnSubscribeAccepted);
  MessageParameters ok_parameters;
  ok_parameters.largest_object = kLargestLocation;  // Location(3, 2)
  ok_parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  TrackProperties properties(
      /*delivery_timeout=*/std::nullopt,
      /*max_cache_duration=*/std::nullopt,
      /*publisher_priority=*/std::nullopt,
      /*group_order=*/std::nullopt,
      /*dynamic_groups=*/true,
      /*immutable_properties=*/std::nullopt);
  publisher_.OnReply(kTrackName, SubscribeOkData{ok_parameters, properties});

  // Requests with new_group_request <= 4 (including 4 and 0) do not trigger
  // SubscribeUpdate because pending_new_group_request_ is still 4.
  MockMoqtObjectListener listener2;
  EXPECT_CALL(listener2, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener2, parameters);

  MockMoqtObjectListener listener3;
  MessageParameters params_zero;
  params_zero.new_group_request = 0;
  EXPECT_CALL(listener3, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener3, params_zero);

  // When an object in group 4 arrives, next_location_ advances to (4, 1) and
  // pending_new_group_request_ is cleared.
  EXPECT_CALL(listener2, OnNewObjectAvailable);
  EXPECT_CALL(listener3, OnNewObjectAvailable);
  ObjectArrives(Location(4, 0), /*subgroup=*/0, MoqtObjectStatus::kNormal, "a");

  // A subsequent listener requesting group 4 is ignored because
  // next_location_.group is now 4.
  MockMoqtObjectListener listener4;
  EXPECT_CALL(listener4, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener4, parameters);

  // A listener requesting 0 is translated to next_location_.group + 1 (5)
  // because next_location_ > Location(0, 0), and sets
  // pending_new_group_request_ to 5.
  MockMoqtObjectListener listener5;
  EXPECT_CALL(listener5, OnSubscribeAccepted);
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(5)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener5, params_zero);

  // Because listener5 set pending_new_group_request_ to 5, a subsequent
  // listener explicitly requesting group 5 does not trigger a duplicate
  // SubscribeUpdate.
  MockMoqtObjectListener listener6;
  MessageParameters params5;
  params5.new_group_request = 5;
  EXPECT_CALL(listener6, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener6, params5);

  // A listener requesting a higher group ID (6 > 5) preserves the explicit
  // group ID and triggers SubscribeUpdate(6).
  MockMoqtObjectListener listener7;
  MessageParameters params6;
  params6.new_group_request = 6;
  EXPECT_CALL(listener7, OnSubscribeAccepted);
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(6)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener7, params6);
}

TEST_F(MoqtRelayTrackPublisherTest, NewGroupRequestBeforeResponse) {
  EXPECT_CALL(*session_,
              Subscribe(kTrackName, &publisher_,
                        testing::Field(&MessageParameters::new_group_request,
                                       std::nullopt)))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());

  // Before OnReply (!got_response_ is true and next_location_ == (0, 0)), a
  // new_group_request = 0 triggers SubscribeUpdate(0) (not next_location_.group
  // + 1) even though properties_.dynamic_groups() is false.
  MockMoqtObjectListener listener_zero;
  MessageParameters params_zero;
  params_zero.new_group_request = 0;
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(0)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_zero, params_zero);

  // A request with a larger group ID (2 > 0) triggers SubscribeUpdate(2).
  MockMoqtObjectListener listener2;
  MessageParameters params2;
  params2.new_group_request = 2;
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(2)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener2, params2);

  // A subsequent request with the same or smaller group ID does not trigger
  // SubscribeUpdate because pending_new_group_request_ is 2.
  MockMoqtObjectListener listener3;
  MessageParameters params3;
  params3.new_group_request = 2;
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener3, params3);

  MockMoqtObjectListener listener4;
  MessageParameters params4;
  params4.new_group_request = 0;
  publisher_.AddObjectListener(&listener4, params4);

  // A request with a larger group ID (> pending_new_group_request_) triggers
  // SubscribeUpdate.
  MockMoqtObjectListener listener5;
  MessageParameters params5;
  params5.new_group_request = 5;
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(5)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener5, params5);

  // When SUBSCRIBE_OK arrives with LARGEST_OBJECT >= pending_new_group_request_
  // (5), pending_new_group_request_ is cleared, allowing another
  // SUBSCRIBE_UPDATE with NEW_GROUP_REQUEST = 0 (translated to
  // next_location_.group + 1 = 6) even though no object has arrived.
  EXPECT_CALL(listener_, OnSubscribeAccepted);
  EXPECT_CALL(listener_zero, OnSubscribeAccepted);
  EXPECT_CALL(listener2, OnSubscribeAccepted);
  EXPECT_CALL(listener3, OnSubscribeAccepted);
  EXPECT_CALL(listener4, OnSubscribeAccepted);
  EXPECT_CALL(listener5, OnSubscribeAccepted);
  MessageParameters ok_parameters;
  ok_parameters.largest_object = Location(5, 2);
  ok_parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  TrackProperties properties(
      /*delivery_timeout=*/std::nullopt,
      /*max_cache_duration=*/std::nullopt,
      /*publisher_priority=*/std::nullopt,
      /*group_order=*/std::nullopt,
      /*dynamic_groups=*/true,
      /*immutable_properties=*/std::nullopt);
  publisher_.OnReply(kTrackName, SubscribeOkData{ok_parameters, properties});

  MockMoqtObjectListener listener6;
  EXPECT_CALL(listener6, OnSubscribeAccepted);
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(6)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener6, params4);
}

TEST_F(MoqtRelayTrackPublisherTest,
       NewGroupRequestAfterResponseWithoutDynamicGroups) {
  SubscribeAndOk();

  // After OnReply, properties_.dynamic_groups() is false by default, so
  // NEW_GROUP_REQUEST is ignored.
  MockMoqtObjectListener listener2;
  EXPECT_CALL(listener2, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  MessageParameters params;
  params.new_group_request = 0;
  publisher_.AddObjectListener(&listener2, params);

  MockMoqtObjectListener listener3;
  EXPECT_CALL(listener3, OnSubscribeAccepted);
  params.new_group_request = 10;
  publisher_.AddObjectListener(&listener3, params);
}

TEST_F(MoqtRelayTrackPublisherTest,
       NewGroupRequestAfterResponseWithDynamicGroups) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(listener_, OnSubscribeAccepted);
  MessageParameters ok_parameters;
  ok_parameters.largest_object = kLargestLocation;  // Location(3, 2)
  ok_parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  TrackProperties properties(
      /*delivery_timeout=*/std::nullopt,
      /*max_cache_duration=*/std::nullopt,
      /*publisher_priority=*/std::nullopt,
      /*group_order=*/std::nullopt,
      /*dynamic_groups=*/true,
      /*immutable_properties=*/std::nullopt);
  publisher_.OnReply(kTrackName, SubscribeOkData{ok_parameters, properties});

  // 1. No new_group_request parameter -> ignored.
  MockMoqtObjectListener listener_no_param;
  EXPECT_CALL(listener_no_param, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener_no_param, MessageParameters());

  // 2. new_group_request <= next_location_.group (which is 3) and != 0 ->
  // ignored.
  MockMoqtObjectListener listener_old_group;
  EXPECT_CALL(listener_old_group, OnSubscribeAccepted);
  MessageParameters params_old;
  params_old.new_group_request = 3;
  publisher_.AddObjectListener(&listener_old_group, params_old);

  // 3. new_group_request == 0 -> translated to next_location_.group + 1 (4)
  // and triggers SubscribeUpdate(4).
  MockMoqtObjectListener listener_zero;
  EXPECT_CALL(listener_zero, OnSubscribeAccepted);
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(4)),
          testing::_))
      .WillOnce(testing::Return(true));
  MessageParameters params_zero;
  params_zero.new_group_request = 0;
  publisher_.AddObjectListener(&listener_zero, params_zero);

  // 4. Duplicate new_group_request == 0 or 4 while pending is 4 -> ignored.
  MockMoqtObjectListener listener_zero_dup;
  EXPECT_CALL(listener_zero_dup, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener_zero_dup, params_zero);

  MockMoqtObjectListener listener_four_dup;
  EXPECT_CALL(listener_four_dup, OnSubscribeAccepted);
  MessageParameters params_four;
  params_four.new_group_request = 4;
  publisher_.AddObjectListener(&listener_four_dup, params_four);

  // 5. new_group_request > next_location_.group (5 > 3) and > pending (5 > 4)
  // -> triggers SubscribeUpdate(5).
  MockMoqtObjectListener listener_five;
  EXPECT_CALL(listener_five, OnSubscribeAccepted);
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(5)),
          testing::_))
      .WillOnce(testing::Return(true));
  MessageParameters params_five;
  params_five.new_group_request = 5;
  publisher_.AddObjectListener(&listener_five, params_five);

  // 6. Request with <= pending (e.g. 5 or 0) -> ignored.
  MockMoqtObjectListener listener_five_dup;
  EXPECT_CALL(listener_five_dup, OnSubscribeAccepted);
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  publisher_.AddObjectListener(&listener_five_dup, params_five);

  // 7. When an object from group 4 arrives, pending_new_group_request_ is
  // cleared and next_location_.group advances to 4.
  EXPECT_CALL(listener_no_param, OnNewObjectAvailable);
  EXPECT_CALL(listener_old_group, OnNewObjectAvailable);
  EXPECT_CALL(listener_zero, OnNewObjectAvailable);
  EXPECT_CALL(listener_zero_dup, OnNewObjectAvailable);
  EXPECT_CALL(listener_four_dup, OnNewObjectAvailable);
  EXPECT_CALL(listener_five, OnNewObjectAvailable);
  EXPECT_CALL(listener_five_dup, OnNewObjectAvailable);
  ObjectArrives(Location(4, 0), /*subgroup=*/0, MoqtObjectStatus::kNormal, "a");

  // Now that pending_new_group_request_ is cleared, a new request with 0
  // triggers SubscribeUpdate(5) (next_location_.group + 1).
  MockMoqtObjectListener listener_after_new_group;
  EXPECT_CALL(listener_after_new_group, OnSubscribeAccepted);
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(5)),
          testing::_))
      .WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_after_new_group, params_zero);
}

TEST_F(MoqtRelayTrackPublisherTest, UpdateObjectListenerNotFound) {
  SubscribeAndOk();
  MockMoqtObjectListener listener;
  EXPECT_TRUE(IsNotFound(
      publisher_.UpdateObjectListener(&listener, MessageParameters())));
}

TEST_F(MoqtRelayTrackPublisherTest, UpdateObjectListenerUpstreamClosed) {
  SubscribeAndOk();
  session_.reset();
  EXPECT_TRUE(IsInternal(
      publisher_.UpdateObjectListener(&listener_, MessageParameters())));
}

TEST_F(MoqtRelayTrackPublisherTest, UpdateObjectListenerClosing) {
  SubscribeAndOk();
  publisher_.Close();
  EXPECT_TRUE(IsInternal(
      publisher_.UpdateObjectListener(&listener_, MessageParameters())));
}

TEST_F(MoqtRelayTrackPublisherTest,
       UpdateObjectListenerForwardsNewGroupRequest) {
  EXPECT_CALL(*session_, Subscribe).WillOnce(testing::Return(true));
  publisher_.AddObjectListener(&listener_, MessageParameters());
  EXPECT_CALL(listener_, OnSubscribeAccepted);
  MessageParameters ok_parameters;
  ok_parameters.largest_object = kLargestLocation;  // Location(3, 2)
  ok_parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  TrackProperties properties(
      /*delivery_timeout=*/std::nullopt,
      /*max_cache_duration=*/std::nullopt,
      /*publisher_priority=*/std::nullopt,
      /*group_order=*/std::nullopt,
      /*dynamic_groups=*/true,
      /*immutable_properties=*/std::nullopt);
  publisher_.OnReply(kTrackName, SubscribeOkData{ok_parameters, properties});

  // 1. Update with new_group_request = 4 forwards to session->SubscribeUpdate
  // and passes the callback through.
  MessageParameters update_params;
  update_params.new_group_request = 4;
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(4)),
          testing::_))
      .WillOnce(testing::Return(true));
  QUICHE_EXPECT_OK(publisher_.UpdateObjectListener(&listener_, update_params));

  // 2. Subsequent update with same new_group_request while pending does not
  // call SubscribeUpdate and immediately invokes the callback with
  // MessageParameters().
  EXPECT_CALL(*session_, SubscribeUpdate).Times(0);
  QUICHE_EXPECT_OK(publisher_.UpdateObjectListener(&listener_, update_params));

  // 3. After group 4 arrives, new_group_request = 0 translates to
  // next_location_.group + 1 (5), triggers SubscribeUpdate(5), and passes the
  // callback through.
  ObjectArrives(Location(4, 0), /*subgroup=*/0, MoqtObjectStatus::kNormal, "a");
  MessageParameters params_zero;
  params_zero.new_group_request = 0;
  MoqtResponseCallback saved_callback3;
  EXPECT_CALL(
      *session_,
      SubscribeUpdate(
          kTrackName,
          testing::Field(&MessageParameters::new_group_request, Optional(5)),
          testing::_))
      .WillOnce([&](const FullTrackName&, const MessageParameters&,
                    MoqtResponseCallback cb) {
        saved_callback3 = std::move(cb);
        return true;
      });
  QUICHE_EXPECT_OK(publisher_.UpdateObjectListener(&listener_, params_zero));
}

}  // namespace

}  // namespace moqt::test
