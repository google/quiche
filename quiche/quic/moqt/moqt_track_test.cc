// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_track.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

namespace {

using ::testing::_;

class AlarmDelegate : public quic::QuicAlarm::DelegateWithoutContext {
 public:
  AlarmDelegate(bool* fired) : fired_(fired) {}
  void OnAlarm() override { *fired_ = true; }
  bool* fired_;
};

}  // namespace

class SubscribeRemoteTrackPeer {
 public:
  static MoqtFetchTask* GetFetchTask(SubscribeRemoteTrack* track) {
    return track->fetch_task_.get();
  }
};

class SubscribeRemoteTrackTest : public quic::test::QuicTest {
 public:
  SubscribeRemoteTrackTest()
      : track_(
            subscribe_, &visitor_, [this]() { deleted_ = true; },
            [this](uint64_t, SubscribeRemoteTrack* track) {
              alias_registered_ = (track != nullptr);
              if (alias_registered_) {
                EXPECT_EQ(track, &track_);
              }
              return true;
            }) {}

  MockSubscribeRemoteTrackVisitor visitor_;
  MoqtSubscribe subscribe_ = {/*request_id=*/1, FullTrackName("foo", "bar"),
                              MessageParameters(Location(2, 0))};
  SubscribeRemoteTrack track_;
  bool alias_registered_ = false;
  bool deleted_ = false;
};

TEST_F(SubscribeRemoteTrackTest, Queries) {
  EXPECT_EQ(track_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_EQ(track_.request_id(), 1);
  EXPECT_FALSE(track_.track_alias().has_value());
  EXPECT_EQ(track_.visitor(), &visitor_);
  EXPECT_FALSE(track_.is_fetch());
  EXPECT_TRUE(track_.set_track_alias(1));
  EXPECT_EQ(track_.track_alias(), 1);
}

TEST_F(SubscribeRemoteTrackTest, AllowError) {
  EXPECT_TRUE(track_.ErrorIsAllowed());
  track_.OnObjectOrOk();
  EXPECT_FALSE(track_.ErrorIsAllowed());
}

TEST_F(SubscribeRemoteTrackTest, Windows) {
  EXPECT_TRUE(track_.InWindow(Location(2, 0)));
  EXPECT_FALSE(track_.InWindow(Location(1, 25)));
}

TEST_F(SubscribeRemoteTrackTest, JoiningFetchMultiObject) {
  auto fetch_task = std::make_unique<MockFetchTask>();
  MockFetchTask* task_ptr = fetch_task.get();
  track_.OnJoiningFetchReady(std::move(fetch_task));

  PublishedObject o1, o2;
  o1.metadata.location = Location(2, 0);
  o1.metadata.payload_length = 3;
  o1.payload.push_back(quiche::QuicheMemSlice::Copy("abc"));

  o2.metadata.location = Location(2, 1);
  o2.metadata.payload_length = 3;
  o2.payload.push_back(quiche::QuicheMemSlice::Copy("def"));

  EXPECT_CALL(visitor_,
              OnObjectFragment(track_.full_track_name(), _, "abc", 0));
  EXPECT_CALL(visitor_,
              OnObjectFragment(track_.full_track_name(), _, "def", 0));
  EXPECT_CALL(*task_ptr, GetNextObject)
      .WillOnce([&](PublishedObject& output) {
        output = std::move(o1);
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce([&](PublishedObject& output) {
        output = std::move(o2);
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce(testing::Return(MoqtFetchTask::GetNextObjectResult::kPending));
  task_ptr->CallObjectsAvailableCallback();
  EXPECT_NE(SubscribeRemoteTrackPeer::GetFetchTask(&track_), nullptr);
  EXPECT_CALL(*task_ptr, GetNextObject)
      .WillOnce(testing::Return(MoqtFetchTask::GetNextObjectResult::kEof));
  task_ptr->CallObjectsAvailableCallback();
  EXPECT_EQ(SubscribeRemoteTrackPeer::GetFetchTask(&track_), nullptr);
}

TEST_F(SubscribeRemoteTrackTest, JoiningFetchFragmented) {
  auto fetch_task = std::make_unique<MockFetchTask>();
  MockFetchTask* task_ptr = fetch_task.get();
  track_.OnJoiningFetchReady(std::move(fetch_task));

  PublishedObject part1, part2;
  part1.metadata.location = Location(2, 0);
  part1.metadata.payload_length = 6;
  part1.payload.push_back(quiche::QuicheMemSlice::Copy("abc"));

  part2.metadata.location = Location(2, 0);
  part2.metadata.payload_length = 6;
  part2.payload.push_back(quiche::QuicheMemSlice::Copy("def"));

  EXPECT_CALL(visitor_,
              OnObjectFragment(track_.full_track_name(), _, "abc", 0));
  EXPECT_CALL(visitor_,
              OnObjectFragment(track_.full_track_name(), _, "def", 3));
  EXPECT_CALL(*task_ptr, GetNextObject)
      .WillOnce([&](PublishedObject& output) {
        output = std::move(part1);
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce([&](PublishedObject& output) {
        output = std::move(part2);
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce(testing::Return(MoqtFetchTask::GetNextObjectResult::kPending));
  task_ptr->CallObjectsAvailableCallback();
}

TEST_F(SubscribeRemoteTrackTest, JoiningFetchEmptyPayload) {
  auto fetch_task = std::make_unique<MockFetchTask>();
  MockFetchTask* task_ptr = fetch_task.get();
  track_.OnJoiningFetchReady(std::move(fetch_task));

  PublishedObject o1;
  o1.metadata.location = Location(2, 0);
  o1.metadata.payload_length = 0;
  o1.metadata.status = MoqtObjectStatus::kEndOfGroup;

  // Since object.payload is empty, is called once.
  EXPECT_CALL(visitor_,
              OnObjectFragment(track_.full_track_name(), o1.metadata, "", 0));
  EXPECT_CALL(*task_ptr, GetNextObject)
      .WillOnce([&](PublishedObject& output) {
        output = std::move(o1);
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce(testing::Return(MoqtFetchTask::GetNextObjectResult::kPending));
  task_ptr->CallObjectsAvailableCallback();
}

TEST_F(SubscribeRemoteTrackTest, JoiningFetchError) {
  auto fetch_task = std::make_unique<MockFetchTask>();
  MockFetchTask* task_ptr = fetch_task.get();
  track_.OnJoiningFetchReady(std::move(fetch_task));

  EXPECT_NE(SubscribeRemoteTrackPeer::GetFetchTask(&track_), nullptr);
  EXPECT_CALL(*task_ptr, GetNextObject)
      .WillOnce(testing::Return(MoqtFetchTask::GetNextObjectResult::kError));
  task_ptr->CallObjectsAvailableCallback();
  EXPECT_EQ(SubscribeRemoteTrackPeer::GetFetchTask(&track_), nullptr);
}

class UpstreamFetchTest : public quic::test::QuicTest {
 protected:
  UpstreamFetchTest()
      : fetch_(
            fetch_message_, std::get<StandaloneFetch>(fetch_message_.fetch),
            [&](std::unique_ptr<MoqtFetchTask> task) {
              fetch_task_ = std::move(task);
            },
            [&]() { deleted_ = true; }) {}

  MoqtFetch fetch_message_ = {
      /*request_id=*/1,
      StandaloneFetch(FullTrackName("foo", "bar"), Location(1, 1),
                      Location(3, 100)),
      MessageParameters(),
  };
  // The pointer held by the application.
  UpstreamFetch fetch_;
  std::unique_ptr<MoqtFetchTask> fetch_task_;
  bool deleted_ = false;
};

TEST_F(UpstreamFetchTest, Queries) {
  EXPECT_EQ(fetch_.request_id(), 1);
  EXPECT_EQ(fetch_.full_track_name(), FullTrackName("foo", "bar"));
  EXPECT_TRUE(fetch_.is_fetch());
  EXPECT_FALSE(fetch_.InWindow(Location{1, 0}));
  EXPECT_TRUE(fetch_.InWindow(Location{1, 1}));
  EXPECT_TRUE(fetch_.InWindow(Location{3, 100}));
  EXPECT_FALSE(fetch_.InWindow(Location{3, 101}));
}

TEST_F(UpstreamFetchTest, AllowError) {
  EXPECT_TRUE(fetch_.ErrorIsAllowed());
  fetch_.OnObjectOrOk();
  EXPECT_FALSE(fetch_.ErrorIsAllowed());
}

TEST_F(UpstreamFetchTest, FetchResponse) {
  EXPECT_EQ(fetch_task_, nullptr);
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  EXPECT_NE(fetch_task_, nullptr);
  EXPECT_NE(fetch_.task(), nullptr);
  EXPECT_TRUE(fetch_task_->GetStatus().ok());
}

TEST_F(UpstreamFetchTest, FetchClosedByMoqt) {
  bool terminated = false;
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(),
                       [&]() { terminated = true; });
  bool got_eof = false;
  fetch_task_->SetObjectAvailableCallback([&]() {
    PublishedObject object;
    EXPECT_EQ(fetch_task_->GetNextObject(object),
              MoqtFetchTask::GetNextObjectResult::kEof);
    got_eof = true;
  });
  fetch_.task()->OnStreamAndFetchClosed(std::nullopt, "");
  EXPECT_FALSE(terminated);
  EXPECT_TRUE(got_eof);
}

TEST_F(UpstreamFetchTest, FetchClosedByApplication) {
  bool terminated = false;
  fetch_.OnFetchResult(Location(3, 50), absl::Status(),
                       [&]() { terminated = true; });
  fetch_task_.reset();
  EXPECT_TRUE(terminated);
}

TEST_F(UpstreamFetchTest, ObjectRetrieval) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  PublishedObject object;
  EXPECT_EQ(fetch_task_->GetNextObject(object),
            MoqtFetchTask::GetNextObjectResult::kPending);
  MoqtObject new_object = {1, 3, 0, 128, "", MoqtObjectStatus::kNormal, 0, 6};
  bool got_object = false;
  fetch_task_->SetObjectAvailableCallback([&]() {
    got_object = true;
    EXPECT_EQ(fetch_task_->GetNextObject(object),
              MoqtFetchTask::GetNextObjectResult::kSuccess);
    EXPECT_EQ(object.metadata.location, Location(3, 0));
    EXPECT_EQ(object.metadata.subgroup, 0);
    EXPECT_EQ(object.payload[0].AsStringView(), "foo");
    EXPECT_EQ(object.payload[1].AsStringView(), "bar");
  });
  int got_read_callback = 0;
  fetch_.OnStreamOpened([&]() { ++got_read_callback; });
  EXPECT_FALSE(fetch_.task()->HasObject());
  EXPECT_FALSE(fetch_.task()->NeedsMorePayload());
  fetch_.task()->NewObject(new_object);
  EXPECT_TRUE(fetch_.task()->HasObject());
  EXPECT_TRUE(fetch_.task()->NeedsMorePayload());
  fetch_.task()->AppendPayloadToObject("foo");
  EXPECT_TRUE(fetch_.task()->HasObject());
  EXPECT_TRUE(fetch_.task()->NeedsMorePayload());
  fetch_.task()->AppendPayloadToObject("bar");
  EXPECT_TRUE(fetch_.task()->HasObject());
  EXPECT_FALSE(fetch_.task()->NeedsMorePayload());
  EXPECT_FALSE(got_object);
  EXPECT_EQ(got_read_callback, 1);  // Call from OnStreamOpened().
  fetch_.task()->NotifyNewObject();
  EXPECT_FALSE(fetch_.task()->HasObject());
  EXPECT_FALSE(fetch_.task()->NeedsMorePayload());
  EXPECT_EQ(got_read_callback, 2);  // Call from GetNextObjectResult().
  EXPECT_TRUE(got_object);
}

TEST_F(UpstreamFetchTest, ObjectRetrievalEmptyPayload) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  MoqtObject moqt_obj = {1, 3, 0, 128, "", MoqtObjectStatus::kEndOfGroup, 0, 0};
  fetch_.task()->NewObject(moqt_obj);
  fetch_.task()->NotifyNewObject();
  fetch_.OnStreamOpened([]() {});

  PublishedObject output;
  EXPECT_EQ(fetch_task_->GetNextObject(output),
            MoqtFetchTask::GetNextObjectResult::kSuccess);
  EXPECT_TRUE(output.payload.empty());
  EXPECT_EQ(output.metadata.status, MoqtObjectStatus::kEndOfGroup);
}

TEST_F(UpstreamFetchTest, GetNextObjectAfterEof) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  fetch_.task()->OnStreamAndFetchClosed(std::nullopt, "");

  PublishedObject object;
  EXPECT_EQ(fetch_task_->GetNextObject(object),
            MoqtFetchTask::GetNextObjectResult::kEof);
  // Subsequent calls should still return EOF.
  EXPECT_EQ(fetch_task_->GetNextObject(object),
            MoqtFetchTask::GetNextObjectResult::kEof);
}

TEST_F(UpstreamFetchTest, GetNextObjectEofAtLargestLocation) {
  Location largest(3, 50);
  fetch_.OnFetchResult(largest, absl::OkStatus(), nullptr);
  fetch_.OnStreamOpened([]() {});

  MoqtObject obj1 = {1, 3, 49, 128, "", MoqtObjectStatus::kNormal, 0, 1};
  fetch_.task()->NewObject(obj1);
  fetch_.task()->AppendPayloadToObject("a");
  fetch_.task()->NotifyNewObject();

  PublishedObject out;
  EXPECT_EQ(fetch_task_->GetNextObject(out),
            MoqtFetchTask::GetNextObjectResult::kSuccess);
  // Not at largest location yet.
  EXPECT_EQ(fetch_task_->GetNextObject(out),
            MoqtFetchTask::GetNextObjectResult::kPending);

  MoqtObject obj2 = {1, 3, 50, 128, "", MoqtObjectStatus::kNormal, 0, 1};
  fetch_.task()->NewObject(obj2);
  fetch_.task()->AppendPayloadToObject("b");
  fetch_.task()->NotifyNewObject();

  EXPECT_EQ(fetch_task_->GetNextObject(out),
            MoqtFetchTask::GetNextObjectResult::kSuccess);
  // Reached largest location. EOF should be set.
  EXPECT_EQ(fetch_task_->GetNextObject(out),
            MoqtFetchTask::GetNextObjectResult::kEof);
}

TEST_F(UpstreamFetchTest, CloseWithError) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  fetch_.task()->OnStreamAndFetchClosed(
      static_cast<webtransport::StreamErrorCode>(0x123), "reason");
  PublishedObject out;
  EXPECT_EQ(fetch_task_->GetNextObject(out),
            MoqtFetchTask::GetNextObjectResult::kError);
  EXPECT_FALSE(fetch_task_->GetStatus().ok());
}

TEST_F(UpstreamFetchTest, LocationIsValidOkFirstObjectIdDeclining) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 1), MoqtObjectStatus::kNormal, true));
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 2), MoqtObjectStatus::kNormal, true));
  EXPECT_FALSE(
      fetch_.LocationIsValid(Location(1, 0), MoqtObjectStatus::kNormal, true));
}

TEST_F(UpstreamFetchTest, LocationIsValidPartialObject) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 1), MoqtObjectStatus::kNormal, true));
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 2), MoqtObjectStatus::kNormal, false));
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 2), MoqtObjectStatus::kNormal, false));
}

TEST_F(UpstreamFetchTest, LocationIsValidOkGroupDescendingIncorrectly) {
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(2, 1), MoqtObjectStatus::kNormal, true));
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(3, 1), MoqtObjectStatus::kNormal, true));
  EXPECT_FALSE(
      fetch_.LocationIsValid(Location(1, 1), MoqtObjectStatus::kNormal, true));
}

TEST_F(UpstreamFetchTest, LocationIsValidOkGroupAscendingIncorrectly) {
  fetch_message_.parameters.group_order = MoqtDeliveryOrder::kDescending;
  UpstreamFetch fetch(
      fetch_message_, std::get<StandaloneFetch>(fetch_message_.fetch),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task_ = std::move(task);
      },
      []() {});
  fetch.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  EXPECT_TRUE(
      fetch.LocationIsValid(Location(2, 1), MoqtObjectStatus::kNormal, true));
  EXPECT_FALSE(
      fetch.LocationIsValid(Location(3, 1), MoqtObjectStatus::kNormal, true));
}

TEST_F(UpstreamFetchTest, LocationIsValidLearnOrderThenOkSuccess) {
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 1), MoqtObjectStatus::kNormal, true));
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(2, 1), MoqtObjectStatus::kNormal, true));
  fetch_.OnFetchResult(Location(3, 50), absl::OkStatus(), nullptr);
  //  Groups arrived in ascending order, but the FETCH_OK reported descending.
  EXPECT_TRUE(fetch_task_->GetStatus().ok());
}

TEST_F(UpstreamFetchTest, LocationIsValidObjectBeyondEndOfGroup) {
  EXPECT_TRUE(fetch_.LocationIsValid(Location(1, 1),
                                     MoqtObjectStatus::kEndOfGroup, true));
  EXPECT_FALSE(
      fetch_.LocationIsValid(Location(1, 2), MoqtObjectStatus::kNormal, true));
}

TEST_F(UpstreamFetchTest, LocationIsValidObjectBeyondEndOfTrack) {
  EXPECT_TRUE(fetch_.LocationIsValid(Location(1, 1),
                                     MoqtObjectStatus::kEndOfTrack, true));
  EXPECT_FALSE(
      fetch_.LocationIsValid(Location(2, 1), MoqtObjectStatus::kNormal, true));
}

TEST_F(UpstreamFetchTest, LocationIsValidTwoEndsOfTrack) {
  EXPECT_TRUE(fetch_.LocationIsValid(Location(1, 1),
                                     MoqtObjectStatus::kEndOfTrack, true));
  EXPECT_FALSE(fetch_.LocationIsValid(Location(1, 2),
                                      MoqtObjectStatus::kEndOfTrack, true));
}

TEST_F(UpstreamFetchTest, LocationIsValidEndOfTrackTooLow) {
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(1, 2), MoqtObjectStatus::kNormal, true));
  EXPECT_TRUE(
      fetch_.LocationIsValid(Location(3, 0), MoqtObjectStatus::kNormal, true));
  EXPECT_FALSE(fetch_.LocationIsValid(Location(2, 1),
                                      MoqtObjectStatus::kEndOfTrack, true));
}

TEST_F(UpstreamFetchTest, RelativeJoiningFetch) {
  MoqtFetch relative_fetch_message = {
      /*request_id=*/2,
      JoiningFetchRelative(1, 2),
      MessageParameters(),
  };
  UpstreamFetch relative_fetch(
      relative_fetch_message, FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task_ = std::move(task);
      },
      []() {});
  relative_fetch.OnFetchResult(Location(10, 50), absl::OkStatus(), nullptr);
  EXPECT_FALSE(relative_fetch.InWindow(Location(7, 35)));
  EXPECT_TRUE(relative_fetch.InWindow(Location(8, 0)));
}

TEST_F(UpstreamFetchTest, RelativeJoiningFetchUnderflow) {
  MoqtFetch relative_fetch_message = {
      /*request_id=*/2,
      JoiningFetchRelative(1, 10),
      MessageParameters(),
  };
  UpstreamFetch relative_fetch(
      relative_fetch_message, FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task_ = std::move(task);
      },
      []() {});
  relative_fetch.OnFetchResult(Location(1, 50), absl::OkStatus(), nullptr);
  EXPECT_TRUE(relative_fetch.InWindow(Location(0, 0)));
  EXPECT_TRUE(relative_fetch.InWindow(Location(1, 50)));
}

}  // namespace test

}  // namespace moqt
