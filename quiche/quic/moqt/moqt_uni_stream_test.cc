// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_uni_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/moqt/test_tools/moqt_session_peer.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {

namespace {

using ::testing::Optional;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;

PublishedObject DefaultObject() {
  PublishedObject object;
  object.metadata.location = Location(0, 0);
  object.metadata.subgroup = 0;
  object.metadata.status = MoqtObjectStatus::kNormal;
  object.metadata.arrival_time = quic::QuicTime::Zero();
  object.metadata.payload_length = 7;
  object.payload.push_back(quiche::QuicheMemSlice::Copy("payload"));
  object.fin_after_this = false;
  return object;
}

class MockSubscriptionPublisherInterface
    : public SubscriptionPublisherInterface {
 public:
  MockSubscriptionPublisherInterface() : weak_ptr_factory_(this) {}

  MOCK_METHOD(bool, InWindow, (Location), (override));
  MOCK_METHOD(bool, alternate_delivery_timeout, (), (override));
  MOCK_METHOD(quic::QuicClock*, clock, (), (override));
  MOCK_METHOD(quic::QuicTimeDelta, delivery_timeout, (), (override));
  MOCK_METHOD(quic::QuicAlarmFactory*, alarm_factory, (), (override));
  MOCK_METHOD(void, OnObjectSent, (Location), (override));
  MOCK_METHOD(void, OnStreamTimeout, (DataStreamIndex), (override));
  MOCK_METHOD(void, OnSubgroupAbandoned,
              (uint64_t, uint64_t, webtransport::StreamErrorCode), (override));
  MOCK_METHOD(void, OnDataStreamDestroyed, (DataStreamIndex), (override));

  quiche::QuicheWeakPtr<SubscriptionPublisherInterface> GetWeakPtr() {
    return weak_ptr_factory_.Create();
  }

 private:
  quiche::QuicheWeakPtrFactory<SubscriptionPublisherInterface>
      weak_ptr_factory_;
};

class OutgoingSubgroupStreamTest : public quic::test::QuicTest {
 public:
  OutgoingSubgroupStreamTest()
      : index_(0, 0),
        track_publisher_(std::make_shared<StrictMock<MockTrackPublisher>>(
            FullTrackName("foo", "bar"))),
        trace_recorder_(nullptr) {
    EXPECT_CALL(mock_stream_, GetStreamId()).WillRepeatedly(Return(14));
    CreateStream();
  }
  ~OutgoingSubgroupStreamTest() override {
    EXPECT_CALL(visitor_, OnDataStreamDestroyed(index_));
  }

  void CreateStream(uint64_t next_object = 0) { CreateStream(0, next_object); }
  void CreateStream(uint64_t subgroup, uint64_t next_object) {
    EXPECT_CALL(mock_stream_, SetPriority);
    index_ = DataStreamIndex(0, subgroup);
    stream_ = std::make_unique<OutgoingSubgroupStream>(
        framer_, &mock_stream_, index_, next_object, visitor_.GetWeakPtr(),
        track_publisher_, webtransport::StreamPriority(), 0, &trace_recorder_);
  }

  void ExpectFin() {
    EXPECT_CALL(mock_stream_, Writev)
        .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                     const webtransport::StreamWriteOptions& options) {
          EXPECT_TRUE(data.empty());
          EXPECT_TRUE(options.send_fin());
          return absl::OkStatus();
        });
  }

  void ExpectAlarm() {
    EXPECT_CALL(visitor_, alarm_factory()).WillOnce(Return(&alarm_factory_));
  }

  MoqtFramer framer_{true, quic::Perspective::IS_CLIENT};
  StrictMock<webtransport::test::MockStream> mock_stream_;
  DataStreamIndex index_;
  std::shared_ptr<StrictMock<MockTrackPublisher>> track_publisher_;
  StrictMock<MockSubscriptionPublisherInterface> visitor_;
  MoqtTraceRecorder trace_recorder_;
  TrackExtensions track_extensions_;
  quic::MockClock mock_clock_;
  quic::test::MockAlarmFactory alarm_factory_;
  std::unique_ptr<OutgoingSubgroupStream> stream_;
};

TEST_F(OutgoingSubgroupStreamTest, OnCanWrite) {
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(false));
  stream_->OnCanWrite();
}

TEST_F(OutgoingSubgroupStreamTest, OnStopSendingReceived) {
  EXPECT_CALL(visitor_, OnSubgroupAbandoned(index_.group, index_.subgroup, 1));
  stream_->OnStopSendingReceived(1);
}

TEST_F(OutgoingSubgroupStreamTest, DeliveryTimeoutAlarm) {
  OutgoingSubgroupStream::DeliveryTimeoutDelegate delegate(stream_.get());
  EXPECT_CALL(visitor_, OnStreamTimeout(index_));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeDeliveryTimeout));
  delegate.OnAlarm();
}

TEST_F(OutgoingSubgroupStreamTest, OnCanWriteCompleteFlow) {
  PublishedObject obj0 = DefaultObject();
  EXPECT_CALL(mock_stream_, CanWrite())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 0))
      .WillOnce(Return(std::move(obj0)));
  EXPECT_CALL(visitor_, InWindow(Location(0, 0))).WillOnce(Return(true));
  EXPECT_CALL(visitor_, delivery_timeout())
      .WillOnce(Return(quic::QuicTimeDelta::FromSeconds(1)));
  EXPECT_CALL(visitor_, alternate_delivery_timeout()).WillOnce(Return(false));
  EXPECT_CALL(visitor_, clock()).WillOnce(Return(&mock_clock_));
  EXPECT_CALL(*track_publisher_, extensions())
      .WillRepeatedly(ReturnRef(track_extensions_));
  EXPECT_CALL(mock_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(visitor_, OnObjectSent(Location(0, 0)));
  stream_->OnCanWrite();
}

TEST_F(OutgoingSubgroupStreamTest, OnCanWriteNotInWindow) {
  PublishedObject obj0 = DefaultObject();

  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 0))
      .WillOnce(Return(std::move(obj0)));
  EXPECT_CALL(visitor_, InWindow(Location(0, 0))).WillOnce(Return(false));
  ExpectFin();
  stream_->OnCanWrite();
}

TEST_F(OutgoingSubgroupStreamTest, OnCanWriteTimeout) {
  PublishedObject obj0 = DefaultObject();
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 0))
      .WillOnce(Return(std::move(obj0)));
  EXPECT_CALL(visitor_, InWindow(Location(0, 0))).WillOnce(Return(true));
  EXPECT_CALL(visitor_, delivery_timeout())
      .WillOnce(Return(quic::QuicTimeDelta::FromSeconds(1)));
  EXPECT_CALL(visitor_, alternate_delivery_timeout()).WillOnce(Return(false));
  mock_clock_.AdvanceTime(quic::QuicTimeDelta::FromSeconds(2));
  EXPECT_CALL(visitor_, clock()).WillOnce(Return(&mock_clock_));
  EXPECT_CALL(visitor_, OnStreamTimeout(index_));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeDeliveryTimeout));
  stream_->OnCanWrite();
}

TEST_F(OutgoingSubgroupStreamTest, OnCanWriteWriteError) {
  PublishedObject obj0 = DefaultObject();
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 0))
      .WillOnce(Return(std::move(obj0)));
  EXPECT_CALL(visitor_, InWindow(Location(0, 0))).WillOnce(Return(true));
  EXPECT_CALL(visitor_, delivery_timeout())
      .WillOnce(Return(quic::QuicTimeDelta::FromSeconds(1)));
  EXPECT_CALL(visitor_, alternate_delivery_timeout()).WillOnce(Return(false));
  EXPECT_CALL(visitor_, clock).WillOnce(Return(&mock_clock_));
  EXPECT_CALL(*track_publisher_, extensions())
      .WillRepeatedly(ReturnRef(track_extensions_));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce(Return(absl::InternalError("error")));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeInternalError));
  EXPECT_QUICHE_BUG(
      stream_->OnCanWrite(),
      "Writing into MoQT stream failed despite CanWrite being true before; "
      "status: INTERNAL: error");
}

TEST_F(OutgoingSubgroupStreamTest, OnCanWriteSetsAlarm) {
  PublishedObject obj0 = DefaultObject();
  obj0.fin_after_this = true;
  EXPECT_CALL(mock_stream_, CanWrite())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 0))
      .WillOnce(Return(std::move(obj0)));
  EXPECT_CALL(visitor_, InWindow(Location(0, 0))).WillOnce(Return(true));
  EXPECT_CALL(visitor_, delivery_timeout())
      .WillRepeatedly(Return(quic::QuicTimeDelta::FromSeconds(1)));
  EXPECT_CALL(visitor_, alternate_delivery_timeout())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(visitor_, clock).WillOnce(Return(&mock_clock_));

  EXPECT_CALL(*track_publisher_, extensions())
      .WillRepeatedly(ReturnRef(track_extensions_));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  EXPECT_CALL(visitor_, OnObjectSent(Location(0, 0)));
  ExpectAlarm();
  stream_->OnCanWrite();
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeDeliveryTimeout));
  EXPECT_CALL(visitor_, OnStreamTimeout(index_));
  alarm_factory_.FireAlarm(OutgoingSubgroupStreamPeer::GetAlarm(stream_.get()));
}

TEST_F(OutgoingSubgroupStreamTest, Fin) {
  // Replace stream_ with one where next_object_ is 1.
  EXPECT_CALL(visitor_, OnDataStreamDestroyed(index_));
  CreateStream(1);
  // last_object.object < next_object: sends pure FIN
  ExpectFin();
  EXPECT_CALL(visitor_, delivery_timeout())
      .WillOnce(Return(quic::QuicTimeDelta::FromSeconds(1)));
  EXPECT_CALL(visitor_, clock()).WillOnce(Return(&mock_clock_));
  ExpectAlarm();
  stream_->Fin(Location(0, 0));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeDeliveryTimeout));
  EXPECT_CALL(visitor_, OnStreamTimeout(index_));
  alarm_factory_.FireAlarm(OutgoingSubgroupStreamPeer::GetAlarm(stream_.get()));
}

TEST_F(OutgoingSubgroupStreamTest, FinForFutureObject) {
  // Delivery is blocked.
  EXPECT_CALL(mock_stream_, CanWrite).WillOnce(Return(false));
  stream_->OnCanWrite();
  // FIN does nothing because last object hasn't been sent. Rely on the cache
  // to set object.fin_after_this.
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  stream_->Fin(Location(0, 0));
}

TEST_F(OutgoingSubgroupStreamTest, UpdatePriority) {
  EXPECT_CALL(mock_stream_, SetPriority(webtransport::StreamPriority{
                                0, 0x3fc0000000000000ULL}));
  stream_->UpdatePriority(0);
}

TEST_F(OutgoingSubgroupStreamTest, SendFragmentedObject) {
  PublishedObject obj0 = DefaultObject();
  obj0.metadata.payload_length = 15;
  obj0.payload.clear();
  obj0.payload.push_back(quiche::QuicheMemSlice::Copy("part1"));
  obj0.payload.push_back(quiche::QuicheMemSlice::Copy("part2"));
  obj0.fin_after_this = true;
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 0))
      .WillOnce(Return(std::move(obj0)));
  EXPECT_CALL(visitor_, InWindow).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(visitor_, delivery_timeout())
      .WillRepeatedly(Return(quic::QuicTimeDelta::FromSeconds(1)));
  EXPECT_CALL(visitor_, alternate_delivery_timeout())
      .WillRepeatedly(Return(false));
  EXPECT_CALL(visitor_, clock()).WillRepeatedly(Return(&mock_clock_));
  EXPECT_CALL(*track_publisher_, extensions())
      .WillRepeatedly(ReturnRef(track_extensions_));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(data.size(), 3);
        EXPECT_EQ(data[1].AsStringView(), "part1");
        EXPECT_EQ(data[2].AsStringView(), "part2");
        EXPECT_FALSE(options.send_fin());
        return absl::OkStatus();
      });
  EXPECT_CALL(visitor_, OnObjectSent(Location(0, 0)));
  stream_->OnCanWrite();
  PublishedObject obj1 = DefaultObject();
  obj1.metadata.payload_length = 15;
  obj1.payload.clear();
  obj1.payload.push_back(quiche::QuicheMemSlice::Copy("part3"));
  obj1.fin_after_this = true;
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 0, 10))
      .WillOnce(Return(std::move(obj1)));
  EXPECT_CALL(*track_publisher_, GetCachedObject(0, Optional(0), 1, 0))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(data.size(), 1);
        EXPECT_EQ(data[0].AsStringView(), "part3");
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  EXPECT_CALL(visitor_, OnObjectSent).Times(0);
  ExpectAlarm();
  stream_->OnCanWrite();
}

class OutgoingFetchStreamTest : public quic::test::QuicTest {
 public:
  OutgoingFetchStreamTest()
      : task_(std::make_unique<StrictMock<MockFetchTask>>()),
        task_ptr_(task_.get()),
        trace_recorder_(nullptr) {
    EXPECT_CALL(mock_stream_, GetStreamId()).WillRepeatedly(Return(14));
    EXPECT_CALL(mock_stream_, SetPriority);
    stream_ = std::make_unique<OutgoingFetchStream>(
        framer_, &mock_stream_, 10, webtransport::StreamPriority(),
        std::move(task_), [this]() { close_callback_called_ = true; },
        &trace_recorder_);
  }
  ~OutgoingFetchStreamTest() override {
    stream_.reset();
    EXPECT_TRUE(close_callback_called_);
  }

 protected:
  MoqtFramer framer_{true, quic::Perspective::IS_CLIENT};
  StrictMock<webtransport::test::MockStream> mock_stream_;
  std::unique_ptr<StrictMock<MockFetchTask>> task_;
  MockFetchTask* task_ptr_;
  MoqtTraceRecorder trace_recorder_;
  bool close_callback_called_ = false;
  std::unique_ptr<OutgoingFetchStream> stream_;
};

TEST_F(OutgoingFetchStreamTest, OnCanWritePending) {
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*task_ptr_, GetNextObject)
      .WillOnce(Return(MoqtFetchTask::kPending));
  stream_->OnCanWrite();
}

TEST_F(OutgoingFetchStreamTest, OnCanWriteSuccess) {
  PublishedObject obj = DefaultObject();
  EXPECT_CALL(mock_stream_, CanWrite())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*task_ptr_, GetNextObject).WillOnce([&](PublishedObject& out) {
    out = std::move(obj);
    return MoqtFetchTask::kSuccess;
  });
  EXPECT_CALL(mock_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  stream_->OnCanWrite();
}

TEST_F(OutgoingFetchStreamTest, OnCanWriteNonNormalStatus) {
  PublishedObject obj = DefaultObject();
  obj.metadata.status = MoqtObjectStatus::kObjectDoesNotExist;
  EXPECT_CALL(mock_stream_, CanWrite())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*task_ptr_, GetNextObject).WillOnce([&](PublishedObject& out) {
    out = std::move(obj);
    return MoqtFetchTask::kSuccess;
  });
  EXPECT_QUICHE_BUG(stream_->OnCanWrite(), "Got Non-normal object in FETCH");
}

TEST_F(OutgoingFetchStreamTest, OnCanWriteEof) {
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*task_ptr_, GetNextObject).WillOnce(Return(MoqtFetchTask::kEof));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(data.empty());
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  stream_->OnCanWrite();
}

TEST_F(OutgoingFetchStreamTest, OnCanWriteEofFail) {
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*task_ptr_, GetNextObject).WillOnce(Return(MoqtFetchTask::kEof));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce(Return(absl::InternalError("error")));
  stream_->OnCanWrite();
}

TEST_F(OutgoingFetchStreamTest, OnCanWriteWriteError) {
  PublishedObject obj = DefaultObject();
  EXPECT_CALL(mock_stream_, CanWrite())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(*task_ptr_, GetNextObject).WillOnce([&](PublishedObject& out) {
    out = std::move(obj);
    return MoqtFetchTask::kSuccess;
  });
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce(Return(absl::InternalError("error")));
  EXPECT_QUICHE_BUG(stream_->OnCanWrite(),
                    "Writing into MoQT stream failed despite CanWrite being "
                    "true before; status: INTERNAL: error");
}

TEST_F(OutgoingFetchStreamTest, OnCanWriteError) {
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*task_ptr_, GetNextObject)
      .WillOnce(Return(MoqtFetchTask::kError));
  EXPECT_CALL(*task_ptr_, GetStatus())
      .WillOnce(Return(absl::InternalError("error")));
  EXPECT_CALL(
      mock_stream_,
      ResetWithUserCode(static_cast<uint64_t>(absl::StatusCode::kInternal)));
  stream_->OnCanWrite();
}

TEST_F(OutgoingFetchStreamTest, OnStopSendingReceived) {
  EXPECT_CALL(mock_stream_, ResetWithUserCode(17));
  stream_->OnStopSendingReceived(17);
}

TEST_F(OutgoingFetchStreamTest, UpdatePriority) {
  EXPECT_CALL(mock_stream_, SetPriority(webtransport::StreamPriority{
                                0, 0x3fc0000000000000ULL}));
  stream_->UpdatePriority(0);
}

TEST_F(OutgoingFetchStreamTest, ObjectAvailableCallback) {
  EXPECT_CALL(mock_stream_, CanWrite()).WillOnce(Return(false));
  task_ptr_->CallObjectsAvailableCallback();
}

MoqtObject kDefaultObject = {
    2,     // track_alias
    0,     // group_id
    0,     // object_id
    0x80,  // publisher_priority
    "",    // extension_headers
    MoqtObjectStatus::kNormal,
    0,  // subgroup_id
    0,  // payload_length
};

class MockSessionToUniStreamInterface : public SessionToUniStreamInterface {
 public:
  MockSessionToUniStreamInterface() = default;
  ~MockSessionToUniStreamInterface() override = default;

  MOCK_METHOD(bool, deliver_partial_objects, (), (const, override));
  MOCK_METHOD(void, OnMalformedTrack, (RemoteTrack*), (override));
  MOCK_METHOD(quiche::QuicheWeakPtr<RemoteTrack>, GetSubscribe, (uint64_t),
              (override));
  MOCK_METHOD(quiche::QuicheWeakPtr<RemoteTrack>, GetFetch, (uint64_t),
              (override));
  MOCK_METHOD(void, Error, (MoqtError, absl::string_view), (override));
};

class IncomingDataStreamTest : public quic::test::QuicTest {
 public:
  IncomingDataStreamTest()
      : mock_stream_(14),
        ftn_("foo", "bar"),
        subscribe_message_(1, ftn_, MessageParameters()) {
    EXPECT_CALL(session_, deliver_partial_objects())
        .WillRepeatedly(Return(false));
    track_ = std::make_unique<SubscribeRemoteTrack>(
        subscribe_message_, &visitor_, []() {},
        [this](uint64_t alias, SubscribeRemoteTrack* track) -> bool {
          alias_ = alias;
          alias_track_ = track;
          return true;
        });
    EXPECT_TRUE(track_->set_track_alias(2));
    CreateStream();
  }

  void CreateStream() {
    stream_ = std::make_unique<IncomingDataStream>(&mock_stream_, &session_,
                                                   &mock_clock_);
  }
  void ProcessStreamType(MoqtDataStreamType type) {
    uint8_t type_byte = static_cast<uint8_t>(type.value());
    mock_stream_.Receive(
        absl::string_view(reinterpret_cast<const char*>(&type_byte), 1), false);
    stream_->OnCanRead();
  }
  void ProcessAlias(uint8_t alias) {
    mock_stream_.Receive(
        absl::string_view(reinterpret_cast<const char*>(&alias), 1), false);
    EXPECT_CALL(session_, GetSubscribe(alias))
        .WillOnce(Return(track_->weak_ptr()));
    stream_->OnCanRead();
    EXPECT_EQ(alias_, alias);
    EXPECT_EQ(alias_track_, track_.get());
  }

  webtransport::test::InMemoryStream mock_stream_;
  testing::NiceMock<MockSessionToUniStreamInterface> session_;
  quic::MockClock mock_clock_;
  FullTrackName ftn_;
  MoqtSubscribe subscribe_message_;
  testing::NiceMock<MockSubscribeRemoteTrackVisitor> visitor_;
  std::unique_ptr<SubscribeRemoteTrack> track_;
  std::unique_ptr<IncomingDataStream> stream_;
  uint64_t alias_ = 0;
  SubscribeRemoteTrack* alias_track_ = nullptr;
};

TEST_F(IncomingDataStreamTest, DestructorBeforeTrackAlias) {
  // The stream doesn't know the track, so there's no visitor to notify.
  EXPECT_CALL(visitor_, OnStreamReset).Times(0);
  stream_.reset();
}

TEST_F(IncomingDataStreamTest, DestructorAfterObject) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  EXPECT_CALL(visitor_, OnObjectFragment);
  stream_->OnObjectMessage(kDefaultObject, "", true);
  EXPECT_CALL(visitor_, OnStreamReset);
  stream_.reset();
}

TEST_F(IncomingDataStreamTest, DestructorAfterFin) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  EXPECT_CALL(visitor_, OnObjectFragment);
  stream_->OnObjectMessage(kDefaultObject, "", true);
  stream_->OnFin();
  EXPECT_CALL(visitor_, OnStreamFin);
  stream_.reset();
}

TEST_F(IncomingDataStreamTest, OnParsingError) {
  EXPECT_CALL(session_,
              Error(MoqtError::kProtocolViolation, "Parse error: reason"))
      .Times(1);
  stream_->OnParsingError(MoqtError::kProtocolViolation, "reason");
}

TEST_F(IncomingDataStreamTest, OnObjectMessageNoTrackAliasError) {
  EXPECT_QUICHE_BUG(stream_->OnObjectMessage(kDefaultObject, "payload", true),
                    "Object delivered without preliminaries");
}

TEST_F(IncomingDataStreamTest, OnObjectMessage) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MoqtObject object = kDefaultObject;
  object.payload_length = 8;
  EXPECT_CALL(visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    const absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(track_name, ftn_);
        EXPECT_EQ(metadata.location, Location(0, 0));
        EXPECT_EQ(metadata.subgroup, 0);
        EXPECT_EQ(metadata.extensions, "");
        EXPECT_EQ(metadata.status, MoqtObjectStatus::kNormal);
        EXPECT_EQ(metadata.publisher_priority, 0x80);
        EXPECT_EQ(metadata.payload_length, 8);
        EXPECT_EQ(received_payload, "deadbeef");
        EXPECT_EQ(offset, 0);
      });
  stream_->OnObjectMessage(object, "deadbeef", true);
}

TEST_F(IncomingDataStreamTest, OnObjectMessageBufferPartialObject) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MoqtObject object = kDefaultObject;
  object.payload_length = 6;
  EXPECT_CALL(visitor_, OnObjectFragment).Times(0);
  stream_->OnObjectMessage(object, "foo", false);
  EXPECT_CALL(visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    const absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(metadata.payload_length, 6);
        EXPECT_EQ(received_payload, "foobar");
        EXPECT_EQ(offset, 0);
      });
  stream_->OnObjectMessage(object, "bar", true);
}

TEST_F(IncomingDataStreamTest, OnObjectMessageDontBufferPartialObject) {
  EXPECT_CALL(session_, deliver_partial_objects()).WillRepeatedly(Return(true));
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MoqtObject object = kDefaultObject;
  object.payload_length = 6;
  EXPECT_CALL(visitor_, OnObjectFragment).Times(0);
  EXPECT_CALL(visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    const absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(metadata.payload_length, 6);
        EXPECT_EQ(received_payload, "foo");
        EXPECT_EQ(offset, 0);
      });
  stream_->OnObjectMessage(object, "foo", false);
  EXPECT_CALL(visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    const absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(metadata.payload_length, 6);
        EXPECT_EQ(received_payload, "bar");
        EXPECT_EQ(offset, 3);
      });
  stream_->OnObjectMessage(object, "bar", true);
  // New object, make sure offset has been reset.
  ++object.object_id;
  EXPECT_CALL(visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    const absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(metadata.payload_length, 6);
        EXPECT_EQ(received_payload, "foobaz");
        EXPECT_EQ(offset, 0);
      });
  stream_->OnObjectMessage(object, "foobaz", true);
}

TEST_F(IncomingDataStreamTest, PartialObjectFetch) {
  EXPECT_CALL(session_, deliver_partial_objects()).WillRepeatedly(Return(true));
  MoqtFetch fetch;
  fetch.request_id = 3;
  StandaloneFetch standalone(ftn_, Location(0, 0), Location(0, 9));
  int objects_available_callbacks = 0;
  std::unique_ptr<MoqtFetchTask> fetch_task;
  auto upstream_fetch = std::make_unique<UpstreamFetch>(
      fetch, standalone,
      [&](std::unique_ptr<MoqtFetchTask> t) { fetch_task = std::move(t); },
      []() {});
  upstream_fetch->OnFetchResult(Location(0, 9), absl::OkStatus(), []() {});
  UpstreamFetch::UpstreamFetchTask* task = upstream_fetch->task();
  task->SetObjectAvailableCallback([&]() { ++objects_available_callbacks; });

  uint8_t stream_header[] = {0x05, 0x03};
  mock_stream_.Receive(
      absl::string_view(reinterpret_cast<const char*>(stream_header), 2),
      false);
  EXPECT_CALL(session_, GetFetch(3))
      .WillOnce(Return(upstream_fetch->weak_ptr()));
  stream_->OnCanRead();

  MoqtObject sent_object = MoqtObject(
      /*request_id=*/0, /*group_id=*/0,
      /*object_id=*/0, /*publisher_priority=*/0x80, /*extension_headers=*/"",
      MoqtObjectStatus::kNormal, /*subgroup_id=*/0, /*payload_length=*/12);
  stream_->OnObjectMessage(sent_object, "foo", false);
  task->NotifyNewObject();
  EXPECT_EQ(objects_available_callbacks, 1);
  PublishedObject received_object;
  EXPECT_EQ(task->GetNextObject(received_object),
            MoqtFetchTask::GetNextObjectResult::kSuccess);
  EXPECT_EQ(task->GetNextObject(received_object),
            MoqtFetchTask::GetNextObjectResult::kPending);
  EXPECT_EQ(sent_object.object_id, received_object.metadata.location.object);
  EXPECT_EQ("foo", received_object.payload[0].AsStringView());
  // Second and third fragments.
  stream_->OnObjectMessage(sent_object, "bar", false);
  task->NotifyNewObject();
  EXPECT_EQ(objects_available_callbacks, 2);
  stream_->OnObjectMessage(sent_object, "baz", false);
  task->NotifyNewObject();
  EXPECT_EQ(objects_available_callbacks, 2);
  received_object.payload.clear();
  EXPECT_EQ(task->GetNextObject(received_object),
            MoqtFetchTask::GetNextObjectResult::kSuccess);
  EXPECT_EQ(task->GetNextObject(received_object),
            MoqtFetchTask::GetNextObjectResult::kPending);
  EXPECT_EQ(sent_object.object_id, received_object.metadata.location.object);
  ASSERT_EQ(received_object.payload.size(), 2);
  EXPECT_EQ("bar", received_object.payload[0].AsStringView());
  EXPECT_EQ("baz", received_object.payload[1].AsStringView());
}

TEST_F(IncomingDataStreamTest, OnObjectMessageInvalidTrack) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  uint8_t alias = 2;
  mock_stream_.Receive(
      absl::string_view(reinterpret_cast<const char*>(&alias), 1), false);
  EXPECT_CALL(session_, GetSubscribe(2))
      .WillOnce(Return(quiche::QuicheWeakPtr<RemoteTrack>()));
  stream_->OnCanRead();
  EXPECT_TRUE(mock_stream_.was_reset());
}

TEST_F(IncomingDataStreamTest, OnObjectMessageNotInWindow) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MessageParameters parameters;
  parameters.set_forward(false);
  track_->Update(parameters);
  EXPECT_CALL(visitor_, OnObjectFragment).Times(0);
  stream_->OnObjectMessage(kDefaultObject, "", true);
}

TEST_F(IncomingDataStreamTest, OnObjectMessageMissingSubgroupId) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MoqtObject object = kDefaultObject;
  object.subgroup_id = std::nullopt;
  EXPECT_QUICHE_BUG(stream_->OnObjectMessage(object, "", true),
                    "Missing subgroup ID on SUBSCRIBE stream");
}

TEST_F(IncomingDataStreamTest, ObjectAfterTrackEnd) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MoqtObject object = kDefaultObject;
  object.object_status = MoqtObjectStatus::kEndOfTrack;
  EXPECT_CALL(visitor_, OnObjectFragment);
  stream_->OnObjectMessage(object, "", true);

  EXPECT_CALL(session_, OnMalformedTrack(track_.get()));
  MoqtObject object2 = object;
  object2.object_id = 1;
  object2.object_status = MoqtObjectStatus::kNormal;
  stream_->OnObjectMessage(object2, "", true);
}

TEST_F(IncomingDataStreamTest, ObjectAfterGroupEnd) {
  ProcessStreamType(MoqtDataStreamType::Subgroup(0, 0, false, 0x80));
  ProcessAlias(2);
  MoqtObject object = kDefaultObject;
  object.object_status = MoqtObjectStatus::kEndOfGroup;
  EXPECT_CALL(visitor_, OnObjectFragment);
  stream_->OnObjectMessage(object, "", true);

  EXPECT_CALL(session_, OnMalformedTrack(track_.get()));
  MoqtObject object2 = object;
  object2.object_id = 1;
  object2.object_status = MoqtObjectStatus::kNormal;
  stream_->OnObjectMessage(object2, "", true);
}

TEST_F(IncomingDataStreamTest, MaybeReadOneObjectUnexpectedState) {
  EXPECT_QUICHE_BUG(stream_->MaybeReadOneObject(),
                    "Requesting object, parser in unexpected state");
}

TEST_F(IncomingDataStreamTest, OnCanReadFetchNewTrackAliasInvalidFetch) {
  char fetch_bytes[] = {0x05, 0x03};
  mock_stream_.Receive(absl::string_view(fetch_bytes, 2), false);
  EXPECT_CALL(session_, GetFetch(3))
      .WillOnce(Return(quiche::QuicheWeakPtr<RemoteTrack>()));
  stream_->OnCanRead();
  EXPECT_TRUE(mock_stream_.was_reset());
}

TEST_F(IncomingDataStreamTest, OnCanReadFetchNewTrackAliasSuccess) {
  MoqtFetch fetch;
  fetch.request_id = 3;
  StandaloneFetch standalone(ftn_, Location(0, 0), Location(0, 9));
  auto upstream_fetch = std::make_unique<UpstreamFetch>(
      fetch, standalone, [](std::unique_ptr<MoqtFetchTask>) {}, []() {});
  upstream_fetch->OnFetchResult(Location(0, 0), absl::OkStatus(), []() {});
  EXPECT_CALL(session_, GetFetch(3))
      .WillOnce(Return(upstream_fetch->weak_ptr()));
  char fetch_bytes[] = {0x05, 0x03};
  mock_stream_.Receive(absl::string_view(fetch_bytes, 2), false);
  stream_->OnCanRead();
}

}  // namespace

}  // namespace moqt::test
