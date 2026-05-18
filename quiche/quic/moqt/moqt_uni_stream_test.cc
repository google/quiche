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
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/quiche_weak_ptr.h"
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

  void CreateStream(uint64_t next_object = 0) {
    EXPECT_CALL(mock_stream_, SetPriority);
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

  MoqtFramer framer_{true};
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
  // last_object.object >= next_object: does nothing
  stream_->Fin(Location(0, 1));
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
  MoqtFramer framer_{true};
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

}  // namespace

}  // namespace moqt::test
