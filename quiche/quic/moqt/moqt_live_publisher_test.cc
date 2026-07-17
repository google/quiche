// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_live_publisher.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/casts.h"
#include "absl/base/nullability.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/moqt/test_tools/moqt_session_peer.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {

class LivePublisherPeer {
 public:
  static size_t num_open_streams(LivePublisher* publisher) {
    return publisher->stream_map_.GetAllStreams().size();
  }
  static std::optional<Location> largest_sent(const LivePublisher* publisher) {
    return publisher->largest_sent_;
  }
  static const absl::flat_hash_set<DataStreamIndex>& reset_subgroups(
      const LivePublisher* publisher) {
    return publisher->reset_subgroups_;
  }
};

namespace {

using ::testing::_;
using ::testing::AtLeast;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;
using ::webtransport::DatagramStatus;
using ::webtransport::DatagramStatusCode;

class TestMoqtBidiStream : public MoqtBidiStreamBase {
 public:
  TestMoqtBidiStream(MoqtFramer* absl_nonnull framer,
                     const MoqtControlMessageParser& message_parser,
                     SessionErrorCallback session_error_callback)
      : MoqtBidiStreamBase(framer, message_parser,
                           std::move(session_error_callback)) {}
  ~TestMoqtBidiStream() override = default;
  void OnStreamBound() override {};
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override {
    return absl::OkStatus();
  }
  void Detach() override { detached_ = true; }
  bool detached_ = false;
};

std::optional<PublishedObject> DefaultPublishedObject(
    Location location, std::optional<uint64_t> subgroup,
    MoqtPriority publisher_priority) {
  PublishedObject object;
  object.metadata.location = location;
  object.metadata.subgroup = subgroup;
  object.metadata.status = MoqtObjectStatus::kNormal;
  object.metadata.publisher_priority = publisher_priority;
  object.metadata.extensions = "extensions";
  object.metadata.first_object_in_subgroup =
      subgroup.has_value() ? std::optional<bool>(location.object == 0)
                           : std::nullopt;
  object.metadata.payload_length = 8;
  object.payload.push_back(quiche::QuicheMemSlice::Copy("deadbeef"));
  return object;
}

class LivePublisherTest : public quic::test::QuicTest {
 public:
  LivePublisherTest()
      : track_publisher_(
            std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"))),
        bidi_stream_(&framer_, message_parser_,
                     [](MoqtError, absl::string_view) {}),
        trace_recorder_(nullptr) {
    bidi_stream_.BindStream(&mock_bidi_stream_);
    parameters_.set_forward(true);
    parameters_.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);
    parameters_.group_order = MoqtDeliveryOrder::kAscending;
    EXPECT_CALL(monitoring_interface_, OnObjectAckSupportKnown)
        .Times(AtLeast(0));
    EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
    ON_CALL(visitor_, ReleaseMonitoringInterface)
        .WillByDefault(Return(&monitoring_interface_));
    publisher_ = std::make_unique<LivePublisher>(
        framer_, track_publisher_, &bidi_stream_, kRequestId, kTrackAlias,
        parameters_, visitor_.weak_ptr_factory_.Create(),
        /*is_publish=*/false);
    ON_CALL(visitor_, alternate_delivery_timeout).WillByDefault(Return(false));
    ON_CALL(webtrans_, GetStreamById(kStreamId))
        .WillByDefault(Return(&mock_uni_stream_));
    ON_CALL(visitor_, alarm_factory).WillByDefault(Return(&alarm_factory_));
    ON_CALL(visitor_, clock).WillByDefault(Return(&mock_clock_));
    ON_CALL(visitor_, trace_recorder).WillByDefault(ReturnRef(trace_recorder_));
  }

  ~LivePublisherTest() override {
    if (track_publisher_ == nullptr) {
      return;
    }
    EXPECT_CALL(*track_publisher_, RemoveObjectListener(publisher_.get()));
  }

  MoqtPriority subscriber_priority() const {
    return parameters_.subscriber_priority.value_or(kDefaultSubscriberPriority);
  }

  // Create a stream with the given parameters and send the first object. Will
  // check that the first bytes written to the stream are equal to
  // |opening_bytes|.
  void CreateStream(Location location, uint64_t subgroup,
                    MoqtPriority publisher_priority,
                    std::string opening_bytes = "") {
    EXPECT_CALL(
        *track_publisher_,
        GetCachedObject(location.group, std::make_optional<uint64_t>(subgroup),
                        location.object, 0))
        .WillOnce(Return(  // Once for monitoring interface.
            DefaultPublishedObject(location, subgroup, publisher_priority)))
        .WillOnce(Return(  // To actually deliver the object.
            DefaultPublishedObject(location, subgroup, publisher_priority)));
    EXPECT_CALL(
        *track_publisher_,
        GetCachedObject(location.group, std::make_optional<uint64_t>(subgroup),
                        location.object + 1, 0))
        .WillOnce(Return(std::nullopt));
    // Additional object retrievals will return nullopt.
    EXPECT_CALL(monitoring_interface_, OnNewObjectEnqueued(location));
    EXPECT_CALL(mock_uni_stream_, GetStreamId())
        .WillRepeatedly(Return(kStreamId));
    EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream())
        .WillOnce(Return(true));
    EXPECT_CALL(webtrans_, OpenOutgoingUnidirectionalStream)
        .WillOnce(Return(&mock_uni_stream_));
    EXPECT_CALL(mock_uni_stream_, SetVisitor)
        .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
          uni_stream_ = std::move(visitor);
        });
    EXPECT_CALL(mock_uni_stream_, SetPriority);
    ON_CALL(mock_uni_stream_, visitor()).WillByDefault([&]() {
      return uni_stream_.get();
    });
    EXPECT_CALL(mock_uni_stream_, CanWrite()).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_uni_stream_, Writev)
        .WillOnce([&](absl::Span<quiche::QuicheMemSlice> data,
                      const webtransport::StreamWriteOptions& options) {
          EXPECT_TRUE(absl::StartsWith(data[0].AsStringView(), opening_bytes));
          EXPECT_FALSE(options.send_fin());
          return absl::OkStatus();
        });
    publisher_->OnNewObjectAvailable(location, subgroup, publisher_priority);
    ++open_streams_;
  }

  void CreatePendingStream(Location location, uint64_t subgroup,
                           MoqtPriority publisher_priority) {
    EXPECT_CALL(
        *track_publisher_,
        GetCachedObject(location.group, std::make_optional<uint64_t>(subgroup),
                        location.object, 0))
        .WillOnce(Return(  // Once for monitoring interface.
            DefaultPublishedObject(location, subgroup, publisher_priority)));
    // Additional object retrievals will return nullopt.
    EXPECT_CALL(monitoring_interface_, OnNewObjectEnqueued(location));
    EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream())
        .WillOnce(Return(false));
    EXPECT_CALL(visitor_,
                UpdateTrackPriority(1, _,
                                    MoqtTrackPriority{subscriber_priority(),
                                                      publisher_priority}));
    publisher_->OnNewObjectAvailable(location, subgroup, publisher_priority);
  }

  static constexpr webtransport::StreamId kStreamId = 100;
  static constexpr uint64_t kTrackAlias = 10;
  static constexpr uint64_t kRequestId = 1;

  MoqtFramer framer_{true, quic::Perspective::IS_CLIENT};
  MoqtControlMessageParser message_parser_{kDefaultMoqtVersion, true,
                                           quic::Perspective::IS_CLIENT};
  webtransport::test::MockSession webtrans_;
  StrictMock<webtransport::test::MockStream> mock_bidi_stream_;
  webtransport::test::MockStream mock_uni_stream_;
  std::shared_ptr<MockTrackPublisher> track_publisher_;
  TestMoqtBidiStream bidi_stream_;
  std::unique_ptr<webtransport::StreamVisitor> uni_stream_;
  MessageParameters parameters_;
  MockSessionToPublisherInterface visitor_;
  StrictMock<MockPublishingMonitorInterface> monitoring_interface_;
  MoqtTraceRecorder trace_recorder_;
  std::unique_ptr<LivePublisher> publisher_;
  const TrackExtensions extensions_;
  quic::MockClock mock_clock_;
  MoqtSessionCallbacks callbacks_;
  quic::test::TestAlarmFactory alarm_factory_;
  int open_streams_ = 0;
};

TEST_F(LivePublisherTest, OnSubscribeAcceptedNoFilter) {
  EXPECT_CALL(mock_bidi_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(*track_publisher_, largest_location())
      .WillOnce(Return(Location(1, 2)));
  EXPECT_CALL(*track_publisher_, expiration)
      .WillOnce(Return(quic::QuicTimeDelta::FromSeconds(10)));
  EXPECT_CALL(*track_publisher_, extensions)
      .WillRepeatedly(ReturnRef(extensions_));
  EXPECT_CALL(mock_bidi_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribeOk), _))
      .WillOnce(Return(absl::OkStatus()));
  publisher_->OnSubscribeAccepted();
  EXPECT_TRUE(publisher_->established());
  EXPECT_EQ(publisher_->parameters().largest_object, Location(1, 2));
  EXPECT_FALSE(publisher_->parameters().subscription_filter.has_value());
}

TEST_F(LivePublisherTest, OnSubscribeAcceptedWithFilter) {
  publisher_->parameters().subscription_filter =
      SubscriptionFilter(MoqtFilterType::kLargestObject);
  const TrackExtensions extensions(std::nullopt, std::nullopt,
                                   /*default_publisher_priority=*/64,
                                   std::nullopt, std::nullopt, std::nullopt);
  EXPECT_CALL(mock_bidi_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(*track_publisher_, largest_location())
      .WillOnce(Return(Location(1, 2)));
  EXPECT_CALL(*track_publisher_, expiration)
      .WillOnce(Return(quic::QuicTimeDelta::FromSeconds(10)));
  EXPECT_CALL(*track_publisher_, extensions)
      .WillRepeatedly(ReturnRef(extensions));
  EXPECT_CALL(mock_bidi_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribeOk), _))
      .WillOnce(Return(absl::OkStatus()));
  publisher_->OnSubscribeAccepted();
  ASSERT_TRUE(publisher_->parameters().subscription_filter.has_value());
  EXPECT_EQ(publisher_->parameters().subscription_filter->start(),
            Location(1, 3));
  // Check that default_publisher_priority is set. A datagram set at priority
  // 64 should not explicitly encode that.
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(1, std::optional<uint64_t>(), 3, 0))
      .WillOnce(
          Return(DefaultPublishedObject(Location(1, 3), std::nullopt, 64)))
      .WillOnce(
          Return(DefaultPublishedObject(Location(1, 3), std::nullopt, 64)));
  EXPECT_CALL(monitoring_interface_, OnNewObjectEnqueued(Location(1, 3)));
  EXPECT_CALL(webtrans_, SendOrQueueDatagram)
      .WillOnce([](absl::string_view datagram) {
        EXPECT_FALSE(datagram.empty());
        std::optional<MoqtDatagramType> type =
            MoqtDatagramType::FromValue(static_cast<uint64_t>(datagram[0]));
        EXPECT_TRUE(type.has_value() && type->has_default_priority());
        return DatagramStatus(DatagramStatusCode::kSuccess, "");
      });
  publisher_->OnNewObjectAvailable(Location(1, 3), std::nullopt, 64);
}

TEST_F(LivePublisherTest, OnSubscribeRejected) {
  EXPECT_CALL(mock_bidi_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_bidi_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  publisher_->OnSubscribeRejected(MoqtRequestErrorInfo(
      RequestErrorCode::kDoesNotExist, std::nullopt, "reason"));
}

TEST_F(LivePublisherTest, Update) {
  MessageParameters new_params;
  new_params.delivery_timeout = quic::QuicTimeDelta::FromSeconds(5);
  publisher_->Update(new_params);

  // Changing forward preference updates can_have_joining_fetch_
  new_params.set_forward(false);
  publisher_->Update(new_params);
  EXPECT_FALSE(publisher_->parameters().forward());
  EXPECT_FALSE(publisher_->can_have_joining_fetch());
}

TEST_F(LivePublisherTest, UpdatePriorityNoStreams) {
  MessageParameters new_params;
  new_params.subscriber_priority = 20;
  publisher_->Update(new_params);
  EXPECT_EQ(publisher_->parameters().subscriber_priority, 20);
}

TEST_F(LivePublisherTest, UpdatePriorityWithPendingStreams) {
  CreatePendingStream(Location(1, 0), 0, 64);
  MessageParameters new_params;
  new_params.subscriber_priority = 20;
  EXPECT_CALL(*track_publisher_, extensions())
      .WillRepeatedly(ReturnRef(extensions_));
  EXPECT_CALL(visitor_, UpdateTrackPriority(1,
                                            std::optional<MoqtTrackPriority>(
                                                {subscriber_priority(), 64}),
                                            MoqtTrackPriority{20, 64}));
  publisher_->Update(new_params);
}

TEST_F(LivePublisherTest, UpdatePriorityWithActiveStreams) {
  CreateStream(
      Location(1, 0), 0, 127,
      {0x51, static_cast<uint8_t>(kTrackAlias), 0x01, 0x7f, 0x00, 0x0a});
  MessageParameters new_params;
  new_params.subscriber_priority = 20;
  EXPECT_CALL(mock_uni_stream_, SetPriority);
  publisher_->Update(new_params);
}

TEST_F(LivePublisherTest, OnNewObjectAvailableNotInWindow) {
  MessageParameters params;
  params.subscription_filter = SubscriptionFilter(Location(10, 0), 10);
  publisher_->Update(params);
  EXPECT_CALL(*track_publisher_, GetCachedObject).Times(0);
  publisher_->OnNewObjectAvailable(Location(5, 0), 0, 128);
}

TEST_F(LivePublisherTest, OnNewObjectAvailableDatagram) {
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(1, std::optional<uint64_t>(), 0, 0))
      .WillOnce(
          Return(DefaultPublishedObject(Location(1, 0), std::nullopt, 128)))
      .WillOnce(
          Return(DefaultPublishedObject(Location(1, 0), std::nullopt, 128)));
  EXPECT_CALL(monitoring_interface_, OnNewObjectEnqueued(Location(1, 0)));
  EXPECT_CALL(webtrans_, SendOrQueueDatagram)
      .WillOnce(Return(DatagramStatus(DatagramStatusCode::kSuccess, "")));
  EXPECT_CALL(*track_publisher_, extensions())
      .WillRepeatedly(ReturnRef(extensions_));
  publisher_->OnNewObjectAvailable(Location(1, 0), std::nullopt, 128);
}

TEST_F(LivePublisherTest, OnNewObjectAvailableStreamCreationBlocked) {
  CreatePendingStream(Location(1, 0), 0, 128);
}

TEST_F(LivePublisherTest, OnNewFinAvailableNoops) {
  // Not in window
  MessageParameters params;
  params.subscription_filter = SubscriptionFilter(Location(10, 0), 10);
  publisher_->Update(params);
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  EXPECT_CALL(mock_uni_stream_, Writev).Times(0);
  publisher_->OnNewFinAvailable(Location(0, 0), 0);

  // In window but no stream
  publisher_->Update(parameters_);
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  EXPECT_CALL(mock_uni_stream_, Writev).Times(0);
  publisher_->OnNewFinAvailable(Location(10, 10), 0);

  EXPECT_CALL(webtrans_, GetStreamById)
      .WillRepeatedly(Return(&mock_uni_stream_));
  // Stream hasn't gotten there yet. The cache will tell us when to send FIN.
  CreateStream(Location(10, 0), 0, 128);
  EXPECT_CALL(mock_uni_stream_, Writev).Times(0);
  publisher_->OnNewFinAvailable(Location(10, 1), 0);
}

TEST_F(LivePublisherTest, OnNewFinAvailableWithStream) {
  CreateStream(Location(1, 0), 0, 128);
  EXPECT_CALL(mock_uni_stream_, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(data.empty());
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  quic::test::MockAlarmFactory alarm_factory;
  EXPECT_CALL(visitor_, alarm_factory).WillOnce(Return(&alarm_factory));
  publisher_->OnNewFinAvailable(Location(1, 0), 0);
}

TEST_F(LivePublisherTest, OnSubgroupAbandonedNoEffect) {
  // Not in window
  MessageParameters params;
  params.subscription_filter = SubscriptionFilter(Location(10, 0), 10);
  publisher_->Update(params);
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  publisher_->OnSubgroupAbandoned(1, 0, 17);

  // In window but no stream
  publisher_->Update(parameters_);
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  publisher_->OnSubgroupAbandoned(1, 0, 17);
}

TEST_F(LivePublisherTest, OnGroupAbandoned) {
  // Not in window
  MessageParameters params;
  params.subscription_filter = SubscriptionFilter(Location(10, 0), 10);
  publisher_->Update(params);
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  publisher_->OnGroupAbandoned(1);

  // In window
  publisher_->Update(parameters_);
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  publisher_->OnGroupAbandoned(1);
  EXPECT_CALL(*track_publisher_, GetCachedObject).Times(0);
  publisher_->OnNewObjectAvailable(Location(1, 0), 0, 128);
}

TEST_F(LivePublisherTest, OnGroupAbandonedWithStreams) {
  // The delivery timeout is not infinite, so it will not send a PUBLISH_DONE
  // with kTooFarBehind.
  CreateStream(Location(1, 0), 0, 128);
  EXPECT_CALL(mock_uni_stream_, ResetWithUserCode);
  EXPECT_CALL(mock_bidi_stream_, Writev).Times(0);  // No PUBLISH_DONE.
  publisher_->OnGroupAbandoned(1);
}

TEST_F(LivePublisherTest, OnGroupAbandonedTooFarBehind) {
  // Set the delivery timeout to infinite so that TooFarBehind is possible.
  parameters_.delivery_timeout = quic::QuicTimeDelta::Infinite();
  publisher_->Update(parameters_);
  CreateStream(Location(5, 0), 0, 128);
  struct MoqtPublishDone expected_publish_done = {
      /*request_id=*/kRequestId,
      PublishDoneCode::kTooFarBehind,
      /*stream_count=*/1,
      /*error_reason=*/"",
  };
  EXPECT_CALL(mock_bidi_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_bidi_stream_,
              Writev(SerializedControlMessage(expected_publish_done), _))
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  EXPECT_CALL(*track_publisher_, RemoveObjectListener);
  publisher_->OnGroupAbandoned(5);
  track_publisher_ = nullptr;
}

TEST_F(LivePublisherTest, OnCanCreateNewUniStreamPendingCleanup) {
  CreatePendingStream(Location(1, 0), 0, 128);
  // Abandon the group.
  publisher_->OnGroupAbandoned(1);
  // OnCanCreateNewUniStream should clean it up; no attempt to create a stream.
  EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream)
      .WillOnce(Return(true));
  EXPECT_CALL(webtrans_, OpenOutgoingUnidirectionalStream).Times(0);
  publisher_->OnCanCreateNewUniStream();
}

TEST_F(LivePublisherTest, AlternateDeliveryTimeoutSetAlarm) {
  ON_CALL(visitor_, alternate_delivery_timeout).WillByDefault(Return(true));
  // Create a stream for group 1.
  CreateStream(Location(1, 0), 0, 128);
  // Create a pending stream for group 2, which should start the timer but does
  // less work than an active stream.
  EXPECT_CALL(visitor_, alarm_factory).WillOnce(Return(&alarm_factory_));
  CreatePendingStream(Location(2, 0), 0, 128);
}

TEST_F(LivePublisherTest, OnTrackPublisherGone) {
  EXPECT_CALL(mock_bidi_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_bidi_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kPublishDone), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track_publisher_, RemoveObjectListener);
  publisher_->OnTrackPublisherGone();
  track_publisher_ = nullptr;
}

TEST_F(LivePublisherTest, ProcessObjectAck) {
  MoqtObjectAck ack;
  ack.group_id = 1;
  ack.object_id = 2;
  ack.delta_from_deadline = quic::QuicTimeDelta::FromMilliseconds(100);
  EXPECT_CALL(monitoring_interface_,
              OnObjectAckReceived(Location(1, 2), ack.delta_from_deadline));
  publisher_->ProcessObjectAck(ack);
}

TEST_F(LivePublisherTest, OnSubgroupAbandonedWithStream) {
  CreateStream(Location(1, 0), 0, 128);
  EXPECT_CALL(mock_uni_stream_, ResetWithUserCode(17));
  publisher_->OnSubgroupAbandoned(1, 0, 17);
}

TEST_F(LivePublisherTest, OnCanCreateNewUniStreamSuccess) {
  CreatePendingStream(Location(1, 0), 0, 128);
  // Call OnCanCreateNewUniStream and succeed.
  EXPECT_CALL(mock_uni_stream_, GetStreamId())
      .WillRepeatedly(Return(kStreamId));
  EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(webtrans_, OpenOutgoingUnidirectionalStream)
      .WillOnce(Return(&mock_uni_stream_));
  EXPECT_CALL(mock_uni_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        uni_stream_ = std::move(visitor);
      });
  EXPECT_CALL(mock_uni_stream_, SetPriority);
  EXPECT_CALL(mock_uni_stream_, visitor()).WillRepeatedly([&]() {
    return uni_stream_.get();
  });
  EXPECT_CALL(mock_uni_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(1, std::optional<uint64_t>(0), 0, 0))
      .WillOnce(Return(DefaultPublishedObject(Location(1, 0), 0, 128)));
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(1, std::optional<uint64_t>(0), 1, 0))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_uni_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  publisher_->OnCanCreateNewUniStream();
}

TEST_F(LivePublisherTest, PendingStreamsInOrder) {
  CreatePendingStream(Location(1, 0), 0, 128);
  CreatePendingStream(Location(0, 0), 0, 128);
  CreatePendingStream(Location(2, 0), 0, 127);
  // Should be opened in the order (2, 0), (0, 0), (1, 0),
  // Open stream and send (2, 0).
  EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(webtrans_, OpenOutgoingUnidirectionalStream)
      .WillOnce(Return(&mock_uni_stream_));
  EXPECT_CALL(mock_uni_stream_, GetStreamId).WillRepeatedly(Return(kStreamId));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor2;
  EXPECT_CALL(mock_uni_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor2 = std::move(visitor);
      });
  EXPECT_CALL(mock_uni_stream_, visitor()).WillRepeatedly([&]() {
    return stream_visitor2.get();
  });
  EXPECT_CALL(mock_uni_stream_, SetPriority);
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(2, std::optional<uint64_t>(0), 0, 0))
      .WillOnce(Return(DefaultPublishedObject(Location(2, 0), 0, 127)));
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(2, std::optional<uint64_t>(0), 1, 0))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_uni_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_uni_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(visitor_, UpdateTrackPriority);
  publisher_->OnCanCreateNewUniStream();
  // Open (0, 0)
  EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  EXPECT_CALL(webtrans_, OpenOutgoingUnidirectionalStream)
      .WillOnce(Return(&mock_uni_stream_));
  EXPECT_CALL(mock_uni_stream_, GetStreamId)
      .WillRepeatedly(Return(kStreamId + 4));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor0;
  EXPECT_CALL(mock_uni_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor0 = std::move(visitor);
      });
  EXPECT_CALL(mock_uni_stream_, visitor()).WillRepeatedly([&]() {
    return stream_visitor0.get();
  });
  EXPECT_CALL(mock_uni_stream_, SetPriority);
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(0, std::optional<uint64_t>(0), 0, 0))
      .WillOnce(Return(DefaultPublishedObject(Location(0, 0), 0, 128)));
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(0, std::optional<uint64_t>(0), 1, 0))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_uni_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_uni_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(visitor_, UpdateTrackPriority);
  publisher_->OnCanCreateNewUniStream();
  // Open (1, 0)
  EXPECT_CALL(webtrans_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));  // Unlimited credit but only one stream.
  EXPECT_CALL(webtrans_, OpenOutgoingUnidirectionalStream)
      .WillOnce(Return(&mock_uni_stream_));
  EXPECT_CALL(mock_uni_stream_, GetStreamId)
      .WillRepeatedly(Return(kStreamId + 8));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor1;
  EXPECT_CALL(mock_uni_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor1 = std::move(visitor);
      });
  EXPECT_CALL(mock_uni_stream_, visitor()).WillRepeatedly([&]() {
    return stream_visitor1.get();
  });
  EXPECT_CALL(mock_uni_stream_, SetPriority);
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(1, std::optional<uint64_t>(0), 0, 0))
      .WillOnce(Return(DefaultPublishedObject(Location(1, 0), 0, 128)));
  EXPECT_CALL(*track_publisher_,
              GetCachedObject(1, std::optional<uint64_t>(0), 1, 0))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_uni_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_uni_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(visitor_, UpdateTrackPriority).Times(0);
  publisher_->OnCanCreateNewUniStream();
}

TEST_F(LivePublisherTest, OnDataStreamDestroyed) {
  CreateStream(Location(1, 0), 0, 128);
  DataStreamIndex index(1, 0);
  publisher_->OnDataStreamDestroyed(index);
  // No entries in the stream map.
  EXPECT_CALL(webtrans_, GetStreamById).Times(0);
  parameters_.subscriber_priority = 20;
  publisher_->Update(parameters_);
}

TEST_F(LivePublisherTest, OnObjectSentTwice) {
  publisher_->OnObjectSent(Location(1, 0));
  EXPECT_TRUE(LivePublisherPeer::largest_sent(publisher_.get()).has_value() &&
              *LivePublisherPeer::largest_sent(publisher_.get()) ==
                  Location(1, 0));
}

TEST_F(LivePublisherTest, AlternateDeliveryTimeout) {
  EXPECT_CALL(visitor_, alternate_delivery_timeout)
      .WillRepeatedly(Return(true));
  CreateStream(Location(0, 0), 0, 128);
  // Save the visitor before it's overwritten.
  std::unique_ptr<webtransport::StreamVisitor> uni_stream =
      std::move(uni_stream_);
  CreateStream(Location(0, 1), 1, 200);
  std::unique_ptr<webtransport::StreamVisitor> uni_stream1 =
      std::move(uni_stream_);
  // Timers aren't running.
  EXPECT_EQ(OutgoingSubgroupStreamPeer::GetAlarm(
                absl::down_cast<OutgoingSubgroupStream*>(uni_stream.get())),
            nullptr);
  EXPECT_EQ(OutgoingSubgroupStreamPeer::GetAlarm(
                absl::down_cast<OutgoingSubgroupStream*>(uni_stream1.get())),
            nullptr);
  // Second group starts the timer.
  EXPECT_CALL(mock_uni_stream_, visitor)
      .WillOnce(Return(uni_stream.get()))
      .WillOnce(Return(uni_stream1.get()))
      .WillRepeatedly([&]() { return uni_stream_.get(); });
  CreateStream(Location(1, 0), 0, 128);
  // Group 0 streams now have a timer running.
  EXPECT_NE(OutgoingSubgroupStreamPeer::GetAlarm(
                absl::down_cast<OutgoingSubgroupStream*>(uni_stream.get())),
            nullptr);
  EXPECT_NE(OutgoingSubgroupStreamPeer::GetAlarm(
                absl::down_cast<OutgoingSubgroupStream*>(uni_stream1.get())),
            nullptr);
  // No timer on group 1.
  EXPECT_EQ(OutgoingSubgroupStreamPeer::GetAlarm(
                absl::down_cast<OutgoingSubgroupStream*>(uni_stream_.get())),
            nullptr);
}

TEST_F(LivePublisherTest, IncomingUpdateTruncatesSubscription) {
  // Track gets to Group 5.
  CreateStream(Location(5, 0), 0, 128);
  parameters_.subscription_filter = SubscriptionFilter(Location(0, 0), 4);
  publisher_->Update(parameters_);
  EXPECT_CALL(*track_publisher_, GetCachedObject).Times(0);
  publisher_->OnNewObjectAvailable(Location(5, 1), 0, 128);
}

TEST_F(LivePublisherTest, OnNewFinAvailable) {
  CreateStream(
      Location(1, 0), 0, 127,
      {0x51, static_cast<uint8_t>(kTrackAlias), 0x01, 0x7f, 0x00, 0x0a});
  EXPECT_CALL(mock_uni_stream_, Writev(testing::IsEmpty(), _))
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  publisher_->OnNewFinAvailable(Location(1, 0), 0);
}

TEST_F(LivePublisherTest, OnSubgroupAbandoned) {
  CreateStream(
      Location(1, 0), 0, 127,
      {0x51, static_cast<uint8_t>(kTrackAlias), 0x01, 0x7f, 0x00, 0x0a});
  EXPECT_CALL(mock_uni_stream_, ResetWithUserCode(1234));
  publisher_->OnSubgroupAbandoned(1, 0, 1234);
}

TEST_F(LivePublisherTest, OnSubgroupAbandonedOutsideWindow) {
  parameters_.subscription_filter = SubscriptionFilter(Location(20, 0));
  publisher_->Update(parameters_);
  EXPECT_CALL(mock_uni_stream_, ResetWithUserCode).Times(0);
  publisher_->OnSubgroupAbandoned(1, 0, 1234);
}

}  // namespace

}  // namespace moqt::test
