// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_publish_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_subscription.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {

class SubscriptionPublisherPeer {
 public:
  static const MessageParameters& parameters(
      const SubscriptionPublisher& publisher) {
    return publisher.parameters_;
  }
};

class SubscribeRemoteTrackPeer {
 public:
  static const MessageParameters& parameters(
      const SubscribeRemoteTrack& track) {
    return track.const_parameters();
  }
};

namespace {

using ::testing::_;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::StrictMock;

class MockSessionToPublisherInterface : public SessionToPublisherInterface {
 public:
  ~MockSessionToPublisherInterface() override = default;
  MOCK_METHOD(bool, alternate_delivery_timeout, (), (const, override));
  MOCK_METHOD(void, UpdateTrackPriority,
              (uint64_t, std::optional<MoqtTrackPriority>, MoqtTrackPriority),
              (override));
  MOCK_METHOD(quic::QuicAlarmFactory*, alarm_factory, (), (override));
  MOCK_METHOD(void, PublishIsDone, (uint64_t), (override));
  MOCK_METHOD(webtransport::Session*, session, (), (override));
};

constexpr uint64_t kRequestId = 1;
constexpr uint64_t kTrackAlias = 10;
const FullTrackName kTrackName("foo", "bar");

class MoqtPublishPublisherStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtPublishPublisherStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_CLIENT),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_CLIENT),
        track_publisher_(std::make_shared<TestTrackPublisher>(kTrackName)) {
    // Construct the stream visitor.
    stream_ = std::make_unique<MoqtPublishPublisherStream>(
        &framer_, message_parser_, deleted_callback_.AsStdFunction(),
        error_callback_.AsStdFunction(),
        [this](std::variant<MessageParameters, MoqtRequestErrorInfo> response) {
          response_ = response;
        });

    // Construct the SubscriptionPublisher.
    parameters_.set_forward(true);
    parameters_.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);
    parameters_.group_order = MoqtDeliveryOrder::kAscending;

    EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
    auto publisher = std::make_unique<SubscriptionPublisher>(
        framer_, track_publisher_, stream_.get(), kRequestId, kTrackAlias,
        parameters_, &visitor_, /*monitoring_interface=*/nullptr, &mock_clock_,
        trace_recorder_, /*is_publish=*/true);

    publisher_ = publisher.get();  // Keep raw pointer for testing
    stream_->SetPublisher(std::move(publisher));
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  }

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  webtransport::test::MockStream mock_stream_;
  std::shared_ptr<TestTrackPublisher> track_publisher_;
  testing::MockFunction<void(SubscriptionPublisher*)> deleted_callback_;
  testing::StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      error_callback_;
  MockSessionToPublisherInterface visitor_;
  webtransport::test::MockSession webtrans_;
  quic::MockClock mock_clock_;
  MoqtTraceRecorder trace_recorder_;
  MessageParameters parameters_;

  std::unique_ptr<MoqtPublishPublisherStream> stream_;
  SubscriptionPublisher* publisher_;  // Raw pointer
  std::optional<std::variant<MessageParameters, MoqtRequestErrorInfo>>
      response_;
};

TEST_F(MoqtPublishPublisherStreamTest, OnStreamBoundSendsPublish) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kPublish), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);  // Calls OnStreamBound
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestOk) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kPublish), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);  // Calls OnStreamBound

  MoqtRequestOk request_ok;
  request_ok.request_id = kRequestId;
  request_ok.parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(2);
  request_ok.parameters.group_order = MoqtDeliveryOrder::kDescending;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_ok));

  // Verify response callback was called.
  ASSERT_TRUE(response_.has_value());
  ASSERT_TRUE(std::holds_alternative<MessageParameters>(*response_));
  MessageParameters resp_params = std::get<MessageParameters>(*response_);
  EXPECT_EQ(resp_params.delivery_timeout,
            request_ok.parameters.delivery_timeout);
  EXPECT_EQ(resp_params.group_order, request_ok.parameters.group_order);

  // Verify publisher parameters were updated.
  const MessageParameters& pub_params =
      SubscriptionPublisherPeer::parameters(*publisher_);
  EXPECT_EQ(pub_params.delivery_timeout,
            request_ok.parameters.delivery_timeout);
  // Group order cannot be updated.
  EXPECT_EQ(pub_params.group_order, parameters_.group_order);
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestError) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kPublish), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);  // Calls OnStreamBound

  MoqtRequestError request_error;
  request_error.request_id = kRequestId;
  request_error.error_code = RequestErrorCode::kUnauthorized;
  request_error.retry_interval = quic::QuicTimeDelta::FromSeconds(5);
  request_error.reason_phrase = "Unauthorized";
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_error));

  // Verify response callback was called with error.
  ASSERT_TRUE(response_.has_value());
  ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(*response_));
  MoqtRequestErrorInfo resp_error = std::get<MoqtRequestErrorInfo>(*response_);
  EXPECT_EQ(resp_error.error_code, request_error.error_code);
  EXPECT_EQ(resp_error.retry_interval, request_error.retry_interval);
  EXPECT_EQ(resp_error.reason_phrase, request_error.reason_phrase);
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestUpdate) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kPublish), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);

  QUICHE_EXPECT_OK(stream_->OnControlMessage(MoqtRequestOk{kRequestId}));
  // Set largest location on publisher
  track_publisher_->AddObject(Location(1, 2), 0, "payload", true);

  MoqtRequestUpdate request_update;
  request_update.request_id = kRequestId + 2;
  request_update.existing_request_id = kRequestId;
  request_update.parameters.delivery_timeout =
      quic::QuicTimeDelta::FromSeconds(3);
  request_update.parameters.subscriber_priority = 5;
  request_update.parameters.subscription_filter.emplace(
      MoqtFilterType::kLargestObject);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _))
      .WillOnce(Return(absl::OkStatus()));
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_update));

  // Verify publisher parameters were updated.
  const MessageParameters& pub_params =
      SubscriptionPublisherPeer::parameters(*publisher_);
  EXPECT_EQ(pub_params.delivery_timeout,
            request_update.parameters.delivery_timeout);
  EXPECT_EQ(pub_params.subscriber_priority,
            request_update.parameters.subscriber_priority);

  // Verify filter was updated based on largest location (1, 2) -> (1, 3)
  // AbsoluteStart
  ASSERT_TRUE(pub_params.subscription_filter.has_value());
  EXPECT_EQ(pub_params.subscription_filter->type(),
            MoqtFilterType::kAbsoluteStart);
  EXPECT_EQ(pub_params.subscription_filter->start(), Location(1, 3));
}

class MoqtPublishSubscriberStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtPublishSubscriberStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_SERVER),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_SERVER),
        incoming_publish_callback_(
            incoming_publish_callback_mock_.AsStdFunction()) {
    stream_ = std::make_unique<MoqtPublishSubscriberStream>(
        &framer_, message_parser_, &mock_clock_, &mock_alarm_factory_,
        error_callback_.AsStdFunction(), &incoming_publish_callback_,
        mock_add_callback_.AsStdFunction(),
        mock_remove_callback_.AsStdFunction());
    stream_->BindStream(&mock_stream_);
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  }

  MoqtPublish DefaultPublish() {
    return MoqtPublish{kRequestId, kTrackName, kTrackAlias, MessageParameters(),
                       TrackExtensions()};
  }

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  quic::MockClock mock_clock_;
  quic::test::MockAlarmFactory mock_alarm_factory_;
  testing::StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      error_callback_;

  testing::MockFunction<SubscribeVisitor*(
      const FullTrackName&, const MessageParameters&, const TrackExtensions&,
      MoqtResponseCallback)>
      incoming_publish_callback_mock_;
  MoqtIncomingPublishCallback incoming_publish_callback_;

  testing::MockFunction<bool(SubscribeRemoteTrack*)> mock_add_callback_;
  testing::MockFunction<void(SubscribeRemoteTrack*)> mock_remove_callback_;

  StrictMock<MockSubscribeRemoteTrackVisitor> mock_subscribe_visitor_;
  MoqtResponseCallback captured_response_callback_;
  webtransport::test::MockStream mock_stream_;
  std::unique_ptr<MoqtPublishSubscriberStream> stream_;
};

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishAndAccept) {
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce([this](const FullTrackName&, const MessageParameters&,
                       const TrackExtensions&, MoqtResponseCallback callback) {
        captured_response_callback_ = std::move(callback);
        return &mock_subscribe_visitor_;
      });
  SubscribeRemoteTrack* captured_subscriber = nullptr;
  EXPECT_CALL(mock_add_callback_, Call(NotNull()))
      .WillOnce([&](SubscribeRemoteTrack* subscriber) {
        captured_subscriber = subscriber;
        return true;
      });
  MoqtPublish publish = DefaultPublish();
  publish.parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Verify subscriber is created.
  ASSERT_NE(captured_subscriber, nullptr);
  EXPECT_EQ(captured_subscriber->track_alias(), kTrackAlias);
  EXPECT_EQ(captured_subscriber->visitor(), &mock_subscribe_visitor_);

  // Verify REQUEST_OK response was sent.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _))
      .WillOnce(Return(absl::OkStatus()));
  MessageParameters response_parameters;
  response_parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(2);
  std::move(captured_response_callback_)(response_parameters);

  // Verify subscriber parameters were updated.
  const MessageParameters& sub_params =
      SubscribeRemoteTrackPeer::parameters(*captured_subscriber);
  EXPECT_EQ(sub_params.delivery_timeout, response_parameters.delivery_timeout);
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone);
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishAndReject) {
  MoqtPublish publish = DefaultPublish();
  // Callback returns nullptr (rejection).
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_remove_callback_, Call);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceiveTwoPublishOnStream) {
  MoqtPublish publish = DefaultPublish();
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Receive second PUBLISH on same stream.
  publish.request_id = kRequestId + 2;
  publish.full_track_name = FullTrackName("dead", "beef");
  publish.track_alias = kTrackAlias + 1;
  EXPECT_FALSE(stream_->OnControlMessage(publish).ok());
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDuplicate) {
  MoqtPublish publish = DefaultPublish();
  publish.request_id = kRequestId + 2;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  EXPECT_CALL(mock_add_callback_, Call).WillOnce(Return(false));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_remove_callback_, Call);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceiveRequestUpdate) {
  MoqtPublish publish = DefaultPublish();
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  SubscribeRemoteTrack* captured_subscriber = nullptr;
  EXPECT_CALL(mock_add_callback_, Call(NotNull()))
      .WillOnce([&](SubscribeRemoteTrack* track) {
        captured_subscriber = track;
        return true;
      });
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Now receive REQUEST_UPDATE.
  MoqtRequestUpdate request_update;
  request_update.request_id = kRequestId + 2;
  request_update.existing_request_id = kRequestId;
  request_update.parameters.delivery_timeout =
      quic::QuicTimeDelta::FromSeconds(3);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _))
      .WillOnce(Return(absl::OkStatus()));
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_update));

  // Verify subscriber parameters were updated.
  ASSERT_NE(captured_subscriber, nullptr);
  const MessageParameters& sub_params =
      SubscribeRemoteTrackPeer::parameters(*captured_subscriber);
  EXPECT_EQ(sub_params.delivery_timeout,
            request_update.parameters.delivery_timeout);
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDone) {
  MoqtPublish publish = DefaultPublish();
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Now receive PUBLISH_DONE.
  MoqtPublishDone publish_done;
  publish_done.request_id = kRequestId;
  publish_done.status_code = PublishDoneCode::kTrackEnded;
  publish_done.stream_count = 0;  // Trigger immediate Destroy
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(data.empty());
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_remove_callback_, Call);
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish_done));
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishAndRejectCallback) {
  MoqtPublish publish = DefaultPublish();
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce([this](const FullTrackName&, const MessageParameters&,
                       const TrackExtensions&, MoqtResponseCallback callback) {
        captured_response_callback_ = std::move(callback);
        return &mock_subscribe_visitor_;
      });
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Now call the response callback with error (reject).
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  MoqtRequestErrorInfo error_info{RequestErrorCode::kUninterested, std::nullopt,
                                  "rejected by app"};
  EXPECT_CALL(mock_remove_callback_, Call);
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  std::move(captured_response_callback_)(error_info);
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDoneOnRejectedStream) {
  MoqtPublish publish = DefaultPublish();
  // Callback returns nullptr (rejection).
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_remove_callback_, Call);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Now receive PUBLISH_DONE.
  MoqtPublishDone publish_done;
  publish_done.request_id = kRequestId;
  publish_done.status_code = PublishDoneCode::kTrackEnded;
  publish_done.stream_count = 0;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish_done));
}

TEST_F(MoqtPublishSubscriberStreamTest, DuplicatePublishOnSameStream) {
  MoqtPublish publish = DefaultPublish();
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish));

  // Receive second PUBLISH on same stream. Should cause a session error.
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Multiple PUBLISH on the same stream"));
  MoqtPublish publish2 = DefaultPublish();
  publish2.request_id = kRequestId + 2;
  publish2.full_track_name = FullTrackName("dead", "beef");
  publish2.track_alias = kTrackAlias + 1;
  stream_->CheckStatus(stream_->OnControlMessage(publish2));
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
}

TEST_F(MoqtPublishSubscriberStreamTest, DuplicatePublishOnDifferentStreams) {
  MoqtPublish publish1 = DefaultPublish();
  EXPECT_CALL(mock_add_callback_, Call(NotNull())).WillOnce(Return(true));
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish1));

  // Second stream
  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback2;
  testing::MockFunction<bool(SubscribeRemoteTrack*)> mock_add_callback2;
  testing::MockFunction<void(SubscribeRemoteTrack*)> mock_remove_callback2;
  testing::MockFunction<SubscribeVisitor*(
      const FullTrackName&, const MessageParameters&, const TrackExtensions&,
      MoqtResponseCallback)>
      incoming_publish_callback_mock2;
  MoqtIncomingPublishCallback incoming_publish_callback2 =
      incoming_publish_callback_mock2.AsStdFunction();

  webtransport::test::MockStream mock_stream2;
  MoqtPublishSubscriberStream stream2(
      &framer_, message_parser_, &mock_clock_, &mock_alarm_factory_,
      error_callback2.AsStdFunction(), &incoming_publish_callback2,
      mock_add_callback2.AsStdFunction(),
      mock_remove_callback2.AsStdFunction());
  stream2.BindStream(&mock_stream2);
  EXPECT_CALL(mock_stream2, CanWrite).WillRepeatedly(Return(true));

  // Duplicate PUBLISH (same track name) on stream2 is rejected.
  MoqtPublish publish2 = DefaultPublish();
  publish2.request_id = kRequestId + 2;
  publish2.full_track_name = kTrackName;
  EXPECT_CALL(mock_add_callback2, Call(NotNull())).WillOnce(Return(false));
  EXPECT_CALL(mock_stream2,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_remove_callback2, Call);

  QUICHE_EXPECT_OK(stream2.OnControlMessage(publish2));

  // Finally, a PUBLISH on the second stream triggers a session error.
  EXPECT_CALL(error_callback2, Call(MoqtError::kProtocolViolation,
                                    "Multiple PUBLISH on the same stream"));
  MoqtPublish publish3 = DefaultPublish();
  publish3.request_id = kRequestId + 4;
  publish3.full_track_name = kTrackName;
  stream2.CheckStatus(stream2.OnControlMessage(publish3));

  // Test teardown expectations
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
}

}  // namespace
}  // namespace moqt::test
