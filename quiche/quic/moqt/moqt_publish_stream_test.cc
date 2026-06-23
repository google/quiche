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
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
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
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"
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

class BidiStreamWithReset
    : public webtransport::test::InMemoryStreamWithWriteBuffer {
 public:
  using InMemoryStreamWithWriteBuffer::InMemoryStreamWithWriteBuffer;
  void ResetWithUserCode(webtransport::StreamErrorCode error) override {
    last_reset_code_ = error;
  }
  std::optional<webtransport::StreamErrorCode> last_reset_code() const {
    return last_reset_code_;
  }

 private:
  std::optional<webtransport::StreamErrorCode> last_reset_code_;
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
    stream_visitor_ = std::make_unique<MoqtPublishPublisherStream>(
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
        framer_, track_publisher_, stream_visitor_.get(), kRequestId,
        kTrackAlias, parameters_, &visitor_, /*monitoring_interface=*/nullptr,
        &mock_clock_, trace_recorder_, /*is_publish=*/true);

    publisher_ = publisher.get();  // Keep raw pointer for testing
    stream_visitor_->SetPublisher(std::move(publisher));
  }

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  std::shared_ptr<TestTrackPublisher> track_publisher_;
  testing::MockFunction<void()> deleted_callback_;
  testing::StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      error_callback_;
  MockSessionToPublisherInterface visitor_;
  webtransport::test::MockSession webtrans_;
  quic::MockClock mock_clock_;
  MoqtTraceRecorder trace_recorder_;
  MessageParameters parameters_;

  std::unique_ptr<MoqtPublishPublisherStream> stream_visitor_;
  SubscriptionPublisher* publisher_;  // Raw pointer
  std::optional<std::variant<MessageParameters, MoqtRequestErrorInfo>>
      response_;
};

TEST_F(MoqtPublishPublisherStreamTest, OnStreamBoundSendsPublish) {
  webtransport::test::InMemoryStreamWithWriteBuffer stream(0);
  stream_visitor_->BindStream(&stream);  // Calls OnStreamBound

  // Verify PUBLISH message was sent.
  std::string& written = stream.write_buffer();
  MoqtControlStreamParser parser(&stream);
  // Feed the written data back to a parser to verify it.
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kPublish);

  MoqtControlMessageParser cmp(kDefaultMoqtVersion, true,
                               quic::Perspective::IS_CLIENT);
  absl::StatusOr<MoqtPublish> publish = cmp.ProcessPublish(message->payload);
  ASSERT_TRUE(publish.ok());
  EXPECT_EQ(publish->request_id, kRequestId);
  EXPECT_EQ(publish->full_track_name, kTrackName);
  EXPECT_EQ(publish->track_alias, kTrackAlias);
  EXPECT_EQ(publish->parameters.delivery_timeout, parameters_.delivery_timeout);
  EXPECT_EQ(publish->parameters.group_order, parameters_.group_order);
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestOk) {
  webtransport::test::InMemoryStreamWithWriteBuffer stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtRequestOk request_ok;
  request_ok.request_id = kRequestId;
  request_ok.parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(2);
  request_ok.parameters.group_order = MoqtDeliveryOrder::kDescending;

  stream.Receive(framer_.SerializeRequestOk(request_ok).AsStringView());
  stream_visitor_->OnCanRead();

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
  webtransport::test::InMemoryStreamWithWriteBuffer stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtRequestError request_error;
  request_error.request_id = kRequestId;
  request_error.error_code = RequestErrorCode::kUnauthorized;
  request_error.retry_interval = quic::QuicTimeDelta::FromSeconds(5);
  request_error.reason_phrase = "Unauthorized";

  stream.Receive(framer_.SerializeRequestError(request_error).AsStringView());
  stream_visitor_->OnCanRead();

  // Verify response callback was called with error.
  ASSERT_TRUE(response_.has_value());
  ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(*response_));
  MoqtRequestErrorInfo resp_error = std::get<MoqtRequestErrorInfo>(*response_);
  EXPECT_EQ(resp_error.error_code, request_error.error_code);
  EXPECT_EQ(resp_error.retry_interval, request_error.retry_interval);
  EXPECT_EQ(resp_error.reason_phrase, request_error.reason_phrase);
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestUpdate) {
  webtransport::test::InMemoryStreamWithWriteBuffer stream(0);
  stream_visitor_->BindStream(&stream);
  stream.write_buffer().clear();  // Clear initial PUBLISH

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

  stream.Receive(framer_.SerializeRequestUpdate(request_update).AsStringView());
  stream_visitor_->OnCanRead();

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

  // Verify REQUEST_OK response was sent.
  std::string& written = stream.write_buffer();
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kRequestOk);

  MoqtControlMessageParser cmp(kDefaultMoqtVersion, true,
                               quic::Perspective::IS_CLIENT);
  absl::StatusOr<MoqtRequestOk> request_ok =
      cmp.ProcessRequestOk(message->payload);
  ASSERT_TRUE(request_ok.ok());
  EXPECT_EQ(request_ok->request_id, request_update.request_id);
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestOkMismatchedId) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  // Receive REQUEST_OK with mismatched ID.
  MoqtRequestOk request_ok;
  request_ok.request_id = kRequestId + 1;  // Mismatched
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "REQUEST_OK does not match PUBLISH request ID"));
  stream.Receive(framer_.SerializeRequestOk(request_ok).AsStringView());
  stream_visitor_->OnCanRead();
}

TEST_F(MoqtPublishPublisherStreamTest, ReceiveRequestErrorMismatchedId) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  // Receive REQUEST_ERROR with mismatched ID.
  MoqtRequestError request_error;
  request_error.request_id = kRequestId + 1;  // Mismatched
  request_error.error_code = RequestErrorCode::kUninterested;
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "REQUEST_OK does not match PUBLISH request ID"));
  stream.Receive(framer_.SerializeRequestError(request_error).AsStringView());
  stream_visitor_->OnCanRead();
}

class MoqtPublishSubscriberStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtPublishSubscriberStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_SERVER),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_SERVER),
        incoming_publish_callback_(
            incoming_publish_callback_mock_.AsStdFunction()) {
    SubscribeRemoteTrack::SubscribeCallbacks callbacks;
    callbacks.query_name = [this](const FullTrackName& name) {
      return query_name_mock_.Call(name);
    };
    callbacks.register_name = [this](const FullTrackName& name,
                                     SubscribeRemoteTrack* track) {
      register_name_mock_.Call(name, track);
    };
    callbacks.register_alias = [this](uint64_t alias,
                                      SubscribeRemoteTrack* track) {
      return register_alias_mock_.Call(alias, track);
    };
    callbacks.unregister = [this](const FullTrackName& name,
                                  std::optional<uint64_t> alias) {
      unregister_mock_.Call(name, alias);
    };

    stream_visitor_ = std::make_unique<MoqtPublishSubscriberStream>(
        &framer_, message_parser_, &mock_clock_, &mock_alarm_factory_,
        error_callback_.AsStdFunction(), &incoming_publish_callback_,
        std::move(callbacks));
  }

  void ExpectSubscriberDestruction() {
    EXPECT_CALL(unregister_mock_,
                Call(kTrackName, std::optional<uint64_t>(kTrackAlias)))
        .Times(1);
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

  testing::MockFunction<SubscribeRemoteTrack*(const FullTrackName&)>
      query_name_mock_;
  testing::MockFunction<void(const FullTrackName&, SubscribeRemoteTrack*)>
      register_name_mock_;
  testing::MockFunction<bool(uint64_t, SubscribeRemoteTrack*)>
      register_alias_mock_;
  testing::MockFunction<void(const FullTrackName&, std::optional<uint64_t>)>
      unregister_mock_;

  StrictMock<MockSubscribeRemoteTrackVisitor> mock_subscribe_visitor_;
  MoqtResponseCallback captured_response_callback_;
  std::unique_ptr<MoqtPublishSubscriberStream> stream_visitor_;
};

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishAndAccept) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  ExpectSubscriberDestruction();

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;
  publish.parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);

  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce([this](const FullTrackName&, const MessageParameters&,
                       const TrackExtensions&, MoqtResponseCallback callback) {
        captured_response_callback_ = std::move(callback);
        return &mock_subscribe_visitor_;
      });

  EXPECT_CALL(query_name_mock_, Call(kTrackName)).WillOnce(Return(nullptr));
  EXPECT_CALL(register_name_mock_, Call(kTrackName, NotNull())).Times(1);
  SubscribeRemoteTrack* captured_subscriber = nullptr;
  EXPECT_CALL(register_alias_mock_, Call(kTrackAlias, NotNull()))
      .WillOnce([&](uint64_t, SubscribeRemoteTrack* track) {
        captured_subscriber = track;
        return true;
      });

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Verify subscriber is created.
  ASSERT_NE(captured_subscriber, nullptr);
  EXPECT_EQ(captured_subscriber->track_alias(), kTrackAlias);
  EXPECT_EQ(captured_subscriber->visitor(), &mock_subscribe_visitor_);

  // Now call the response callback with success.
  stream.write_buffer().clear();
  MessageParameters response_parameters;
  response_parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(2);
  std::move(captured_response_callback_)(response_parameters);

  // Verify REQUEST_OK response was sent.
  std::string& written = stream.write_buffer();
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kRequestOk);

  MoqtControlMessageParser cmp(kDefaultMoqtVersion, true,
                               quic::Perspective::IS_SERVER);
  absl::StatusOr<MoqtRequestOk> request_ok =
      cmp.ProcessRequestOk(message->payload);
  ASSERT_TRUE(request_ok.ok());
  EXPECT_EQ(request_ok->request_id, kRequestId);
  EXPECT_EQ(request_ok->parameters.delivery_timeout,
            response_parameters.delivery_timeout);

  // Verify subscriber parameters were updated.
  const MessageParameters& sub_params =
      SubscribeRemoteTrackPeer::parameters(*captured_subscriber);
  EXPECT_EQ(sub_params.delivery_timeout, response_parameters.delivery_timeout);
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishAndReject) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  // Callback returns nullptr (rejection).
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(nullptr));

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Verify REQUEST_ERROR was sent.
  std::string& written = stream.write_buffer();
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kRequestError);

  MoqtControlMessageParser cmp(kDefaultMoqtVersion, true,
                               quic::Perspective::IS_SERVER);
  absl::StatusOr<MoqtRequestError> request_error =
      cmp.ProcessRequestError(message->payload);
  ASSERT_TRUE(request_error.ok());
  EXPECT_EQ(request_error->request_id, kRequestId);
  EXPECT_EQ(request_error->error_code, RequestErrorCode::kUninterested);
  EXPECT_TRUE(stream.fin_sent());
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDuplicate) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  EXPECT_CALL(query_name_mock_, Call(kTrackName)).WillOnce(Return(nullptr));
  EXPECT_CALL(register_name_mock_, Call(kTrackName, NotNull())).Times(1);
  EXPECT_CALL(register_alias_mock_, Call(kTrackAlias, NotNull()))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  ExpectSubscriberDestruction();

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Send second PUBLISH on same stream.
  stream.Receive(framer_.SerializePublish(publish).AsStringView());

  // It should return InvalidArgumentError, which calls OnFatalError in
  // MoqtBidiStreamBase.
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Multiple PUBLISH on the same stream"));
  stream_visitor_->OnCanRead();
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDuplicateName) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  // Simulate an existing established track.
  MoqtSubscribe sub;
  sub.full_track_name = kTrackName;
  StrictMock<MockSubscribeRemoteTrackVisitor> existing_visitor;
  SubscribeRemoteTrack existing_track(sub, &existing_visitor, []() {}, {});
  existing_track.OnObjectOrOk();

  EXPECT_CALL(existing_visitor, OnPublishDone(kTrackName)).Times(1);

  EXPECT_CALL(query_name_mock_, Call(kTrackName))
      .WillOnce(Return(&existing_track));

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Verify REQUEST_ERROR was sent.
  std::string& written = stream.write_buffer();
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kRequestError);

  MoqtControlMessageParser cmp(kDefaultMoqtVersion, true,
                               quic::Perspective::IS_SERVER);
  absl::StatusOr<MoqtRequestError> request_error =
      cmp.ProcessRequestError(message->payload);
  ASSERT_TRUE(request_error.ok());
  EXPECT_EQ(request_error->request_id, kRequestId);
  EXPECT_EQ(request_error->error_code,
            RequestErrorCode::kDuplicateSubscription);
  EXPECT_TRUE(stream.fin_sent());
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDuplicateAlias) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));

  EXPECT_CALL(query_name_mock_, Call(kTrackName)).WillOnce(Return(nullptr));
  EXPECT_CALL(register_name_mock_, Call(kTrackName, NotNull())).Times(1);
  // Return duplicate alias error (false) from alias callback.
  EXPECT_CALL(register_alias_mock_, Call(kTrackAlias, NotNull()))
      .WillOnce(Return(false));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  ExpectSubscriberDestruction();

  // It should call OnFatalError, which calls error_callback_.
  // Note: The error message is now empty because we pass
  // AlreadyExistsError("").
  EXPECT_CALL(error_callback_, Call(MoqtError::kDuplicateTrackAlias, ""));

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceiveRequestUpdate) {
  // First, establish subscription.
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));

  EXPECT_CALL(query_name_mock_, Call(kTrackName)).WillOnce(Return(nullptr));
  EXPECT_CALL(register_name_mock_, Call(kTrackName, NotNull())).Times(1);
  SubscribeRemoteTrack* captured_subscriber = nullptr;
  EXPECT_CALL(register_alias_mock_, Call(kTrackAlias, NotNull()))
      .WillOnce([&](uint64_t, SubscribeRemoteTrack* track) {
        captured_subscriber = track;
        return true;
      });
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  ExpectSubscriberDestruction();

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();
  stream.write_buffer().clear();

  // Now receive REQUEST_UPDATE.
  MoqtRequestUpdate request_update;
  request_update.request_id = kRequestId + 2;
  request_update.existing_request_id = kRequestId;
  request_update.parameters.delivery_timeout =
      quic::QuicTimeDelta::FromSeconds(3);

  stream.Receive(framer_.SerializeRequestUpdate(request_update).AsStringView());
  stream_visitor_->OnCanRead();

  // Verify subscriber parameters were updated.
  ASSERT_NE(captured_subscriber, nullptr);
  const MessageParameters& sub_params =
      SubscribeRemoteTrackPeer::parameters(*captured_subscriber);
  EXPECT_EQ(sub_params.delivery_timeout,
            request_update.parameters.delivery_timeout);

  // Verify REQUEST_OK response was sent.
  std::string& written = stream.write_buffer();
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kRequestOk);
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDone) {
  // First, establish subscription.
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(&mock_subscribe_visitor_));
  EXPECT_CALL(query_name_mock_, Call(kTrackName)).WillOnce(Return(nullptr));
  EXPECT_CALL(register_name_mock_, Call(kTrackName, NotNull())).Times(1);
  EXPECT_CALL(register_alias_mock_, Call(kTrackAlias, NotNull()))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  ExpectSubscriberDestruction();

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Now receive PUBLISH_DONE.
  MoqtPublishDone publish_done;
  publish_done.request_id = kRequestId;
  publish_done.status_code = PublishDoneCode::kTrackEnded;
  publish_done.stream_count = 0;  // Trigger immediate Destroy

  stream.Receive(framer_.SerializePublishDone(publish_done).AsStringView());
  stream_visitor_->OnCanRead();

  EXPECT_EQ(stream.last_reset_code(), kResetCodeCancelled);
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishAndRejectCallback) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce([this](const FullTrackName&, const MessageParameters&,
                       const TrackExtensions&, MoqtResponseCallback callback) {
        captured_response_callback_ = std::move(callback);
        return &mock_subscribe_visitor_;
      });

  EXPECT_CALL(query_name_mock_, Call(kTrackName)).WillOnce(Return(nullptr));
  EXPECT_CALL(register_name_mock_, Call(kTrackName, NotNull())).Times(1);
  EXPECT_CALL(register_alias_mock_, Call(kTrackAlias, NotNull()))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(kTrackName, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(reply));
          });
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName));
  ExpectSubscriberDestruction();

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Now call the response callback with error (reject).
  stream.write_buffer().clear();
  MoqtRequestErrorInfo error_info{RequestErrorCode::kUninterested, std::nullopt,
                                  "rejected by app"};
  std::move(captured_response_callback_)(error_info);

  // Verify REQUEST_ERROR response was sent.
  std::string& written = stream.write_buffer();
  webtransport::test::InMemoryStream read_stream(0);
  read_stream.Receive(written);
  MoqtControlStreamParser read_parser(&read_stream);
  absl::StatusOr<MoqtRawControlMessage> message = read_parser.ReadNextMessage();
  ASSERT_TRUE(message.ok());
  EXPECT_EQ(message->type, MoqtMessageType::kRequestError);

  MoqtControlMessageParser cmp(kDefaultMoqtVersion, true,
                               quic::Perspective::IS_SERVER);
  absl::StatusOr<MoqtRequestError> request_error =
      cmp.ProcessRequestError(message->payload);
  ASSERT_TRUE(request_error.ok());
  EXPECT_EQ(request_error->request_id, kRequestId);
  EXPECT_EQ(request_error->error_code, RequestErrorCode::kUninterested);
  EXPECT_EQ(request_error->reason_phrase, "rejected by app");
}

TEST_F(MoqtPublishSubscriberStreamTest, ReceivePublishDoneOnRejectedStream) {
  BidiStreamWithReset stream(0);
  stream_visitor_->BindStream(&stream);

  MoqtPublish publish;
  publish.request_id = kRequestId;
  publish.full_track_name = kTrackName;
  publish.track_alias = kTrackAlias;

  // Callback returns nullptr (rejection).
  EXPECT_CALL(incoming_publish_callback_mock_, Call(kTrackName, _, _, _))
      .WillOnce(Return(nullptr));

  stream.Receive(framer_.SerializePublish(publish).AsStringView());
  stream_visitor_->OnCanRead();

  // Now receive PUBLISH_DONE.
  MoqtPublishDone publish_done;
  publish_done.request_id = kRequestId;
  publish_done.status_code = PublishDoneCode::kTrackEnded;
  publish_done.stream_count = 0;

  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(kTrackName)).Times(0);
  stream.Receive(framer_.SerializePublishDone(publish_done).AsStringView());
  stream_visitor_->OnCanRead();
}

}  // namespace
}  // namespace moqt::test
