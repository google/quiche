// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_subscribe_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_live_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object_subscriber.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"

namespace moqt::test {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

class MoqtSubscribeRequestStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtSubscribeRequestStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_CLIENT),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_CLIENT),
        track_name_("foo", "bar") {
    stream_ = std::make_unique<MoqtSubscribeRequestStream>(
        &framer_, message_parser_, kRequestId, error_callback_.AsStdFunction(),
        track_name_, &mock_subscribe_visitor_, parameters_,
        mock_add_callback_.AsStdFunction(),
        mock_remove_callback_.AsStdFunction(), &mock_clock_,
        &mock_alarm_factory_);
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
    EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(track_name_))
        .Times(testing::AnyNumber());
  }

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  uint64_t kRequestId = 1;
  uint64_t kTrackAlias = 100;
  FullTrackName track_name_;
  MessageParameters parameters_;
  testing::StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      error_callback_;
  testing::MockFunction<bool(LiveSubscriber*)> mock_add_callback_;
  testing::MockFunction<void(LiveSubscriber*)> mock_remove_callback_;
  quic::MockClock mock_clock_;
  quic::test::MockAlarmFactory mock_alarm_factory_;
  StrictMock<MockLiveSubscriberVisitor> mock_subscribe_visitor_;
  webtransport::test::MockStream mock_stream_;
  std::unique_ptr<MoqtSubscribeRequestStream> stream_;
};

TEST_F(MoqtSubscribeRequestStreamTest, OnStreamBound) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);
}

TEST_F(MoqtSubscribeRequestStreamTest, ReceiveSubscribeOk) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_add_callback_, Call(stream_->track()))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(track_name_, _));
  MoqtSubscribeOk subscribe_ok;
  subscribe_ok.request_id = kRequestId;
  subscribe_ok.track_alias = kTrackAlias;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe_ok));
  EXPECT_EQ(stream_->track()->track_alias(), kTrackAlias);
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call);
}

TEST_F(MoqtSubscribeRequestStreamTest, ReceiveSubscribeOkAliasDuplicate) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_add_callback_, Call(stream_->track()))
      .WillOnce(Return(false));
  EXPECT_CALL(error_callback_, Call(MoqtError::kDuplicateTrackAlias, _));
  MoqtSubscribeOk subscribe_ok;
  subscribe_ok.request_id = kRequestId;
  subscribe_ok.track_alias = kTrackAlias;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe_ok));
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call);
}

TEST_F(MoqtSubscribeRequestStreamTest, RequestOkBeforeSubscribeOk) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation, _));
  MoqtRequestOk request_ok;
  request_ok.request_id = kRequestId;
  request_ok.parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_ok));
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call);
}

TEST_F(MoqtSubscribeRequestStreamTest, ReceiveRequestOk) {
  // SUBSCRIBE handshake.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_add_callback_, Call(stream_->track()))
      .WillOnce(Return(true));
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(track_name_, _));
  MoqtSubscribeOk subscribe_ok;
  subscribe_ok.request_id = kRequestId;
  subscribe_ok.track_alias = kTrackAlias;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe_ok));
  // REQUEST_UPDATE.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _))
      .WillOnce(Return(absl::OkStatus()));
  bool callback_called = false;
  MoqtResponseCallback callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(res));
        EXPECT_EQ(std::get<MessageParameters>(res).expires,
                  quic::QuicTimeDelta::FromSeconds(30));
      };
  parameters_.subscriber_priority = 20;
  QUICHE_EXPECT_OK(stream_->SendRequestUpdate(
      kRequestId, kRequestId, parameters_, std::move(callback)));
  // Params not yet updated.
  EXPECT_EQ(stream_->track()->const_parameters().subscriber_priority,
            std::nullopt);
  MoqtRequestOk request_ok;
  request_ok.request_id = kRequestId;
  request_ok.parameters.expires = quic::QuicTimeDelta::FromSeconds(30);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_ok));
  EXPECT_EQ(stream_->track()->const_parameters().subscriber_priority, 20);
  EXPECT_EQ(stream_->track()->const_parameters().expires,
            quic::QuicTimeDelta::FromSeconds(30));
  EXPECT_TRUE(callback_called);
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call);
}

TEST_F(MoqtSubscribeRequestStreamTest, ReceiveRequestError) {
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .WillOnce(Return(absl::OkStatus()));
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_subscribe_visitor_, OnReply(track_name_, _))
      .WillOnce(
          [](const FullTrackName&,
             const std::variant<SubscribeOkData, MoqtRequestErrorInfo>& reply) {
            ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(reply));
            EXPECT_EQ(std::get<MoqtRequestErrorInfo>(reply).error_code,
                      RequestErrorCode::kUnauthorized);
          });
  EXPECT_CALL(mock_stream_, Writev(testing::IsEmpty(), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(mock_remove_callback_, Call);
  MoqtRequestError request_error;
  request_error.request_id = kRequestId;
  request_error.error_code = RequestErrorCode::kUnauthorized;
  request_error.reason_phrase = "unauthorized";
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_error));
}

TEST_F(MoqtSubscribeRequestStreamTest, ReceivePublishDone) {
  MoqtPublishDone publish_done;
  publish_done.request_id = kRequestId;
  publish_done.stream_count = 5;
  EXPECT_CALL(mock_subscribe_visitor_, OnPublishDone(track_name_));
  QUICHE_EXPECT_OK(stream_->OnControlMessage(publish_done));
  EXPECT_CALL(mock_remove_callback_, Call);
}

class MoqtSubscribeResponseStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtSubscribeResponseStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_SERVER),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_SERVER),
        track_publisher_(std::make_shared<TestTrackPublisher>(kTrackName)) {
    stream_ = std::make_unique<MoqtSubscribeResponseStream>(
        &framer_, message_parser_, kTrackAlias,
        mock_add_callback_.AsStdFunction(),
        mock_remove_callback_.AsStdFunction(), error_callback_.AsStdFunction(),
        visitor_.weak_ptr_factory_.Create());
    stream_->BindStream(&mock_stream_);
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
  }

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  uint64_t kRequestId = 1;
  uint64_t kTrackAlias = 100;
  FullTrackName kTrackName{"foo", "bar"};
  std::shared_ptr<TestTrackPublisher> track_publisher_;
  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback_;
  testing::MockFunction<bool(LivePublisher*)> mock_add_callback_;
  testing::MockFunction<void(LivePublisher*)> mock_remove_callback_;
  MockSessionToPublisherInterface visitor_;
  webtransport::test::MockSession webtrans_;
  webtransport::test::MockStream mock_stream_;
  MoqtTraceRecorder trace_recorder_;
  std::unique_ptr<MoqtSubscribeResponseStream> stream_;
};

TEST_F(MoqtSubscribeResponseStreamTest, ReceiveSubscribeSuccess) {
  EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
  EXPECT_CALL(visitor_, GetTrackPublisher(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(mock_add_callback_, Call(testing::NotNull()))
      .WillOnce(Return(true));
  MoqtSubscribe subscribe;
  subscribe.request_id = kRequestId;
  subscribe.full_track_name = kTrackName;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe));
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call);
}

TEST_F(MoqtSubscribeResponseStreamTest, ReceiveSubscribeDoesNotExist) {
  EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
  EXPECT_CALL(visitor_, GetTrackPublisher(kTrackName))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtSubscribe subscribe;
  subscribe.request_id = kRequestId;
  subscribe.full_track_name = kTrackName;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe));
}

TEST_F(MoqtSubscribeResponseStreamTest, ReceiveSubscribeDuplicate) {
  EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
  EXPECT_CALL(visitor_, GetTrackPublisher(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(mock_add_callback_, Call(testing::NotNull()))
      .WillOnce(Return(false));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _))
      .WillOnce(Return(absl::OkStatus()));
  MoqtSubscribe subscribe;
  subscribe.request_id = kRequestId;
  subscribe.full_track_name = kTrackName;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe));
}

TEST_F(MoqtSubscribeResponseStreamTest, ReceiveRequestUpdate) {
  EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
  EXPECT_CALL(visitor_, GetTrackPublisher(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(mock_add_callback_, Call(testing::NotNull()))
      .WillOnce(Return(true));
  MoqtSubscribe subscribe;
  subscribe.request_id = kRequestId;
  subscribe.full_track_name = kTrackName;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _))
      .WillOnce(Return(absl::OkStatus()));
  MoqtRequestUpdate update;
  update.request_id = kRequestId;
  update.parameters.subscriber_priority = 10;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(update));
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call(_));
}

TEST_F(MoqtSubscribeResponseStreamTest, ReceiveInvalidControlMessages) {
  MoqtRequestOk request_ok;
  EXPECT_FALSE(stream_->OnControlMessage(request_ok).ok());
  MoqtRequestError request_error;
  EXPECT_FALSE(stream_->OnControlMessage(request_error).ok());
}

TEST_F(MoqtSubscribeResponseStreamTest, ReceiveObjectAck) {
  EXPECT_CALL(visitor_, session).WillRepeatedly(Return(&webtrans_));
  EXPECT_CALL(visitor_, GetTrackPublisher(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(mock_add_callback_, Call(testing::NotNull()))
      .WillOnce(Return(true));
  MoqtSubscribe subscribe;
  subscribe.request_id = kRequestId;
  subscribe.full_track_name = kTrackName;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(subscribe));
  MoqtObjectAck ack;
  ack.group_id = 1;
  ack.object_id = 2;
  ack.delta_from_deadline = quic::QuicTimeDelta::FromMilliseconds(100);
  EXPECT_CALL(visitor_, trace_recorder())
      .WillOnce(testing::ReturnRef(trace_recorder_));
  QUICHE_EXPECT_OK(stream_->OnControlMessage(ack));
  // Test cleanup.
  EXPECT_CALL(mock_remove_callback_, Call(_));
}

}  // namespace
}  // namespace moqt::test
