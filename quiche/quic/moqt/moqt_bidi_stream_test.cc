// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_bidi_stream.h"

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
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"

namespace moqt::test {

class TestMoqtBidiStream : public MoqtBidiStreamBase {
 public:
  using MoqtBidiStreamBase::MoqtBidiStreamBase;
  using MoqtBidiStreamBase::OnControlMessage;

  void OnStreamBound() override {}
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override {
    return ControlMessageDispatcher::DispatchControlMessage(
        *this, message_parser(), message, "test");
  }
  void Detach() override { detached_ = true; }
  bool detached_ = false;

  absl::Status OnControlMessage(const MoqtObjectAck&) {
    // No-op used in the DispatchControlMessage test.
    return absl::OkStatus();
  }

  absl::Status OnControlMessage(const MoqtRequestOk& message) {
    return request_update_queue().OnControlMessage(message);
  }
  absl::Status OnControlMessage(const MoqtRequestError& message) {
    absl::Status status = request_update_queue().OnControlMessage(message);
    if (status.ok()) {
      Fin();
    }
    return status;
  }

  using MoqtBidiStreamBase::IncomingUpdatesQueued;
  using MoqtBidiStreamBase::QueueIncomingUpdate;
};

class MoqtBidiStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtBidiStreamTest()
      : framer_(true, quic::Perspective::IS_CLIENT),
        stream_(std::make_unique<TestMoqtBidiStream>(
            &framer_,
            MoqtControlMessageParser(kDefaultMoqtVersion,
                                     /*webtransport=*/true,
                                     quic::Perspective::IS_CLIENT),
            error_callback_.AsStdFunction())) {}

  MoqtFramer framer_;
  testing::StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      error_callback_;
  std::unique_ptr<TestMoqtBidiStream> stream_;
  webtransport::test::MockStream mock_stream_;
};

TEST_F(MoqtBidiStreamTest, Reset) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, SendStopSending(1234));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(1234));
  stream_->Reset(1234);
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, IncomingReset) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, SendStopSending).Times(0);
  EXPECT_CALL(mock_stream_, ResetWithUserCode(1234));
  stream_->OnResetStreamReceived(1234);
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, FinDetaches) {
  stream_->BindStream(&mock_stream_);
  stream_->Fin();
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, IncomingStopSending) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, SendStopSending(1234));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(1234));
  stream_->OnStopSendingReceived(1234);
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, SendRequestError) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestError), testing::_));
  QUICHE_EXPECT_OK(stream_->SendRequestError(
      RequestErrorCode::kUnauthorized, /*retry_interval=*/std::nullopt, ""));
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, DispatchControlMessage) {
  webtransport::test::InMemoryStream stream(0);
  stream_->BindStream(&stream);
  MoqtFramer framer(/*using_webtrans=*/true, quic::Perspective::IS_SERVER);
  stream.Receive(framer.SerializeObjectAck(MoqtObjectAck()).AsStringView());
  stream_->OnCanRead();

  stream.Receive(framer.SerializePublishDone(MoqtPublishDone()).AsStringView());
  EXPECT_CALL(error_callback_, Call)
      .WillOnce([](MoqtError error, absl::string_view message) {
        EXPECT_EQ(error, MoqtError::kProtocolViolation);
        EXPECT_EQ(message,
                  "Received an unexpected message of type PUBLISH_DONE on a "
                  "test stream");
      });
  stream_->OnCanRead();
}

TEST_F(MoqtBidiStreamTest, ReceiveGoAway) {
  QUICHE_EXPECT_OK(stream_->OnControlMessage(
      MoqtGoAway("", quic::QuicTimeDelta::Zero(), std::nullopt)));
  EXPECT_TRUE(IsInvalidArgument(stream_->OnControlMessage(
      MoqtGoAway("", quic::QuicTimeDelta::Zero(), std::nullopt))));
}

TEST_F(MoqtBidiStreamTest, ReceiveGoAwayWithRequestId) {
  EXPECT_TRUE(IsInvalidArgument(stream_->OnControlMessage(
      MoqtGoAway("", quic::QuicTimeDelta::Zero(), /*request_id=*/0))));
}

TEST_F(MoqtBidiStreamTest, SendRequestOk) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
  MoqtRequestOk expected_ok;
  expected_ok.parameters.subscriber_priority = 20;
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_ok), testing::_));
  MessageParameters parameters;
  parameters.subscriber_priority = 20;
  // Disallowed for PUBLISH_OK, should be sanitized out.
  parameters.largest_object = Location(1, 2);
  QUICHE_EXPECT_OK(
      stream_->SendRequestOk(parameters, MoqtMessageType::kPublish));
  EXPECT_FALSE(stream_->detached_);  // No FIN.
}

TEST_F(MoqtBidiStreamTest, SendRequestErrorOverload) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestError), testing::_));
  QUICHE_EXPECT_OK(stream_->SendRequestError(RequestErrorCode::kUnauthorized,
                                             std::nullopt, "reason"));
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, SendRequestUpdateAndReceiveOk) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
  MoqtRequestUpdate expected_update;
  expected_update.request_id = 1;
  expected_update.existing_request_id = 0;
  expected_update.parameters.subscriber_priority = 20;
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_update), testing::_));
  MessageParameters parameters;
  parameters.subscriber_priority = 20;
  // Disallowed in REQUEST_UPDATE for SUBSCRIBE, should be sanitized out.
  parameters.expires = quic::QuicTimeDelta::FromSeconds(10);
  bool callback_called = false;
  MoqtResponseCallback callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(res));
        EXPECT_EQ(std::get<MessageParameters>(res).subscriber_priority, 30);
      };
  QUICHE_EXPECT_OK(stream_->SendRequestUpdate(
      1, 0, parameters, std::move(callback), MoqtMessageType::kSubscribe));
  // Simulate receiving RequestOk
  MoqtRequestOk request_ok;
  request_ok.parameters.subscriber_priority = 30;
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_ok));
  EXPECT_TRUE(callback_called);
  EXPECT_FALSE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, SendRequestUpdateAndReceiveError) {
  stream_->BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(testing::Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate),
                     testing::_));
  MessageParameters parameters;
  bool callback_called = false;
  MoqtResponseCallback callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(res));
        EXPECT_EQ(std::get<MoqtRequestErrorInfo>(res).error_code,
                  RequestErrorCode::kUnauthorized);
      };
  QUICHE_EXPECT_OK(stream_->SendRequestUpdate(
      1, 0, parameters, std::move(callback), MoqtMessageType::kSubscribe));
  // Simulate receiving RequestError
  MoqtRequestError request_error(RequestErrorCode::kUnauthorized, std::nullopt,
                                 "unauthorized");
  ExpectFin(mock_stream_);
  QUICHE_EXPECT_OK(stream_->OnControlMessage(request_error));
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, QueueIsFull) {
  stream_->BindStream(&mock_stream_);
  EXPECT_FALSE(stream_->QueueIsFull());
}

TEST_F(MoqtBidiStreamTest, IncomingUpdateQueue) {
  EXPECT_FALSE(stream_->IncomingUpdatesQueued());
  EXPECT_EQ(stream_->NextIncomingUpdate(), std::nullopt);

  MessageParameters update1;
  update1.subscriber_priority = 10;
  MessageParameters update2;
  update2.subscriber_priority = 20;

  stream_->QueueIncomingUpdate(update1);
  EXPECT_TRUE(stream_->IncomingUpdatesQueued());
  stream_->QueueIncomingUpdate(update2);
  EXPECT_TRUE(stream_->IncomingUpdatesQueued());

  EXPECT_EQ(stream_->NextIncomingUpdate(), update1);
  EXPECT_TRUE(stream_->IncomingUpdatesQueued());
  EXPECT_EQ(stream_->NextIncomingUpdate(), update2);
  EXPECT_FALSE(stream_->IncomingUpdatesQueued());
  EXPECT_EQ(stream_->NextIncomingUpdate(), std::nullopt);
}

}  // namespace moqt::test
