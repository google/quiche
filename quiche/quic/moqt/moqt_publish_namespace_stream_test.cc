// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_publish_namespace_stream.h"

#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"

namespace moqt::test {

using ::testing::_;
using ::testing::IsNull;
using ::testing::Return;
using ::testing::StrictMock;

class MoqtPublishNamespaceRequestStreamTest : public quiche::test::QuicheTest {
 protected:
  MoqtPublishNamespaceRequestStreamTest()
      : framer_(true, quic::Perspective::IS_CLIENT),
        remove_callback_(),
        session_error_callback_(),
        response_callback_() {
    EXPECT_CALL(remove_callback_, Call(_)).Times(testing::AnyNumber());
  }

  std::unique_ptr<MoqtPublishNamespaceRequestStream> CreateAndBindStream() {
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
    EXPECT_CALL(
        mock_stream_,
        Writev(ControlMessageOfType(MoqtMessageType::kPublishNamespace), _));
    auto stream = std::make_unique<MoqtPublishNamespaceRequestStream>(
        TrackNamespace({"foo"}), MessageParameters(), &framer_,
        MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                                 quic::Perspective::IS_CLIENT),
        /*request_id=*/10, remove_callback_.AsStdFunction(),
        session_error_callback_.AsStdFunction(),
        response_callback_.AsStdFunction());
    stream->BindStream(&mock_stream_);
    return stream;
  }

  MoqtFramer framer_;
  StrictMock<testing::MockFunction<void(const TrackNamespace&)>>
      remove_callback_;
  StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      session_error_callback_;
  StrictMock<testing::MockFunction<void(
      std::variant<MessageParameters, MoqtRequestErrorInfo>)>>
      response_callback_;
  webtransport::test::MockStream mock_stream_;
};

TEST_F(MoqtPublishNamespaceRequestStreamTest, OnStreamBound) {
  // Creating and binding the stream verifies OnStreamBound sends
  // PUBLISH_NAMESPACE.
  std::unique_ptr<MoqtPublishNamespaceRequestStream> request_stream =
      CreateAndBindStream();
}

TEST_F(MoqtPublishNamespaceRequestStreamTest, DetachCallsRemoveCallback) {
  std::unique_ptr<MoqtPublishNamespaceRequestStream> request_stream =
      CreateAndBindStream();
  EXPECT_CALL(remove_callback_, Call(TrackNamespace({"foo"})));
  request_stream = nullptr;
}

TEST_F(MoqtPublishNamespaceRequestStreamTest, OnControlMessageOk) {
  std::unique_ptr<MoqtPublishNamespaceRequestStream> request_stream =
      CreateAndBindStream();
  bool callback_called = false;
  EXPECT_CALL(response_callback_, Call(_))
      .WillOnce([&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback_called = true;
        EXPECT_TRUE(std::holds_alternative<MessageParameters>(res));
      });

  MoqtRequestOk message;
  message.request_id = 10;
  QUICHE_EXPECT_OK(request_stream->OnControlMessage(message));
  EXPECT_TRUE(callback_called);
}

TEST_F(MoqtPublishNamespaceRequestStreamTest, OnControlMessageError) {
  std::unique_ptr<MoqtPublishNamespaceRequestStream> request_stream =
      CreateAndBindStream();
  bool callback_called = false;
  EXPECT_CALL(response_callback_, Call(_))
      .WillOnce([&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(res));
        EXPECT_EQ(std::get<MoqtRequestErrorInfo>(res).error_code,
                  RequestErrorCode::kUnauthorized);
      });
  ExpectFin(mock_stream_);

  MoqtRequestError message;
  message.request_id = 10;
  message.error_code = RequestErrorCode::kUnauthorized;
  QUICHE_EXPECT_OK(request_stream->OnControlMessage(message));
  EXPECT_TRUE(callback_called);
}

TEST_F(MoqtPublishNamespaceRequestStreamTest, SendRequestUpdateAndReceiveOk) {
  std::unique_ptr<MoqtPublishNamespaceRequestStream> request_stream =
      CreateAndBindStream();
  // Resolve initial response first.
  EXPECT_CALL(response_callback_, Call(_));
  MoqtRequestOk initial_ok;
  initial_ok.request_id = 10;
  QUICHE_EXPECT_OK(request_stream->OnControlMessage(initial_ok));

  // Now send update.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _));

  MessageParameters parameters;
  parameters.subscriber_priority = 50;
  bool update_callback_called = false;
  MoqtResponseCallback update_callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        update_callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(res));
        EXPECT_EQ(std::get<MessageParameters>(res).subscriber_priority, 50);
      };

  QUICHE_EXPECT_OK(request_stream->SendRequestUpdate(
      11, 0, parameters, std::move(update_callback)));

  // Receive OK for update.
  MoqtRequestOk ok;
  ok.request_id = 11;
  ok.parameters.subscriber_priority = 50;
  QUICHE_EXPECT_OK(request_stream->OnControlMessage(ok));
  EXPECT_TRUE(update_callback_called);
}

class MoqtPublishNamespaceResponseStreamTest : public quiche::test::QuicheTest {
 protected:
  MoqtPublishNamespaceResponseStreamTest()
      : framer_(true, quic::Perspective::IS_SERVER),
        session_error_callback_(),
        add_callback_(),
        remove_callback_(),
        application_() {
    EXPECT_CALL(remove_callback_, Call(_)).Times(testing::AnyNumber());
    EXPECT_CALL(application_, Call(_, nullptr, _)).Times(testing::AnyNumber());
  }

  MoqtFramer framer_;
  StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      session_error_callback_;
  StrictMock<
      testing::MockFunction<bool(const TrackNamespace&, MoqtBidiStreamBase*)>>
      add_callback_;
  StrictMock<testing::MockFunction<void(const TrackNamespace&)>>
      remove_callback_;
  StrictMock<testing::MockFunction<void(
      const TrackNamespace&, const MessageParameters*, MoqtResponseCallback)>>
      application_;
  webtransport::test::MockStream mock_stream_;
};

TEST_F(MoqtPublishNamespaceResponseStreamTest,
       OnPublishNamespaceAddCallbackFails) {
  auto response_stream = std::make_unique<MoqtPublishNamespaceResponseStream>(
      &framer_,
      MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                               quic::Perspective::IS_SERVER),
      add_callback_.AsStdFunction(), remove_callback_.AsStdFunction(),
      session_error_callback_.AsStdFunction(), application_.AsStdFunction());
  response_stream->BindStream(&mock_stream_);

  MoqtPublishNamespace message;
  message.request_id = 5;
  message.track_namespace = TrackNamespace({"foo"});

  EXPECT_CALL(add_callback_,
              Call(TrackNamespace({"foo"}), response_stream.get()))
      .WillOnce(Return(false));
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(message));
}

TEST_F(MoqtPublishNamespaceResponseStreamTest,
       OnPublishNamespaceSuccessAndApplicationAccepts) {
  auto response_stream = std::make_unique<MoqtPublishNamespaceResponseStream>(
      &framer_,
      MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                               quic::Perspective::IS_SERVER),
      add_callback_.AsStdFunction(), remove_callback_.AsStdFunction(),
      session_error_callback_.AsStdFunction(), application_.AsStdFunction());
  response_stream->BindStream(&mock_stream_);

  MoqtPublishNamespace message;
  message.request_id = 5;
  message.track_namespace = TrackNamespace({"foo"});

  MoqtResponseCallback application_callback;
  EXPECT_CALL(add_callback_,
              Call(TrackNamespace({"foo"}), response_stream.get()))
      .WillOnce(Return(true));
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _))
      .WillOnce([&](const TrackNamespace&, const MessageParameters*,
                    MoqtResponseCallback callback) {
        application_callback = std::move(callback);
      });

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(message));
  ASSERT_TRUE(application_callback != nullptr);

  // Application accepts the publish namespace.
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  std::move(application_callback)(MessageParameters());
}

TEST_F(MoqtPublishNamespaceResponseStreamTest,
       DetachCleansUpPrefixAndNotifiesApplication) {
  auto response_stream = std::make_unique<MoqtPublishNamespaceResponseStream>(
      &framer_,
      MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                               quic::Perspective::IS_SERVER),
      add_callback_.AsStdFunction(), remove_callback_.AsStdFunction(),
      session_error_callback_.AsStdFunction(), application_.AsStdFunction());
  response_stream->BindStream(&mock_stream_);

  MoqtPublishNamespace message;
  message.request_id = 5;
  message.track_namespace = TrackNamespace({"foo"});

  MoqtResponseCallback application_callback;
  EXPECT_CALL(add_callback_,
              Call(TrackNamespace({"foo"}), response_stream.get()))
      .WillOnce(Return(true));
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _))
      .WillOnce([&](const TrackNamespace&, const MessageParameters*,
                    MoqtResponseCallback callback) {
        application_callback = std::move(callback);
      });

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(message));

  // Accept it first.
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  std::move(application_callback)(MessageParameters());

  // Since it was published (published_ = true), Detach() should call
  // remove_callback_ and application_(*prefix_, nullptr, nullptr).
  EXPECT_CALL(remove_callback_, Call(TrackNamespace({"foo"})));
  EXPECT_CALL(application_, Call(TrackNamespace({"foo"}), IsNull(), IsNull()));

  response_stream = nullptr;  // Destroys response_stream, triggering Detach().
}

TEST_F(MoqtPublishNamespaceResponseStreamTest,
       DoublePublishNamespaceReturnsError) {
  auto response_stream = std::make_unique<MoqtPublishNamespaceResponseStream>(
      &framer_,
      MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                               quic::Perspective::IS_SERVER),
      add_callback_.AsStdFunction(), remove_callback_.AsStdFunction(),
      session_error_callback_.AsStdFunction(), application_.AsStdFunction());
  response_stream->BindStream(&mock_stream_);

  MoqtPublishNamespace message;
  message.request_id = 5;
  message.track_namespace = TrackNamespace({"foo"});

  EXPECT_CALL(add_callback_,
              Call(TrackNamespace({"foo"}), response_stream.get()))
      .WillOnce(Return(true));
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _));

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(message));

  // Second call must return absl::InvalidArgumentError
  EXPECT_EQ(response_stream->OnControlMessage(message).code(),
            absl::StatusCode::kInvalidArgument);
}

TEST_F(MoqtPublishNamespaceResponseStreamTest, OnRequestUpdateSuccess) {
  auto response_stream = std::make_unique<MoqtPublishNamespaceResponseStream>(
      &framer_,
      MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                               quic::Perspective::IS_SERVER),
      add_callback_.AsStdFunction(), remove_callback_.AsStdFunction(),
      session_error_callback_.AsStdFunction(), application_.AsStdFunction());
  response_stream->BindStream(&mock_stream_);

  MoqtPublishNamespace message;
  message.request_id = 5;
  message.track_namespace = TrackNamespace({"foo"});

  MoqtResponseCallback application_callback;
  EXPECT_CALL(add_callback_,
              Call(TrackNamespace({"foo"}), response_stream.get()))
      .WillOnce(Return(true));
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _))
      .WillOnce([&](const TrackNamespace&, const MessageParameters*,
                    MoqtResponseCallback callback) {
        application_callback = std::move(callback);
      });

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(message));

  // Accept it.
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  std::move(application_callback)(MessageParameters());

  // Now send a RequestUpdate.
  MoqtRequestUpdate update;
  update.request_id = 12;
  update.parameters.subscriber_priority = 40;

  MoqtResponseCallback update_callback;
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _))
      .WillOnce([&](const TrackNamespace&, const MessageParameters*,
                    MoqtResponseCallback callback) {
        update_callback = std::move(callback);
      });

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(update));
  ASSERT_TRUE(update_callback != nullptr);

  // Application accepts the update.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  std::move(update_callback)(MessageParameters());
}

TEST_F(MoqtPublishNamespaceResponseStreamTest, OnRequestUpdateRejected) {
  auto response_stream = std::make_unique<MoqtPublishNamespaceResponseStream>(
      &framer_,
      MoqtControlMessageParser(kDefaultMoqtVersion, /*webtransport=*/true,
                               quic::Perspective::IS_SERVER),
      add_callback_.AsStdFunction(), remove_callback_.AsStdFunction(),
      session_error_callback_.AsStdFunction(), application_.AsStdFunction());
  response_stream->BindStream(&mock_stream_);

  MoqtPublishNamespace message;
  message.request_id = 5;
  message.track_namespace = TrackNamespace({"foo"});

  MoqtResponseCallback application_callback;
  EXPECT_CALL(add_callback_,
              Call(TrackNamespace({"foo"}), response_stream.get()))
      .WillOnce(Return(true));
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _))
      .WillOnce([&](const TrackNamespace&, const MessageParameters*,
                    MoqtResponseCallback callback) {
        application_callback = std::move(callback);
      });

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(message));

  // Accept it.
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  std::move(application_callback)(MessageParameters());

  // Now send a RequestUpdate.
  MoqtRequestUpdate update;
  update.request_id = 12;
  update.parameters.subscriber_priority = 40;

  MoqtResponseCallback update_callback;
  EXPECT_CALL(application_,
              Call(TrackNamespace({"foo"}), testing::NotNull(), _))
      .WillOnce([&](const TrackNamespace&, const MessageParameters*,
                    MoqtResponseCallback callback) {
        update_callback = std::move(callback);
      });

  QUICHE_EXPECT_OK(response_stream->OnControlMessage(update));

  // Application rejects the update.
  MoqtRequestErrorInfo error_info = {
      RequestErrorCode::kUnauthorized,
      /*retry_interval=*/std::nullopt,
      "unauthorized",
  };
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  std::move(update_callback)(error_info);
}

}  // namespace moqt::test
