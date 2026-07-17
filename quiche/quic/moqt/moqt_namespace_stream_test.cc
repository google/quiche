// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_namespace_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Return;

constexpr uint64_t kRequestId = 3;
const TrackNamespace kPrefix({"foo"});

MoqtControlMessageParser ControlMessageParser() {
  return MoqtControlMessageParser(kDefaultMoqtVersion, true,
                                  quic::Perspective::IS_CLIENT);
}

class MoqtSubscribeNamespaceRequestStreamTest
    : public quiche::test::QuicheTest {
 public:
  MoqtSubscribeNamespaceRequestStreamTest()
      : framer_(true, quic::Perspective::IS_CLIENT),
        stream_(&framer_, ControlMessageParser(), kRequestId,
                deleted_callback_.AsStdFunction(),
                error_callback_.AsStdFunction(),
                response_callback_.AsStdFunction()),
        task_(stream_.CreateTask(kPrefix)) {
    task_->SetObjectsAvailableCallback([this]() { ++objects_available_; });
    stream_.BindStream(&mock_stream_);
    ON_CALL(mock_stream_, CanWrite()).WillByDefault(Return(true));
  }

  void CheckNumberOfObjectsAvailable(int expected_count) {
    EXPECT_EQ(objects_available_, expected_count);
  }

  template <typename M>
  void ReceiveControlMessage(const M& message) {
    stream_.CheckStatus(stream_.OnControlMessage(message));
  }

  MoqtFramer framer_;
  testing::MockFunction<void(const TrackNamespace&)> deleted_callback_;
  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback_;
  testing::MockFunction<void(
      std::variant<MessageParameters, MoqtRequestErrorInfo>)>
      response_callback_;
  webtransport::test::MockStream mock_stream_;
  MoqtSubscribeNamespaceRequestStream stream_;
  int objects_available_ = 0;
  std::unique_ptr<MoqtNamespaceTask> task_;
};

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, RequestOk) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, RequestOkWrongId) {
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Unexpected request ID in response"));
  ReceiveControlMessage(MoqtRequestOk{kRequestId + 1});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, RequestError) {
  EXPECT_CALL(response_callback_, Call);
  ReceiveControlMessage(
      MoqtRequestError{kRequestId, RequestErrorCode::kInternalError,
                       quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, RequestErrorWrongId) {
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Unexpected request ID in response"));
  ReceiveControlMessage(
      MoqtRequestError{kRequestId + 1, RequestErrorCode::kInternalError,
                       quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, NamespaceBeforeResponse) {
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "First message must be REQUEST_OK or REQUEST_ERROR"));
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, NamespaceDoneBeforeResponse) {
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "First message must be REQUEST_OK or REQUEST_ERROR"));
  ReceiveControlMessage(MoqtNamespaceDone{TrackNamespace({"bar"})});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, NamespaceAfterResponse) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(1);
  TrackNamespace received_namespace;
  TransactionType type;
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kPending);
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, NamespaceDoneAfterResponse) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(1);
  ReceiveControlMessage(MoqtNamespaceDone{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(2);
  TrackNamespace received_namespace;
  TransactionType type;
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kDelete);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kPending);
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, DuplicateNamespace) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(1);
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "Two NAMESPACE messages for the same track namespace"));
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, NamespaceDoneWithoutNamespace) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "NAMESPACE_DONE with no active namespace"));
  ReceiveControlMessage(MoqtNamespaceDone{TrackNamespace({"bar"})});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, NamespaceDoneThenNamespace) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  EXPECT_CALL(error_callback_, Call).Times(0);
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(1);
  ReceiveControlMessage(MoqtNamespaceDone{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(2);
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"buzz"})});
  CheckNumberOfObjectsAvailable(3);
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, TaskGetNextSuffix) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(1);
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"buzz"})});
  CheckNumberOfObjectsAvailable(2);
  ReceiveControlMessage(MoqtNamespaceDone{TrackNamespace({"bar"})});
  CheckNumberOfObjectsAvailable(3);
  TrackNamespace received_namespace;
  TransactionType type;
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"buzz"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kDelete);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kPending);
  ReceiveControlMessage(MoqtNamespace{TrackNamespace({"another"})});
  CheckNumberOfObjectsAvailable(4);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"another"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kPending);
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, DeclareEof) {
  auto stream = std::make_unique<MoqtSubscribeNamespaceRequestStream>(
      &framer_, ControlMessageParser(), kRequestId,
      deleted_callback_.AsStdFunction(), error_callback_.AsStdFunction(),
      response_callback_.AsStdFunction());
  std::unique_ptr<MoqtNamespaceTask> task = stream->CreateTask(kPrefix);
  ASSERT_TRUE(task != nullptr);
  task->SetObjectsAvailableCallback([this]() { ++objects_available_; });
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  QUICHE_EXPECT_OK(stream->OnControlMessage(MoqtRequestOk{kRequestId}));
  QUICHE_EXPECT_OK(
      stream->OnControlMessage(MoqtNamespace{TrackNamespace({"bar"})}));
  CheckNumberOfObjectsAvailable(1);
  stream.reset();
  CheckNumberOfObjectsAvailable(2);
  TrackNamespace received_namespace;
  TransactionType type;
  EXPECT_EQ(task->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task->GetNextSuffix(received_namespace, type), kEof);
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, UpdateAndRequestOk) {
  EXPECT_CALL(
      response_callback_,
      Call(testing::VariantWith<MessageParameters>(Eq(MessageParameters()))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId});
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _));
  MessageParameters update_params;
  update_params.subscriber_priority = 10;
  testing::MockFunction<void(
      std::variant<MessageParameters, MoqtRequestErrorInfo>)>
      update_response_callback;
  task_->Update(update_params, update_response_callback.AsStdFunction());
  MessageParameters ok_params;
  ok_params.expires = quic::QuicTimeDelta::FromSeconds(60);
  EXPECT_CALL(update_response_callback,
              Call(testing::VariantWith<MessageParameters>(Eq(ok_params))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId + 2, ok_params});
}

TEST_F(MoqtSubscribeNamespaceRequestStreamTest, UpdateAndRequestError) {
  MessageParameters ok_params;
  ok_params.expires = quic::QuicTimeDelta::FromSeconds(60);
  EXPECT_CALL(response_callback_,
              Call(testing::VariantWith<MessageParameters>(Eq(ok_params))));
  ReceiveControlMessage(MoqtRequestOk{kRequestId, ok_params});
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _));
  MessageParameters update_params;
  update_params.subscriber_priority = 10;
  testing::MockFunction<void(
      std::variant<MessageParameters, MoqtRequestErrorInfo>)>
      update_response_callback;
  task_->Update(update_params, update_response_callback.AsStdFunction());
  EXPECT_CALL(update_response_callback, Call(_));
  ReceiveControlMessage(
      MoqtRequestError{kRequestId + 2, RequestErrorCode::kInternalError,
                       quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
}

class MoqtSubscribeNamespaceResponseStreamTest
    : public quiche::test::QuicheTest {
 public:
  MoqtSubscribeNamespaceResponseStreamTest()
      : framer_(false, quic::Perspective::IS_CLIENT),
        application_callback_(mock_application_.AsStdFunction()),
        stream_(&framer_, ControlMessageParser(), add_callback_.AsStdFunction(),
                remove_callback_.AsStdFunction(),
                error_callback_.AsStdFunction(), application_callback_) {
    stream_.BindStream(&mock_stream_);
    EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly(Return(true));
  }

  template <typename M>
  void ReceiveControlMessage(const M& message) {
    stream_.CheckStatus(stream_.OnControlMessage(message));
  }

  MoqtFramer framer_;
  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback_;
  webtransport::test::MockStream mock_stream_;
  testing::MockFunction<bool(const TrackNamespace&)> add_callback_;
  testing::MockFunction<void(const TrackNamespace&)> remove_callback_;
  testing::MockFunction<std::unique_ptr<MoqtNamespaceTask>(
      const TrackNamespace&, const MessageParameters&, MoqtResponseCallback)>
      mock_application_;
  MoqtIncomingSubscribeNamespaceCallback application_callback_;
  MoqtSubscribeNamespaceResponseStream stream_;
};

TEST_F(MoqtSubscribeNamespaceResponseStreamTest, Subscribe) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  ObjectsAvailableCallback callback;
  MockNamespaceTask* task_ptr = nullptr;
  MoqtRequestOk ok(kRequestId);
  ok.parameters.expires = quic::QuicTimeDelta::FromSeconds(60);
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(ok.parameters);
        auto task =
            std::make_unique<MockNamespaceTask>(message.track_namespace_prefix);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(ok), _));
  ReceiveControlMessage(message);
  ASSERT_TRUE(task_ptr != nullptr);
  EXPECT_EQ(task_ptr->prefix(), message.track_namespace_prefix);

  // Deliver NAMESPACE.
  EXPECT_CALL(*task_ptr, GetNextSuffix)
      .WillOnce([](TrackNamespace& ns, TransactionType& type) {
        ns = TrackNamespace({"bar"});
        type = TransactionType::kAdd;
        return kSuccess;
      })
      .WillOnce([](TrackNamespace& ns, TransactionType& type) {
        ns = TrackNamespace({"beef"});
        type = TransactionType::kAdd;
        return kSuccess;
      })
      .WillOnce(Return(kPending));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kNamespace), _))
      .Times(2);
  task_ptr->InvokeCallback();

  // Deliver NAMESPACE_DONE and FIN.
  EXPECT_CALL(*task_ptr, GetNextSuffix)
      .WillOnce([](TrackNamespace& ns, TransactionType& type) {
        ns = TrackNamespace({"bar"});
        type = TransactionType::kDelete;
        return kSuccess;
      })
      .WillOnce([](TrackNamespace& ns, TransactionType& type) { return kEof; });
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> slices,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(slices.size(), 1);
        EXPECT_EQ(slices[0].data()[0],
                  static_cast<uint8_t>(MoqtMessageType::kNamespaceDone));
        EXPECT_FALSE(options.send_fin());
        return absl::OkStatus();
      })
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> slices,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(slices.size(), 0);
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  task_ptr->InvokeCallback();
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest, SubscribeUnsubscribe) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  ObjectsAvailableCallback callback;
  MockNamespaceTask* task_ptr = nullptr;
  MoqtRequestOk ok(kRequestId);
  ok.parameters.expires = quic::QuicTimeDelta::FromSeconds(60);
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(ok.parameters);
        auto task =
            std::make_unique<MockNamespaceTask>(message.track_namespace_prefix);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(ok), _));
  ReceiveControlMessage(message);
  ASSERT_TRUE(task_ptr != nullptr);
  EXPECT_EQ(task_ptr->prefix(), message.track_namespace_prefix);
  // Unsubscribe.
  EXPECT_CALL(remove_callback_, Call);
  stream_.OnResetStreamReceived(kResetCodeCancelled);
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest, RequestError) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MoqtRequestErrorInfo{
            RequestErrorCode::kInternalError,
            quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
        return nullptr;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  ReceiveControlMessage(message);
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest, RequestUpdateOk) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  MockNamespaceTask* task_ptr = nullptr;
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MessageParameters());
        auto task =
            std::make_unique<MockNamespaceTask>(message.track_namespace_prefix);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  ReceiveControlMessage(message);
  ASSERT_TRUE(task_ptr != nullptr);

  // Now send RequestUpdate
  MoqtRequestUpdate update_message = {
      kRequestId + 2,
      kRequestId,
      MessageParameters(),
  };
  update_message.parameters.subscriber_priority = 10;
  MoqtRequestOk ok_response(update_message.request_id);
  ok_response.parameters.expires = quic::QuicTimeDelta::FromSeconds(60);
  EXPECT_CALL(*task_ptr, Update(_, _))
      .WillOnce([&](const MessageParameters& params, MoqtResponseCallback cb) {
        EXPECT_EQ(params.subscriber_priority, 10);
        std::move(cb)(ok_response.parameters);
      });
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(ok_response), _));
  ReceiveControlMessage(update_message);
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest, RequestUpdateError) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  MockNamespaceTask* task_ptr = nullptr;
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MessageParameters());
        auto task =
            std::make_unique<MockNamespaceTask>(message.track_namespace_prefix);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  ReceiveControlMessage(message);
  ASSERT_TRUE(task_ptr != nullptr);

  // Now send RequestUpdate
  MoqtRequestUpdate update_message = {
      kRequestId + 2,
      kRequestId,
      MessageParameters(),
  };
  update_message.parameters.subscriber_priority = 10;
  EXPECT_CALL(*task_ptr, Update(_, _))
      .WillOnce([&](const MessageParameters& params, MoqtResponseCallback cb) {
        EXPECT_EQ(params.subscriber_priority, 10);
        std::move(cb)(MoqtRequestErrorInfo{
            RequestErrorCode::kInternalError,
            quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  ReceiveControlMessage(update_message);
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest, SubscribePrefixOverlap) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo", "bar", "baz"}),
      MessageParameters(),
  };
  // The namespace tree already has a subscriber for a prefix of "foo".
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(false));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  ReceiveControlMessage(message);
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest,
       DuplicateSubscribeNamespaceOnSameStream) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  MoqtRequestOk ok(kRequestId);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(ok), _));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MessageParameters());
        return std::make_unique<MockNamespaceTask>(
            message.track_namespace_prefix);
      });
  ReceiveControlMessage(message);

  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Two SUBSCRIBE_NAMESPACE on one stream"));
  MoqtSubscribeNamespace message2 = {
      kRequestId + 2,
      TrackNamespace({"bar"}),
      MessageParameters(),
  };
  ReceiveControlMessage(message2);
}

TEST_F(MoqtSubscribeNamespaceResponseStreamTest,
       DuplicateSubscribeNamespaceOnDifferentStreams) {
  MoqtSubscribeNamespace message1 = {
      kRequestId,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(true));
  MoqtRequestOk ok1(kRequestId);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(ok1), _));
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MessageParameters());
        return std::make_unique<MockNamespaceTask>(
            message1.track_namespace_prefix);
      });
  ReceiveControlMessage(message1);

  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback2;
  webtransport::test::MockStream mock_stream2;
  MoqtSubscribeNamespaceResponseStream stream2(
      &framer_, ControlMessageParser(), add_callback_.AsStdFunction(),
      remove_callback_.AsStdFunction(), error_callback2.AsStdFunction(),
      application_callback_);
  stream2.BindStream(&mock_stream2);
  EXPECT_CALL(mock_stream2, CanWrite()).WillRepeatedly(Return(true));

  MoqtSubscribeNamespace message2 = {
      kRequestId + 2,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  EXPECT_CALL(add_callback_, Call).WillOnce(Return(false));
  EXPECT_CALL(mock_stream2,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream2.CheckStatus(stream2.OnControlMessage(message2));

  EXPECT_CALL(error_callback2, Call(MoqtError::kProtocolViolation,
                                    "Two SUBSCRIBE_NAMESPACE on one stream"));
  MoqtSubscribeNamespace message3 = {
      kRequestId + 4,
      TrackNamespace({"foo"}),
      MessageParameters(),
  };
  stream2.CheckStatus(stream2.OnControlMessage(message3));
}

}  // namespace
}  // namespace moqt::test
