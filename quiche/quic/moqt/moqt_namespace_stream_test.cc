// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_namespace_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/session_namespace_tree.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::Return;

constexpr uint64_t kRequestId = 3;
const TrackNamespace kPrefix({"foo"});

class MockNamespaceTask : public MoqtNamespaceTask {
 public:
  MockNamespaceTask(TrackNamespace& prefix) : prefix_(prefix) {}
  MOCK_METHOD(GetNextResult, GetNextSuffix,
              (TrackNamespace & whole_namespace, TransactionType& type),
              (override));
  MOCK_METHOD(void, SetObjectAvailableCallback,
              (ObjectsAvailableCallback callback), (override));
  MOCK_METHOD(std::optional<webtransport::StreamErrorCode>, GetStatus, (),
              (override));
  const TrackNamespace& prefix() override { return prefix_; }

 private:
  TrackNamespace prefix_;
};

class MoqtNamespaceSubscriberStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtNamespaceSubscriberStreamTest()
      : framer_(true),
        stream_(&framer_, kRequestId, deleted_callback_.AsStdFunction(),
                error_callback_.AsStdFunction(),
                response_callback_.AsStdFunction()),
        task_(stream_.CreateTask(kPrefix)) {
    stream_.set_stream(&mock_stream_);
  }

  MoqtFramer framer_;
  testing::MockFunction<void()> deleted_callback_;
  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback_;
  testing::MockFunction<void(std::optional<MoqtRequestErrorInfo>)>
      response_callback_;
  webtransport::test::MockStream mock_stream_;
  MoqtNamespaceSubscriberStream stream_;
  std::unique_ptr<MoqtNamespaceTask> task_ = stream_.CreateTask(kPrefix);
};

TEST_F(MoqtNamespaceSubscriberStreamTest, RequestOk) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, RequestOkWrongId) {
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Unexpected request ID in response"));
  stream_.OnRequestOkMessage({kRequestId + 1});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, RequestError) {
  EXPECT_CALL(response_callback_, Call);
  stream_.OnRequestErrorMessage({kRequestId, RequestErrorCode::kInternalError,
                                 quic::QuicTimeDelta::FromMilliseconds(100),
                                 "bar"});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, RequestErrorWrongId) {
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "Unexpected request ID in error"));
  stream_.OnRequestErrorMessage(
      {kRequestId + 1, RequestErrorCode::kInternalError,
       quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, NamespaceBeforeResponse) {
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "First message must be REQUEST_OK or REQUEST_ERROR"));
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, NamespaceDoneBeforeResponse) {
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "First message must be REQUEST_OK or REQUEST_ERROR"));
  stream_.OnNamespaceDoneMessage({TrackNamespace({"bar"})});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, NamespaceAfterResponse) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
  TrackNamespace received_namespace;
  TransactionType type;
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"bar"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kPending);
}

TEST_F(MoqtNamespaceSubscriberStreamTest, NamespaceDoneAfterResponse) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
  stream_.OnNamespaceDoneMessage({TrackNamespace({"bar"})});
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

TEST_F(MoqtNamespaceSubscriberStreamTest, DuplicateNamespace) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
  EXPECT_CALL(error_callback_,
              Call(MoqtError::kProtocolViolation,
                   "Two NAMESPACE messages for the same track namespace"));
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, NamespaceDoneWithoutNamespace) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
  EXPECT_CALL(error_callback_, Call(MoqtError::kProtocolViolation,
                                    "NAMESPACE_DONE with no active namespace"));
  stream_.OnNamespaceDoneMessage({TrackNamespace({"bar"})});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, NamespaceDoneThenNamespace) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
  EXPECT_CALL(error_callback_, Call).Times(0);
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
  stream_.OnNamespaceDoneMessage({TrackNamespace({"bar"})});
  stream_.OnNamespaceMessage({TrackNamespace({"buzz"})});
}

TEST_F(MoqtNamespaceSubscriberStreamTest, TaskGetNextSuffix) {
  EXPECT_CALL(response_callback_, Call(Eq(std::nullopt)));
  stream_.OnRequestOkMessage({kRequestId});
  stream_.OnNamespaceMessage({TrackNamespace({"bar"})});
  stream_.OnNamespaceMessage({TrackNamespace({"buzz"})});
  stream_.OnNamespaceDoneMessage({TrackNamespace({"bar"})});
  TrackNamespace received_namespace;
  TransactionType type;
  bool object_available = false;
  task_->SetObjectAvailableCallback([&]() { object_available = true; });
  EXPECT_TRUE(object_available);
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
  object_available = false;
  stream_.OnNamespaceMessage({TrackNamespace({"another"})});
  EXPECT_TRUE(object_available);
  object_available = false;
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kSuccess);
  EXPECT_EQ(received_namespace, TrackNamespace({"another"}));
  EXPECT_EQ(type, TransactionType::kAdd);
  EXPECT_EQ(task_->GetNextSuffix(received_namespace, type), kPending);
}

class MoqtNamespacePublisherStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtNamespacePublisherStreamTest()
      : framer_(false),
        tree_(),
        application_callback_(mock_application_.AsStdFunction()),
        stream_(&framer_, &mock_stream_, error_callback_.AsStdFunction(), tree_,
                application_callback_) {
    EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly(Return(true));
  }

  MoqtFramer framer_;
  testing::MockFunction<void(MoqtError, absl::string_view)> error_callback_;
  webtransport::test::MockStream mock_stream_;
  SessionNamespaceTree tree_;
  testing::MockFunction<std::unique_ptr<MoqtNamespaceTask>(
      const TrackNamespace&, std::optional<MessageParameters>,
      MoqtResponseCallback)>
      mock_application_;
  MoqtIncomingSubscribeNamespaceCallbackNew application_callback_;
  MoqtNamespacePublisherStream stream_;
};

TEST_F(MoqtNamespacePublisherStreamTest, Subscribe) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      SubscribeNamespaceOption::kNamespace,
      MessageParameters(),
  };
  ObjectsAvailableCallback callback;
  MockNamespaceTask* task_ptr;
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, std::optional<MessageParameters>,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(std::nullopt);
        auto task =
            std::make_unique<MockNamespaceTask>(message.track_namespace_prefix);
        EXPECT_CALL(*task, SetObjectAvailableCallback)
            .WillOnce([&](ObjectsAvailableCallback oa_callback) {
              callback = std::move(oa_callback);
            });
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  stream_.OnSubscribeNamespaceMessage(message);
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
  callback();

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
                    const quiche::StreamWriteOptions& options) {
        EXPECT_EQ(slices.size(), 1);
        EXPECT_EQ(slices[0].data()[0],
                  static_cast<uint8_t>(MoqtMessageType::kNamespaceDone));
        EXPECT_FALSE(options.send_fin());
        return absl::OkStatus();
      })
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> slices,
                    const quiche::StreamWriteOptions& options) {
        EXPECT_EQ(slices.size(), 0);
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  callback();
}

TEST_F(MoqtNamespacePublisherStreamTest, RequestError) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo"}),
      SubscribeNamespaceOption::kNamespace,
      MessageParameters(),
  };
  EXPECT_CALL(mock_application_, Call)
      .WillOnce([&](const TrackNamespace&, std::optional<MessageParameters>,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MoqtRequestErrorInfo{
            RequestErrorCode::kInternalError,
            quic::QuicTimeDelta::FromMilliseconds(100), "bar"});
        auto task =
            std::make_unique<MockNamespaceTask>(message.track_namespace_prefix);
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_.OnSubscribeNamespaceMessage(message);
}

TEST_F(MoqtNamespacePublisherStreamTest, SubscribePrefixOverlap) {
  MoqtSubscribeNamespace message = {
      kRequestId,
      TrackNamespace({"foo", "bar", "baz"}),
      SubscribeNamespaceOption::kNamespace,
      MessageParameters(),
  };
  // The namespace tree already has a subscriber for a prefix of "foo".
  tree_.SubscribeNamespace(TrackNamespace({"foo", "bar"}));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_.OnSubscribeNamespaceMessage(message);
  // Try to subscribe to the parent. Also not allowed.
  message.track_namespace_prefix.PopElement();
  message.track_namespace_prefix.PopElement();
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_.OnSubscribeNamespaceMessage(message);
}

}  // namespace
}  // namespace moqt::test
