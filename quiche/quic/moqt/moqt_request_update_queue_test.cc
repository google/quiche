// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_request_update_queue.h"

#include <optional>
#include <utility>
#include <variant>

#include "absl/status/status.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace moqt::test {

TEST(MoqtRequestUpdateQueueTest, EmptyQueue) {
  MoqtRequestUpdateQueue queue;
  EXPECT_TRUE(queue.empty());
  EXPECT_EQ(queue.NextParameters().status().code(),
            absl::StatusCode::kFailedPrecondition);
}

TEST(MoqtRequestUpdateQueueTest, EnqueueAndReceiveOk) {
  MoqtRequestUpdateQueue queue;
  MessageParameters params1;
  params1.subscriber_priority = 20;
  MessageParameters params2;
  params2.subscriber_priority = 25;

  bool callback1_called = false;
  MoqtResponseCallback callback1 =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback1_called = true;
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(res));
        EXPECT_EQ(std::get<MessageParameters>(res).subscriber_priority, 30);
      };

  bool callback2_called = false;
  MoqtResponseCallback callback2 =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback2_called = true;
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(res));
        EXPECT_EQ(std::get<MessageParameters>(res).subscriber_priority, 35);
      };

  queue.Enqueue(params1, std::move(callback1));
  queue.Enqueue(params2, std::move(callback2));
  EXPECT_FALSE(queue.empty());

  absl::StatusOr<MessageParameters> next_params = queue.NextParameters();
  QUICHE_EXPECT_OK(next_params);
  EXPECT_EQ(next_params->subscriber_priority, 20);

  MoqtRequestOk request_ok1;
  request_ok1.parameters.subscriber_priority = 30;

  QUICHE_EXPECT_OK(queue.OnControlMessage(request_ok1));
  EXPECT_TRUE(callback1_called);
  EXPECT_FALSE(callback2_called);
  EXPECT_FALSE(queue.empty());

  next_params = queue.NextParameters();
  QUICHE_EXPECT_OK(next_params);
  EXPECT_EQ(next_params->subscriber_priority, 25);

  MoqtRequestOk request_ok2;
  request_ok2.parameters.subscriber_priority = 35;

  QUICHE_EXPECT_OK(queue.OnControlMessage(request_ok2));
  EXPECT_TRUE(callback2_called);
  EXPECT_TRUE(queue.empty());
  EXPECT_EQ(queue.NextParameters().status().code(),
            absl::StatusCode::kFailedPrecondition);
}

TEST(MoqtRequestUpdateQueueTest, EnqueueAndReceiveError) {
  MoqtRequestUpdateQueue queue;
  MessageParameters params;

  bool callback_called = false;
  MoqtResponseCallback callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(res));
        EXPECT_EQ(std::get<MoqtRequestErrorInfo>(res).error_code,
                  RequestErrorCode::kUnauthorized);
      };

  queue.Enqueue(params, std::move(callback));
  EXPECT_FALSE(queue.empty());

  MoqtRequestError request_error;
  request_error.error_code = RequestErrorCode::kUnauthorized;
  request_error.reason_phrase = "unauthorized";

  QUICHE_EXPECT_OK(queue.OnControlMessage(request_error));
  EXPECT_TRUE(callback_called);
  EXPECT_TRUE(queue.empty());
}

}  // namespace moqt::test
