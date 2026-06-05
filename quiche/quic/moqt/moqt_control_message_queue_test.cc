// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_control_message_queue.h"

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

using ::testing::Return;

namespace moqt::test {
namespace {

class MoqtControlMessageQueueTest : public quiche::test::QuicheTest {
 public:
  MoqtControlMessageQueueTest() : queue_(&mock_stream_) {}

  quiche::QuicheBuffer MakeMessage(absl::string_view payload) {
    return quiche::QuicheBuffer::Copy(quiche::SimpleBufferAllocator::Get(),
                                      payload);
  }

  webtransport::test::MockStream mock_stream_;
  MoqtControlMessageQueue queue_;
};

TEST_F(MoqtControlMessageQueueTest, MessageBufferedThenSent) {
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  QUICHE_EXPECT_OK(queue_.SendOrBufferMessage(MakeMessage("message1")));
  QUICHE_EXPECT_OK(queue_.SendOrBufferMessage(MakeMessage("message2")));
  QUICHE_EXPECT_OK(queue_.Fin());
  {
    testing::InSequence seq;
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_stream_, Writev)
        .WillOnce([](absl::Span<quiche::QuicheMemSlice> slices,
                     const webtransport::StreamWriteOptions& options) {
          EXPECT_EQ(slices.size(), 1u);
          EXPECT_EQ(slices[0].AsStringView(), "message1");
          EXPECT_FALSE(options.send_fin());
          return absl::OkStatus();
        });
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_stream_, Writev)
        .WillOnce([](absl::Span<quiche::QuicheMemSlice> slices,
                     const webtransport::StreamWriteOptions& options) {
          EXPECT_EQ(slices.size(), 1u);
          EXPECT_EQ(slices[0].AsStringView(), "message2");
          EXPECT_TRUE(options.send_fin());
          return absl::OkStatus();
        });
  }
  QUICHE_EXPECT_OK(queue_.OnCanWrite());
}

TEST_F(MoqtControlMessageQueueTest, FinSentWhenEmpty) {
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> slices,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(slices.empty());
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  QUICHE_EXPECT_OK(queue_.Fin());
}

TEST_F(MoqtControlMessageQueueTest, PendingQueueFull) {
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(false));
  for (int i = 0; i < MoqtControlMessageQueue::kMaxPendingMessages; ++i) {
    EXPECT_FALSE(queue_.QueueIsFull());
    QUICHE_EXPECT_OK(queue_.SendOrBufferMessage(MakeMessage("msg")));
  }
  EXPECT_TRUE(queue_.QueueIsFull());
  EXPECT_EQ(queue_.SendOrBufferMessage(MakeMessage("msg")).code(),
            absl::StatusCode::kResourceExhausted);
}

TEST_F(MoqtControlMessageQueueTest, SendWhenCanWrite) {
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> slices,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(slices.size(), 1u);
        EXPECT_EQ(slices[0].AsStringView(), "immediate");
        EXPECT_FALSE(options.send_fin());
        return absl::OkStatus();
      });
  QUICHE_EXPECT_OK(
      queue_.SendOrBufferMessage(MakeMessage("immediate"), /*fin=*/false));
}

TEST_F(MoqtControlMessageQueueTest, ErrorWhenFinAlreadyQueued) {
  EXPECT_CALL(mock_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  QUICHE_EXPECT_OK(queue_.Fin());
  EXPECT_EQ(queue_.SendOrBufferMessage(MakeMessage("msg")).code(),
            absl::StatusCode::kInternal);
}

TEST_F(MoqtControlMessageQueueTest, OnCanWriteWithoutStream) {
  MoqtControlMessageQueue queue(nullptr);
  EXPECT_EQ(queue.OnCanWrite().code(), absl::StatusCode::kInternal);
}

TEST_F(MoqtControlMessageQueueTest, BufferFinWithoutStream) {
  MoqtControlMessageQueue queue(nullptr);
  QUICHE_EXPECT_OK(queue.Fin());
  queue.SetStream(&mock_stream_);

  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> slices,
                   const webtransport::StreamWriteOptions& options) {
        EXPECT_TRUE(slices.empty());
        EXPECT_TRUE(options.send_fin());
        return absl::OkStatus();
      });
  QUICHE_EXPECT_OK(queue.OnCanWrite());
}

}  // namespace
}  // namespace moqt::test
