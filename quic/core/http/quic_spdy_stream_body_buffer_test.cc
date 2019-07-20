// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_stream_body_buffer.h"

#include <string>

#include "net/third_party/quiche/src/quic/core/quic_stream_sequencer.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_expect_bug.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"

namespace quic {

namespace test {

namespace {

class MockConsumer {
 public:
  MOCK_METHOD1(MarkConsumed, void(size_t num_bytes_consumed));
};

class QuicSpdyStreamBodyBufferTest : public QuicTest {
 public:
  QuicSpdyStreamBodyBufferTest()
      : body_buffer_(std::bind(&MockConsumer::MarkConsumed,
                               &consumer_,
                               std::placeholders::_1)) {}

 protected:
  testing::StrictMock<MockConsumer> consumer_;
  QuicSpdyStreamBodyBuffer body_buffer_;
  HttpEncoder encoder_;
};

TEST_F(QuicSpdyStreamBodyBufferTest, HasBytesToRead) {
  const QuicByteCount header_length = 3;
  std::string body(1024, 'a');

  EXPECT_CALL(consumer_, MarkConsumed(header_length));
  body_buffer_.OnConsumableBytes(header_length);

  EXPECT_FALSE(body_buffer_.HasBytesToRead());
  EXPECT_EQ(0u, body_buffer_.total_body_bytes_received());

  body_buffer_.OnDataPayload(body);
  EXPECT_TRUE(body_buffer_.HasBytesToRead());
  EXPECT_EQ(1024u, body_buffer_.total_body_bytes_received());
}

TEST_F(QuicSpdyStreamBodyBufferTest, PeekBody) {
  const QuicByteCount header_length = 3;
  std::string body(1024, 'a');

  EXPECT_CALL(consumer_, MarkConsumed(header_length));
  body_buffer_.OnConsumableBytes(header_length);
  body_buffer_.OnDataPayload(body);

  iovec vec;
  EXPECT_EQ(1, body_buffer_.PeekBody(&vec, 1));
  EXPECT_EQ(1024u, vec.iov_len);
  EXPECT_EQ(body,
            QuicStringPiece(static_cast<const char*>(vec.iov_base), 1024));
}

// Buffer receives one frame. Stream consumes payload in fragments.
TEST_F(QuicSpdyStreamBodyBufferTest, MarkConsumedPartialSingleFrame) {
  testing::InSequence seq;

  const QuicByteCount header_length = 3;
  std::string body(1024, 'a');

  EXPECT_CALL(consumer_, MarkConsumed(header_length));
  body_buffer_.OnConsumableBytes(header_length);
  body_buffer_.OnDataPayload(body);

  EXPECT_CALL(consumer_, MarkConsumed(512));
  body_buffer_.MarkBodyConsumed(512);

  EXPECT_CALL(consumer_, MarkConsumed(512));
  body_buffer_.MarkBodyConsumed(512);
}

// Buffer receives two frames. Stream consumes multiple times.
TEST_F(QuicSpdyStreamBodyBufferTest, MarkConsumedMultipleFrames) {
  testing::InSequence seq;

  const QuicByteCount header_length1 = 3;
  std::string body1(1024, 'a');

  EXPECT_CALL(consumer_, MarkConsumed(header_length1));
  body_buffer_.OnConsumableBytes(header_length1);
  body_buffer_.OnDataPayload(body1);

  const QuicByteCount header_length2 = 3;
  std::string body2(2048, 'b');
  body_buffer_.OnConsumableBytes(header_length2);
  body_buffer_.OnDataPayload(body2);

  // Consume part of the first frame payload.
  EXPECT_CALL(consumer_, MarkConsumed(512));
  body_buffer_.MarkBodyConsumed(512);

  // Consume rest of the first frame and some of the second.
  EXPECT_CALL(consumer_, MarkConsumed(header_length2 + 2048));
  body_buffer_.MarkBodyConsumed(2048);

  // Consume rest of the second frame.
  EXPECT_CALL(consumer_, MarkConsumed(512));
  body_buffer_.MarkBodyConsumed(512);
}

TEST_F(QuicSpdyStreamBodyBufferTest, MarkConsumedMoreThanBuffered) {
  const QuicByteCount header_length = 3;
  EXPECT_CALL(consumer_, MarkConsumed(header_length));
  body_buffer_.OnConsumableBytes(header_length);

  std::string body(1024, 'a');
  body_buffer_.OnDataPayload(body);
  EXPECT_QUIC_BUG(
      body_buffer_.MarkBodyConsumed(2048),
      "Invalid argument to MarkBodyConsumed. expect to consume: 2048, but not "
      "enough bytes available. Total bytes readable are: 1024");
}

// Buffer receives one frame. Stream reads from the buffer.
TEST_F(QuicSpdyStreamBodyBufferTest, ReadSingleBody) {
  testing::InSequence seq;

  const QuicByteCount header_length = 3;
  std::string body(1024, 'a');

  EXPECT_CALL(consumer_, MarkConsumed(header_length));
  body_buffer_.OnConsumableBytes(header_length);
  body_buffer_.OnDataPayload(QuicStringPiece(body));

  EXPECT_CALL(consumer_, MarkConsumed(1024));
  char base[1024];
  iovec iov = {&base[0], 1024};
  EXPECT_EQ(1024u, body_buffer_.ReadBody(&iov, 1));
  EXPECT_EQ(1024u, iov.iov_len);
  EXPECT_EQ(body,
            QuicStringPiece(static_cast<const char*>(iov.iov_base), 1024));
}

// Buffer receives two frames. Stream reads from the buffer multiple times.
TEST_F(QuicSpdyStreamBodyBufferTest, ReadMultipleBody) {
  testing::InSequence seq;

  const QuicByteCount header_length1 = 3;
  std::string body1(1024, 'a');

  EXPECT_CALL(consumer_, MarkConsumed(header_length1));
  body_buffer_.OnConsumableBytes(header_length1);
  body_buffer_.OnDataPayload(body1);

  const QuicByteCount header_length2 = 3;
  std::string body2(2048, 'b');
  body_buffer_.OnConsumableBytes(header_length2);
  body_buffer_.OnDataPayload(body2);

  // Read part of the first frame payload.
  EXPECT_CALL(consumer_, MarkConsumed(512));
  char base[512];
  iovec iov = {&base[0], 512};
  EXPECT_EQ(512u, body_buffer_.ReadBody(&iov, 1));
  EXPECT_EQ(512u, iov.iov_len);
  EXPECT_EQ(body1.substr(0, 512),
            QuicStringPiece(static_cast<const char*>(iov.iov_base), 512));

  // Read rest of the first frame and some of the second.
  EXPECT_CALL(consumer_, MarkConsumed(header_length2 + 2048));
  char base2[2048];
  iovec iov2 = {&base2[0], 2048};
  EXPECT_EQ(2048u, body_buffer_.ReadBody(&iov2, 1));
  EXPECT_EQ(2048u, iov2.iov_len);
  EXPECT_EQ(body1.substr(512, 512) + body2.substr(0, 1536),
            QuicStringPiece(static_cast<const char*>(iov2.iov_base), 2048));

  // Read rest of the second frame.
  EXPECT_CALL(consumer_, MarkConsumed(512));
  char base3[512];
  iovec iov3 = {&base3[0], 512};
  EXPECT_EQ(512u, body_buffer_.ReadBody(&iov3, 1));
  EXPECT_EQ(512u, iov3.iov_len);
  EXPECT_EQ(body2.substr(1536, 512),
            QuicStringPiece(static_cast<const char*>(iov3.iov_base), 512));
}

}  // anonymous namespace

}  // namespace test

}  // namespace quic
