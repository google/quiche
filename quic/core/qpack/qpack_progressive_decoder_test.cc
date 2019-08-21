// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/qpack/qpack_progressive_decoder.h"

#include "net/third_party/quiche/src/quic/core/qpack/qpack_decoder_test_utils.h"
#include "net/third_party/quiche/src/quic/core/qpack/qpack_test_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"

using ::testing::Eq;
using ::testing::Return;
using ::testing::StrictMock;

namespace quic {
namespace test {
namespace {

const uint64_t kMaximumDynamicTableCapacityForTesting = 1024 * 1024;
const QuicStreamId kStreamId = 0;
// Header Acknowledgement decoder stream instruction with stream_id = 0.
const char* const kHeaderAcknowledgement = "\x80";

class MockEnforcer
    : public QpackProgressiveDecoder::BlockedStreamLimitEnforcer {
 public:
  ~MockEnforcer() override = default;

  MOCK_METHOD(bool, OnStreamBlocked, (QuicStreamId stream_id));
  MOCK_METHOD(void, OnStreamUnblocked, (QuicStreamId stream_id));
};

class QpackProgressiveDecoderTest : public QuicTest {
 protected:
  QpackProgressiveDecoderTest()
      : progressive_decoder_(kStreamId,
                             &enforcer_,
                             &header_table_,
                             &decoder_stream_sender_,
                             &headers_handler_) {
    decoder_stream_sender_.set_qpack_stream_sender_delegate(
        &decoder_stream_sender_delegate_);
    header_table_.SetMaximumDynamicTableCapacity(
        kMaximumDynamicTableCapacityForTesting);
  }
  ~QpackProgressiveDecoderTest() override = default;

  QpackProgressiveDecoder progressive_decoder_;
  StrictMock<MockEnforcer> enforcer_;
  QpackHeaderTable header_table_;
  QpackDecoderStreamSender decoder_stream_sender_;
  StrictMock<MockQpackStreamSenderDelegate> decoder_stream_sender_delegate_;
  StrictMock<MockHeadersHandler> headers_handler_;
};

TEST_F(QpackProgressiveDecoderTest, Literal) {
  EXPECT_CALL(headers_handler_, OnHeaderDecoded(Eq("foo"), Eq("bar")));
  progressive_decoder_.Decode(QuicTextUtils::HexDecode("000023666f6f03626172"));

  EXPECT_CALL(headers_handler_, OnDecodingCompleted());
  progressive_decoder_.EndHeaderBlock();
}

TEST_F(QpackProgressiveDecoderTest, DynamicTableSynchronous) {
  EXPECT_TRUE(header_table_.InsertEntry("foo", "bar"));

  EXPECT_CALL(headers_handler_, OnHeaderDecoded(Eq("foo"), Eq("bar")));
  progressive_decoder_.Decode(QuicTextUtils::HexDecode(
      "0200"   // Required Insert Count 1 and Delta Base 0.
      "80"));  // Dynamic table entry with relative index 0,
               // absolute index 0.

  EXPECT_CALL(headers_handler_, OnDecodingCompleted());
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)));
  progressive_decoder_.EndHeaderBlock();
}

TEST_F(QpackProgressiveDecoderTest, DynamicTableBlocked) {
  EXPECT_CALL(enforcer_, OnStreamBlocked(kStreamId)).WillOnce(Return(true));
  progressive_decoder_.Decode(QuicTextUtils::HexDecode(
      "0200"   // Required Insert Count 1 and Delta Base 0.
      "80"));  // Dynamic table entry with relative index 0,
               // absolute index 0.
  progressive_decoder_.EndHeaderBlock();

  EXPECT_CALL(enforcer_, OnStreamUnblocked(kStreamId));
  EXPECT_CALL(headers_handler_, OnHeaderDecoded(Eq("foo"), Eq("bar")));
  EXPECT_CALL(headers_handler_, OnDecodingCompleted());
  EXPECT_CALL(decoder_stream_sender_delegate_,
              WriteStreamData(Eq(kHeaderAcknowledgement)));

  EXPECT_TRUE(header_table_.InsertEntry("foo", "bar"));
}

TEST_F(QpackProgressiveDecoderTest, TooManyBlockedStreams) {
  EXPECT_CALL(enforcer_, OnStreamBlocked(kStreamId)).WillOnce(Return(false));
  EXPECT_CALL(
      headers_handler_,
      OnDecodingErrorDetected("Limit on number of blocked streams exceeded."));

  // Required Insert Count 1.
  progressive_decoder_.Decode(QuicTextUtils::HexDecode("0200"));
}

}  // namespace
}  // namespace test
}  // namespace quic
