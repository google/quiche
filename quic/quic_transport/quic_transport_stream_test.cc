// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/quic_transport/quic_transport_stream.h"

#include <memory>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quic/core/crypto/null_encrypter.h"
#include "quic/core/frames/quic_window_update_frame.h"
#include "quic/platform/api/quic_expect_bug.h"
#include "quic/platform/api/quic_test.h"
#include "quic/quic_transport/quic_transport_session_interface.h"
#include "quic/test_tools/quic_config_peer.h"
#include "quic/test_tools/quic_test_utils.h"
#include "quic/test_tools/quic_transport_test_tools.h"

namespace quic {
namespace test {
namespace {

using testing::_;
using testing::Return;

ParsedQuicVersionVector GetVersions() {
  return {DefaultVersionForQuicTransport()};
}

class MockQuicTransportSessionInterface : public QuicTransportSessionInterface {
 public:
  MOCK_METHOD(bool, IsSessionReady, (), (const, override));
};

class QuicTransportStreamTest : public QuicTest {
 public:
  QuicTransportStreamTest()
      : connection_(new MockQuicConnection(&helper_,
                                           &alarm_factory_,
                                           Perspective::IS_CLIENT,
                                           GetVersions())),
        session_(connection_) {
    QuicEnableVersion(DefaultVersionForQuicTransport());
    session_.Initialize();
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
    stream_ = new QuicTransportStream(0, &session_, &interface_);
    session_.ActivateStream(absl::WrapUnique(stream_));

    auto visitor = std::make_unique<MockStreamVisitor>();
    visitor_ = visitor.get();
    stream_->SetVisitor(std::move(visitor));
  }

  void ReceiveStreamData(absl::string_view data, QuicStreamOffset offset) {
    QuicStreamFrame frame(0, false, offset, data);
    stream_->OnStreamFrame(frame);
  }

 protected:
  MockAlarmFactory alarm_factory_;
  MockQuicConnectionHelper helper_;

  MockQuicConnection* connection_;  // Owned by |session_|.
  MockQuicSession session_;
  MockQuicTransportSessionInterface interface_;
  QuicTransportStream* stream_;  // Owned by |session_|.
  MockStreamVisitor* visitor_;   // Owned by |stream_|.
};

TEST_F(QuicTransportStreamTest, NotReady) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(false));
  ReceiveStreamData("test", 0);
  EXPECT_EQ(stream_->ReadableBytes(), 0u);
  EXPECT_FALSE(stream_->CanWrite());
}

TEST_F(QuicTransportStreamTest, ReadWhenNotReady) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(false));
  ReceiveStreamData("test", 0);
  char buffer[4];
  WebTransportStream::ReadResult result = stream_->Read(buffer, sizeof(buffer));
  EXPECT_EQ(result.bytes_read, 0u);
  EXPECT_FALSE(result.fin);
}

TEST_F(QuicTransportStreamTest, WriteWhenNotReady) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(false));
  EXPECT_FALSE(stream_->Write("test"));
}

TEST_F(QuicTransportStreamTest, Ready) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(true));
  ReceiveStreamData("test", 0);
  EXPECT_EQ(stream_->ReadableBytes(), 4u);
  EXPECT_TRUE(stream_->CanWrite());
  EXPECT_TRUE(stream_->Write("test"));
}

TEST_F(QuicTransportStreamTest, ReceiveData) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(true));
  EXPECT_CALL(*visitor_, OnCanRead());
  ReceiveStreamData("test", 0);

  std::string buffer;
  WebTransportStream::ReadResult result = stream_->Read(&buffer);
  EXPECT_EQ(result.bytes_read, 4u);
  EXPECT_FALSE(result.fin);
  EXPECT_EQ(buffer, "test");
}

TEST_F(QuicTransportStreamTest, FinReadWithNoDataPending) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(true));
  EXPECT_CALL(*visitor_, OnCanRead());

  QuicStreamFrame frame(0, true, 0, "");
  stream_->OnStreamFrame(frame);

  std::string buffer;
  WebTransportStream::ReadResult result = stream_->Read(&buffer);
  EXPECT_EQ(result.bytes_read, 0u);
  EXPECT_TRUE(result.fin);
  EXPECT_EQ(buffer, "");
}

TEST_F(QuicTransportStreamTest, FinReadWithDataPending) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(true));

  EXPECT_CALL(*visitor_, OnCanRead());
  QuicStreamFrame frame(0, true, 0, "test");
  stream_->OnStreamFrame(frame);

  char buffer[2];
  WebTransportStream::ReadResult result = stream_->Read(buffer, sizeof(buffer));
  EXPECT_EQ(result.bytes_read, 2u);
  EXPECT_FALSE(result.fin);
  EXPECT_EQ(buffer[0], 't');
  EXPECT_EQ(buffer[1], 'e');

  result = stream_->Read(buffer, sizeof(buffer));
  EXPECT_EQ(result.bytes_read, 2u);
  EXPECT_TRUE(result.fin);
  EXPECT_EQ(buffer[0], 's');
  EXPECT_EQ(buffer[1], 't');
}

TEST_F(QuicTransportStreamTest, WritingTooMuchData) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(true));
  ASSERT_TRUE(stream_->CanWrite());

  std::string a_little_bit_of_data(128, 'A');
  std::string a_lot_of_data(GetQuicFlag(FLAGS_quic_buffered_data_threshold) * 2,
                            'a');

  EXPECT_TRUE(stream_->Write(a_little_bit_of_data));
  EXPECT_TRUE(stream_->Write(a_little_bit_of_data));
  EXPECT_TRUE(stream_->Write(a_little_bit_of_data));

  EXPECT_TRUE(stream_->Write(a_lot_of_data));
  EXPECT_FALSE(stream_->Write(a_lot_of_data));
}

TEST_F(QuicTransportStreamTest, CannotSendFinTwice) {
  EXPECT_CALL(interface_, IsSessionReady()).WillRepeatedly(Return(true));
  ASSERT_TRUE(stream_->CanWrite());

  EXPECT_CALL(session_, WritevData(stream_->id(), _, _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, /*fin_consumed=*/true)));
  EXPECT_TRUE(stream_->SendFin());
  EXPECT_FALSE(stream_->CanWrite());
}

}  // namespace
}  // namespace test
}  // namespace quic
