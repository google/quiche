// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_bidi_stream.h"

#include <memory>
#include <optional>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"

namespace moqt::test {

class TestMoqtBidiStream : public MoqtBidiStreamBase {
 public:
  using MoqtBidiStreamBase::MoqtBidiStreamBase;

  absl::Status OnControlMessage(const MoqtRequestOk& message) {
    ++ok_received_;
    return absl::OkStatus();
  }

  void OnStreamBound() override {}
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override {
    return ControlMessageDispatcher::DispatchControlMessage(
        *this, message_parser(), message, "test");
  }
  void Detach() override { detached_ = true; }

  int ok_received_ = 0;
  bool detached_ = false;
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
  EXPECT_CALL(mock_stream_, ResetWithUserCode(1234));
  stream_->Reset(1234);
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, IncomingReset) {
  stream_->BindStream(&mock_stream_);
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
      1,
      MoqtRequestErrorInfo{RequestErrorCode::kUnauthorized,
                           /*retry_interval=*/std::nullopt, ""},
      false));
  EXPECT_FALSE(stream_->detached_);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestError), testing::_));
  QUICHE_EXPECT_OK(stream_->SendRequestError(
      1,
      MoqtRequestErrorInfo{RequestErrorCode::kUnauthorized,
                           /*retry_interval=*/std::nullopt, ""},
      true));
  EXPECT_TRUE(stream_->detached_);
}

TEST_F(MoqtBidiStreamTest, DispatchControlMessage) {
  webtransport::test::InMemoryStream stream(0);
  stream_->BindStream(&stream);
  MoqtFramer framer(/*using_webtrans=*/true, quic::Perspective::IS_SERVER);
  stream.Receive(framer.SerializeRequestOk(MoqtRequestOk()).AsStringView());
  stream_->OnCanRead();
  EXPECT_EQ(stream_->ok_received_, 1u);

  stream.Receive(framer.SerializeGoAway(MoqtGoAway()).AsStringView());
  EXPECT_CALL(error_callback_, Call)
      .WillOnce([](MoqtError error, absl::string_view message) {
        EXPECT_EQ(error, MoqtError::kProtocolViolation);
        EXPECT_EQ(
            message,
            "Received an unexpected message of type GOAWAY on a test stream");
      });
  stream_->OnCanRead();
}

}  // namespace moqt::test
