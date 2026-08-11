// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_track_status_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
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
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {
namespace {

using ::quiche::test::StatusIs;
using ::testing::_;
using ::testing::IsEmpty;
using ::testing::Property;
using ::testing::Return;
using ::testing::StrictMock;

class MoqtTrackStatusRequestStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtTrackStatusRequestStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_CLIENT),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_CLIENT),
        track_name_("foo", "bar") {}

  MoqtTrackStatusRequestStream CreateStream(
      const MessageParameters& parameters = MessageParameters()) {
    return MoqtTrackStatusRequestStream(&framer_, message_parser_, kRequestId,
                                        track_name_, parameters,
                                        session_error_callback_.AsStdFunction(),
                                        response_callback_.AsStdFunction());
  }

 protected:
  static constexpr uint64_t kRequestId = 2;

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  FullTrackName track_name_;
  StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      session_error_callback_;
  StrictMock<testing::MockFunction<void(
      std::variant<MessageParameters, MoqtRequestErrorInfo>)>>
      response_callback_;
  StrictMock<webtransport::test::MockStream> mock_stream_;
};

TEST_F(MoqtTrackStatusRequestStreamTest, SendRequestOnStreamBound) {
  MoqtTrackStatusRequestStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kTrackStatus), _));
  EXPECT_CALL(response_callback_, Call)
      .WillOnce([&](std::variant<MessageParameters, MoqtRequestErrorInfo> v) {
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(v));
        auto info = std::get<MoqtRequestErrorInfo>(v);
        EXPECT_EQ(info.error_code, RequestErrorCode::kInternalError);
        EXPECT_EQ(info.reason_phrase, "Stream closed");
      });
  stream.BindStream(&mock_stream_);
}

TEST_F(MoqtTrackStatusRequestStreamTest, SendRequestWithParameters) {
  MessageParameters parameters;
  parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(5);
  MoqtTrackStatusRequestStream stream = CreateStream(parameters);
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  MoqtTrackStatus expected_message;
  expected_message.request_id = kRequestId;
  expected_message.full_track_name = track_name_;
  expected_message.parameters = parameters;
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_message), _));
  EXPECT_CALL(response_callback_, Call)
      .WillOnce([&](std::variant<MessageParameters, MoqtRequestErrorInfo> v) {
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(v));
        auto info = std::get<MoqtRequestErrorInfo>(v);
        EXPECT_EQ(info.error_code, RequestErrorCode::kInternalError);
        EXPECT_EQ(info.reason_phrase, "Stream closed");
      });
  stream.BindStream(&mock_stream_);
}

TEST_F(MoqtTrackStatusRequestStreamTest, ReceiveOkResponse) {
  MoqtTrackStatusRequestStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kTrackStatus), _));
  stream.BindStream(&mock_stream_);

  MessageParameters parameters;
  parameters.expires = quic::QuicTimeDelta::FromSeconds(10);
  parameters.largest_object = Location(1, 2);

  EXPECT_CALL(response_callback_, Call)
      .WillOnce([&](std::variant<MessageParameters, MoqtRequestErrorInfo> v) {
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(v));
        auto params = std::get<MessageParameters>(v);
        EXPECT_EQ(params.expires, parameters.expires);
        EXPECT_EQ(params.largest_object, parameters.largest_object);
      });
  EXPECT_CALL(mock_stream_, Writev(testing::IsEmpty(), _));

  MoqtRequestOk ok;
  ok.request_id = kRequestId;
  ok.parameters = parameters;

  QUICHE_EXPECT_OK(
      stream.OnRawControlMessage(GenericMessageToRawControlMessage(ok)));
}

TEST_F(MoqtTrackStatusRequestStreamTest, ReceiveErrorResponse) {
  MoqtTrackStatusRequestStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kTrackStatus), _));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(response_callback_, Call)
      .WillOnce([&](std::variant<MessageParameters, MoqtRequestErrorInfo> v) {
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(v));
        auto info = std::get<MoqtRequestErrorInfo>(v);
        EXPECT_EQ(info.error_code, RequestErrorCode::kDoesNotExist);
        EXPECT_EQ(info.reason_phrase, "Track does not exist");
      });
  EXPECT_CALL(
      mock_stream_,
      Writev(IsEmpty(),
             Property(&webtransport::StreamWriteOptions::send_fin, true)));

  MoqtRequestError error;
  error.request_id = kRequestId;
  error.error_code = RequestErrorCode::kDoesNotExist;
  error.reason_phrase = "Track does not exist";

  QUICHE_EXPECT_OK(
      stream.OnRawControlMessage(GenericMessageToRawControlMessage(error)));
}

TEST_F(MoqtTrackStatusRequestStreamTest, DuplicateRequestOk) {
  MoqtTrackStatusRequestStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kTrackStatus), _));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(response_callback_, Call);
  EXPECT_CALL(mock_stream_, Writev(testing::IsEmpty(), _));

  MoqtRequestOk ok;
  ok.request_id = kRequestId;

  QUICHE_EXPECT_OK(
      stream.OnRawControlMessage(GenericMessageToRawControlMessage(ok)));

  EXPECT_THAT(
      stream.OnRawControlMessage(GenericMessageToRawControlMessage(ok)),
      StatusIs(absl::StatusCode::kInvalidArgument, "Duplicate REQUEST_OK"));
}

TEST_F(MoqtTrackStatusRequestStreamTest, DuplicateRequestError) {
  MoqtTrackStatusRequestStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kTrackStatus), _));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(response_callback_, Call);
  EXPECT_CALL(
      mock_stream_,
      Writev(IsEmpty(),
             Property(&webtransport::StreamWriteOptions::send_fin, true)));

  MoqtRequestError error;
  error.request_id = kRequestId;
  error.error_code = RequestErrorCode::kDoesNotExist;
  error.reason_phrase = "Track does not exist";

  QUICHE_EXPECT_OK(
      stream.OnRawControlMessage(GenericMessageToRawControlMessage(error)));

  EXPECT_THAT(
      stream.OnRawControlMessage(GenericMessageToRawControlMessage(error)),
      StatusIs(absl::StatusCode::kInvalidArgument, "Duplicate REQUEST_ERROR"));
}

class MoqtTrackStatusResponseStreamTest : public quiche::test::QuicheTest {
 public:
  MoqtTrackStatusResponseStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_SERVER),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_SERVER),
        track_name_("foo", "bar"),
        mock_publisher_(track_name_) {}

  MoqtTrackStatusResponseStream CreateStream() {
    return MoqtTrackStatusResponseStream(
        &framer_, message_parser_, session_error_callback_.AsStdFunction(),
        session_.weak_ptr_factory_.Create());
  }

 protected:
  static constexpr uint64_t kRequestId = 2;
  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  FullTrackName track_name_;
  StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      session_error_callback_;
  MockSessionToPublisherInterface session_;
  MockTrackPublisher mock_publisher_;
  StrictMock<webtransport::test::MockStream> mock_stream_;
};

TEST_F(MoqtTrackStatusResponseStreamTest, ProcessTrackStatusSuccess) {
  MoqtTrackStatusResponseStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(session_, GetTrackPublisher(track_name_))
      .WillOnce(Return(
          std::shared_ptr<MoqtTrackPublisher>(&mock_publisher_, [](auto*) {})));

  MoqtObjectListener* listener = nullptr;
  EXPECT_CALL(mock_publisher_, AddObjectListener)
      .WillOnce(testing::SaveArg<0>(&listener));

  MoqtTrackStatus track_status;
  track_status.request_id = kRequestId;
  track_status.full_track_name = track_name_;

  QUICHE_EXPECT_OK(stream.OnRawControlMessage(
      GenericMessageToRawControlMessage(track_status)));
  ASSERT_NE(listener, nullptr);

  EXPECT_CALL(mock_publisher_, expiration)
      .WillRepeatedly(Return(quic::QuicTimeDelta::FromSeconds(5)));
  EXPECT_CALL(mock_publisher_, largest_location)
      .WillRepeatedly(Return(Location(10, 20)));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  EXPECT_CALL(mock_publisher_, RemoveObjectListener(listener));

  listener->OnSubscribeAccepted();
}

TEST_F(MoqtTrackStatusResponseStreamTest, TrackDoesNotExist) {
  MoqtTrackStatusResponseStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(session_, GetTrackPublisher(track_name_))
      .WillOnce(Return(nullptr));

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));

  MoqtTrackStatus track_status;
  track_status.request_id = kRequestId;
  track_status.full_track_name = track_name_;

  QUICHE_EXPECT_OK(stream.OnRawControlMessage(
      GenericMessageToRawControlMessage(track_status)));
}

TEST_F(MoqtTrackStatusResponseStreamTest, DuplicateTrackStatus) {
  MoqtTrackStatusResponseStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(session_, GetTrackPublisher(track_name_))
      .WillOnce(Return(
          std::shared_ptr<MoqtTrackPublisher>(&mock_publisher_, [](auto*) {})));

  MoqtObjectListener* listener = nullptr;
  EXPECT_CALL(mock_publisher_, AddObjectListener)
      .WillOnce(testing::SaveArg<0>(&listener));

  MoqtTrackStatus track_status;
  track_status.request_id = kRequestId;
  track_status.full_track_name = track_name_;

  QUICHE_EXPECT_OK(stream.OnRawControlMessage(
      GenericMessageToRawControlMessage(track_status)));
  ASSERT_NE(listener, nullptr);

  EXPECT_THAT(stream.OnRawControlMessage(
                  GenericMessageToRawControlMessage(track_status)),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       "Duplicate TRACK_STATUS received"));

  EXPECT_CALL(mock_publisher_, RemoveObjectListener(listener));
}

TEST_F(MoqtTrackStatusResponseStreamTest, TrackPublisherDestroyed) {
  MoqtTrackStatusResponseStream stream = CreateStream();
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  stream.BindStream(&mock_stream_);

  EXPECT_CALL(session_, GetTrackPublisher(track_name_))
      .WillOnce(Return(
          std::shared_ptr<MoqtTrackPublisher>(&mock_publisher_, [](auto*) {})));

  MoqtObjectListener* listener = nullptr;
  EXPECT_CALL(mock_publisher_, AddObjectListener)
      .WillOnce(testing::SaveArg<0>(&listener));

  MoqtTrackStatus track_status;
  track_status.request_id = kRequestId;
  track_status.full_track_name = track_name_;

  QUICHE_EXPECT_OK(stream.OnRawControlMessage(
      GenericMessageToRawControlMessage(track_status)));
  ASSERT_NE(listener, nullptr);

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));

  listener->OnTrackPublisherGone();
}

}  // namespace
}  // namespace moqt::test
