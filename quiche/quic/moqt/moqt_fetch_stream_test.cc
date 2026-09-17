// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_fetch_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_live_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_object_subscriber.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {
namespace {

using ::testing::_;
using ::testing::Return;
using ::testing::StrictMock;

constexpr uint64_t kRequestId = 1;
const FullTrackName kTrackName("foo", "bar");
const Location kStart(1, 1);
const Location kEnd(3, 100);

PublishedObject DefaultObject() {
  PublishedObject object;
  object.metadata = PublishedObjectMetadata{Location(0, 0),
                                            0,
                                            "",
                                            MoqtObjectStatus::kNormal,
                                            kDefaultPublisherPriority,
                                            true,
                                            3};
  object.payload.push_back(quiche::QuicheMemSlice::Copy("foo"));
  object.fin_after_this = false;
  return object;
}

class MockIncomingDataStream : public IncomingDataStream {
 public:
  MockIncomingDataStream(MoqtStreamTypeParser& stream_type_parser,
                         SessionToUniStreamInterface* absl_nonnull session,
                         const quic::MockClock* absl_nonnull clock)
      : IncomingDataStream(std::move(stream_type_parser), session, clock) {}
  MOCK_METHOD(void, set_fetch_task, (UpstreamFetchTask * fetch_task),
              (override));
};

class MoqtFetchRequestStreamTest : public quiche::test::QuicheTest {
 protected:
  MoqtFetchRequestStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_CLIENT),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_CLIENT),
        stream_type_parser_(&mock_stream_),
        data_stream_(stream_type_parser_, &mock_session_, &mock_clock_) {
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
    EXPECT_CALL(delete_callback_, Call).Times(testing::AnyNumber());
    EXPECT_CALL(session_error_callback_, Call).Times(testing::AnyNumber());
  }

  std::unique_ptr<MoqtFetchRequestStream> CreateAndBindStandaloneStream(
      Location start = kStart, Location end = kEnd,
      const MessageParameters& parameters = MessageParameters()) {
    MoqtFetch expected_fetch;
    expected_fetch.request_id = kRequestId;
    expected_fetch.fetch = StandaloneFetch(kTrackName, start, end);
    expected_fetch.parameters = parameters;
    EXPECT_CALL(mock_stream_,
                Writev(SerializedControlMessage(expected_fetch), _))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(task_, set_task_destroyed_callback);
    auto stream = std::make_unique<MoqtFetchRequestStream>(
        &framer_, message_parser_, kRequestId, kTrackName, start, end,
        parameters, &task_, session_error_callback_.AsStdFunction(),
        response_callback_.AsStdFunction(), delete_callback_.AsStdFunction());
    stream->BindStream(&mock_stream_);
    return stream;
  }

  std::unique_ptr<MoqtFetchRequestStream> CreateAndBindJoiningStream(
      uint64_t joining_request_id, uint64_t joining_start, bool relative,
      const MessageParameters& parameters = MessageParameters()) {
    MoqtFetch expected_fetch;
    expected_fetch.request_id = kRequestId;
    if (relative) {
      expected_fetch.fetch =
          JoiningFetchRelative(joining_request_id, joining_start);
    } else {
      expected_fetch.fetch =
          JoiningFetchAbsolute(joining_request_id, joining_start);
    }
    expected_fetch.parameters = parameters;
    EXPECT_CALL(mock_stream_,
                Writev(SerializedControlMessage(expected_fetch), _))
        .WillOnce(Return(absl::OkStatus()));

    EXPECT_CALL(task_, set_task_destroyed_callback)
        .WillOnce([&](TaskDestroyedCallback callback) {
          task_destroyed_callback_ = std::move(callback);
        });
    auto stream = std::make_unique<MoqtFetchRequestStream>(
        &framer_, message_parser_, kRequestId, kTrackName, joining_request_id,
        joining_start, relative, parameters, &task_,
        session_error_callback_.AsStdFunction(),
        response_callback_.AsStdFunction(), delete_callback_.AsStdFunction());
    stream->BindStream(&mock_stream_);
    return stream;
  }

  MoqtFramer framer_;
  webtransport::test::MockStream mock_stream_;
  MoqtControlMessageParser message_parser_;
  MoqtStreamTypeParser stream_type_parser_;
  MockSessionToUniStreamInterface mock_session_;
  quic::MockClock mock_clock_;
  MessageParameters parameters_;
  StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      session_error_callback_;
  StrictMock<testing::MockFunction<void(
      std::variant<FetchOkData, MoqtRequestErrorInfo>)>>
      response_callback_;
  TaskDestroyedCallback task_destroyed_callback_;
  StrictMock<testing::MockFunction<void(uint64_t)>> delete_callback_;
  MockUpstreamFetchTask task_;
  MockIncomingDataStream data_stream_;
};

TEST_F(MoqtFetchRequestStreamTest, OnStreamBoundStandalone) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_EQ(stream->request_id(), kRequestId);
  EXPECT_EQ(stream->full_track_name(), kTrackName);
  EXPECT_TRUE(stream->is_fetch());
}

TEST_F(MoqtFetchRequestStreamTest, OnStreamBoundJoiningRelative) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindJoiningStream(/*joining_request_id=*/10,
                                 /*joining_start=*/2, /*relative=*/true);
  EXPECT_EQ(stream->request_id(), kRequestId);
  EXPECT_EQ(stream->full_track_name(), kTrackName);
  EXPECT_TRUE(stream->is_fetch());
}

TEST_F(MoqtFetchRequestStreamTest, OnStreamBoundJoiningAbsolute) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindJoiningStream(/*joining_request_id=*/10,
                                 /*joining_start=*/5, /*relative=*/false);
  EXPECT_EQ(stream->request_id(), kRequestId);
  EXPECT_EQ(stream->full_track_name(), kTrackName);
  EXPECT_TRUE(stream->is_fetch());
}

TEST_F(MoqtFetchRequestStreamTest, InWindowStandalone) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream(Location(1, 1), Location(3, 100));
  EXPECT_FALSE(stream->InWindow(Location(1, 0)));
  EXPECT_TRUE(stream->InWindow(Location(1, 1)));
  EXPECT_TRUE(stream->InWindow(Location(2, 50)));
  EXPECT_TRUE(stream->InWindow(Location(3, 100)));
  EXPECT_FALSE(stream->InWindow(Location(3, 101)));
  EXPECT_FALSE(stream->InWindow(Location(4, 0)));
}

TEST_F(MoqtFetchRequestStreamTest, InWindowJoiningRelative) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindJoiningStream(/*joining_request_id=*/10,
                                 /*joining_start=*/2, /*relative=*/true);
  // Before FETCH_OK, start is (0, 0), end is max.
  EXPECT_TRUE(stream->InWindow(Location(0, 0)));
  EXPECT_TRUE(stream->InWindow(Location(kMaxGroupId, kMaxObjectId)));

  // Deliver FETCH_OK with end_location = (10, 50).
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(10, 50);
  ok_message.end_of_track = true;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));
  // Window is now defined relative to end_location.
  EXPECT_FALSE(stream->InWindow(Location(7, 99)));
  EXPECT_TRUE(stream->InWindow(Location(8, 0)));
  EXPECT_TRUE(stream->InWindow(Location(9, 10)));
  EXPECT_TRUE(stream->InWindow(Location(10, 50)));
  EXPECT_FALSE(stream->InWindow(Location(10, 51)));
  EXPECT_FALSE(stream->InWindow(Location(11, 0)));
}

TEST_F(MoqtFetchRequestStreamTest, InWindowJoiningRelativeUnderflow) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindJoiningStream(/*joining_request_id=*/10,
                                 /*joining_start=*/10, /*relative=*/true);
  // Deliver FETCH_OK with end_location = (1, 50).
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(1, 50);
  ok_message.end_of_track = false;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));
  EXPECT_TRUE(stream->InWindow(Location(1, 50)));
  EXPECT_FALSE(stream->InWindow(Location(1, 51)));
}

TEST_F(MoqtFetchRequestStreamTest, OnControlMessageFetchOk) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();

  EXPECT_CALL(response_callback_,
              Call(testing::VariantWith<FetchOkData>(testing::_)));
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = true;

  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));
  EXPECT_TRUE(task_.GetStatus().ok());
  EXPECT_TRUE(stream->InWindow(Location(3, 50)));
  EXPECT_FALSE(stream->InWindow(Location(3, 51)));
}

TEST_F(MoqtFetchRequestStreamTest, OnControlMessageDuplicateFetchOk) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = true;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));
  // Second FETCH_OK on the same stream should return InvalidArgumentError.
  EXPECT_EQ(stream->OnControlMessage(ok_message).code(),
            absl::StatusCode::kInvalidArgument);
}

TEST_F(MoqtFetchRequestStreamTest, OnControlMessageRequestErrorInitial) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_,
              Call(testing::VariantWith<MoqtRequestErrorInfo>(testing::_)));
  ExpectFin(mock_stream_);
  MoqtRequestError error_message;
  error_message.error_code = RequestErrorCode::kUnauthorized;
  error_message.reason_phrase = "Unauthorized";
  QUICHE_EXPECT_OK(stream->OnControlMessage(error_message));
}

TEST_F(MoqtFetchRequestStreamTest, SendRequestUpdateAndReceiveOk) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = true;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));

  // Send REQUEST_UPDATE.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _))
      .WillOnce(Return(absl::OkStatus()));
  MessageParameters update_params;
  update_params.subscriber_priority = 50;
  bool update_callback_called = false;
  MoqtResponseCallback update_callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        update_callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MessageParameters>(res));
        EXPECT_EQ(std::get<MessageParameters>(res).subscriber_priority, 50);
      };
  QUICHE_EXPECT_OK(stream->SendRequestUpdate(
      /*request_id=*/2, /*joining_start=*/0, update_params,
      std::move(update_callback)));

  // Receive REQUEST_OK for the update.
  MoqtRequestOk request_ok;
  request_ok.parameters.subscriber_priority = 50;
  QUICHE_EXPECT_OK(stream->OnControlMessage(request_ok));
  EXPECT_TRUE(update_callback_called);
  EXPECT_EQ(stream->const_parameters().subscriber_priority, 50);
}

TEST_F(MoqtFetchRequestStreamTest, ReceiveRequestOkWithoutPendingUpdate) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = true;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));
  MoqtRequestOk request_ok;
  EXPECT_EQ(stream->OnControlMessage(request_ok).code(),
            absl::StatusCode::kFailedPrecondition);
}

TEST_F(MoqtFetchRequestStreamTest, SendRequestUpdateAndReceiveError) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = true;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));

  // Send REQUEST_UPDATE.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _))
      .WillOnce(Return(absl::OkStatus()));
  MessageParameters update_params;
  update_params.subscriber_priority = 50;
  bool update_callback_called = false;
  MoqtRequestError request_error(RequestErrorCode::kUnauthorized, std::nullopt,
                                 "Unauthorized");
  MoqtResponseCallback update_callback =
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> res) {
        update_callback_called = true;
        ASSERT_TRUE(std::holds_alternative<MoqtRequestErrorInfo>(res));
        EXPECT_EQ(request_error, std::get<MoqtRequestErrorInfo>(res));
      };
  QUICHE_EXPECT_OK(stream->SendRequestUpdate(
      /*request_id=*/2, /*joining_start=*/0, update_params,
      std::move(update_callback)));

  ExpectFin(mock_stream_);
  QUICHE_EXPECT_OK(stream->OnControlMessage(request_error));
  EXPECT_TRUE(update_callback_called);
}

TEST_F(MoqtFetchRequestStreamTest, OnRawControlMessage) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = false;
  QUICHE_EXPECT_OK(stream->OnRawControlMessage(
      GenericMessageToRawControlMessage(ok_message)));
  EXPECT_TRUE(task_.GetStatus().ok());
}

TEST_F(MoqtFetchRequestStreamTest, DetachCallsRemoveCallbackAndClosesTask) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(response_callback_, Call);
  MoqtFetchOk ok_message;
  ok_message.end_location = Location(3, 50);
  ok_message.end_of_track = true;
  QUICHE_EXPECT_OK(stream->OnControlMessage(ok_message));
  EXPECT_CALL(delete_callback_, Call(kRequestId));
  EXPECT_CALL(task_,
              OnStreamAndFetchClosed(absl::CancelledError("stream destroyed")));
  stream = nullptr;  // Destroys stream, triggering Detach().
  EXPECT_TRUE(task_.GetStatus().ok());
}

TEST_F(MoqtFetchRequestStreamTest, OnStreamClosedWithError) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(data_stream_, set_fetch_task(&task_));
  stream->OnStreamOpened(&data_stream_);
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeCancelled));
  // Data stream now has responsibility for the task.
  EXPECT_CALL(task_, OnStreamAndFetchClosed).Times(0);
  stream->OnStreamClosed(absl::CancelledError(), std::nullopt);
}

TEST_F(MoqtFetchRequestStreamTest, OnStreamClosedWithFin) {
  std::unique_ptr<MoqtFetchRequestStream> stream =
      CreateAndBindStandaloneStream();
  EXPECT_CALL(data_stream_, set_fetch_task(&task_));
  stream->OnStreamOpened(&data_stream_);
  ExpectFin(mock_stream_);
  // Data stream now has responsibility for the task.
  EXPECT_CALL(task_, OnStreamAndFetchClosed).Times(0);
  stream->OnStreamClosed(absl::OkStatus(), std::nullopt);
}

class MockMoqtPublisher : public MoqtPublisher {
 public:
  MOCK_METHOD(std::shared_ptr<MoqtTrackPublisher>, GetTrack,
              (const FullTrackName& track_name), (override));
};

class MoqtFetchResponseStreamTest : public quiche::test::QuicheTest {
 protected:
  MoqtFetchResponseStreamTest()
      : framer_(/*using_webtrans=*/true, quic::Perspective::IS_SERVER),
        message_parser_(kDefaultMoqtVersion, /*uses_web_transport=*/true,
                        quic::Perspective::IS_SERVER),
        track_publisher_(std::make_shared<MockTrackPublisher>(kTrackName)) {
    EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
    EXPECT_CALL(mock_stream_, GetStreamId).WillRepeatedly(Return(4));
    EXPECT_CALL(session_error_callback_, Call).Times(testing::AnyNumber());
    ON_CALL(mock_data_stream_, CanWrite).WillByDefault(Return(true));
    ON_CALL(mock_stream_, CanWrite).WillByDefault(Return(true));
  }

  std::unique_ptr<MoqtFetchResponseStream> CreateAndBindStream(
      bool has_subscription_callback = true) {
    MoqtFetchResponseStream::GetSubscriptionCallback subscription_cb;
    if (has_subscription_callback) {
      subscription_cb = get_subscription_callback_.AsStdFunction();
    }
    auto stream = std::make_unique<MoqtFetchResponseStream>(
        &framer_, message_parser_, &mock_publisher_,
        session_error_callback_.AsStdFunction(),
        open_stream_callback_.AsStdFunction(), std::move(subscription_cb));
    stream->BindStream(&mock_stream_);
    return stream;
  }

  MoqtFramer framer_;
  MoqtControlMessageParser message_parser_;
  webtransport::test::MockStream mock_stream_, mock_data_stream_;
  MockMoqtPublisher mock_publisher_;
  std::shared_ptr<MockTrackPublisher> track_publisher_;
  MockFetchTask task_;
  StrictMock<testing::MockFunction<void(MoqtError, absl::string_view)>>
      session_error_callback_;
  StrictMock<
      testing::MockFunction<void(webtransport::StreamId, MoqtTrackPriority)>>
      open_stream_callback_;
  StrictMock<testing::MockFunction<LivePublisher*(uint64_t)>>
      get_subscription_callback_;
  MoqtTraceRecorder trace_recorder_;
};

TEST_F(MoqtFetchResponseStreamTest, ReceiveFetchStandaloneSuccess) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_FALSE(stream->request_id().has_value());
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        std::move(callback)(ok_data);
        return std::make_unique<MockFetchTask>();
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
  EXPECT_EQ(stream->request_id(), kRequestId);
}

TEST_F(MoqtFetchResponseStreamTest, ReceiveFetchStandaloneTrackDoesNotExist) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName)).WillOnce(Return(nullptr));
  MoqtRequestError expected_error = {RequestErrorCode::kDoesNotExist,
                                     std::nullopt, "not found"};
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_error), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
}

TEST_F(MoqtFetchResponseStreamTest,
       ReceiveFetchStandaloneErrorFromApplication) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  MoqtRequestError expected_error = {RequestErrorCode::kInternalError,
                                     std::nullopt, "Application error"};
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        std::move(callback)(expected_error);
        return nullptr;
      });

  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_error), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
}

TEST_F(MoqtFetchResponseStreamTest, ReceiveDuplicateFetch) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        std::move(callback)(ok_data);
        return std::make_unique<MockFetchTask>();
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));

  EXPECT_THAT(stream->OnControlMessage(fetch),
              quiche::test::StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(MoqtFetchResponseStreamTest,
       AsyncObjectAvailableCallsOpenStreamCallback) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MockFetchTask* task_ptr = nullptr;
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        auto task = std::make_unique<MockFetchTask>();
        std::move(callback)(ok_data);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));
  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.parameters.subscriber_priority = 50;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
  ASSERT_NE(task_ptr, nullptr);

  EXPECT_CALL(open_stream_callback_,
              Call(4, MoqtTrackPriority{50, kDefaultPublisherPriority}))
      .WillOnce([&](uint64_t, MoqtTrackPriority) {
        stream->OnDataStreamOpen(&mock_data_stream_, &trace_recorder_);
      });
  EXPECT_CALL(mock_data_stream_, SetPriority);
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_data_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(*task_ptr, GetNextObject)
      .WillOnce([&](PublishedObject& object) {
        object = DefaultObject();
        return MoqtFetchTask::kSuccess;
      })
      .WillOnce(Return(MoqtFetchTask::kPending));
  EXPECT_CALL(mock_data_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  task_ptr->CallObjectsAvailableCallback();
  EXPECT_NE(data_stream_visitor, nullptr);
}

TEST_F(MoqtFetchResponseStreamTest,
       SyncObjectAvailableCallsOpenStreamCallback) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MockFetchTask* task_ptr = nullptr;
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        auto task = std::make_unique<MockFetchTask>(true);
        std::move(callback)(ok_data);
        EXPECT_CALL(*task, GetNextObject)
            .WillOnce([&](PublishedObject& object) {
              object = DefaultObject();
              return MoqtFetchTask::kSuccess;
            })
            .WillOnce(Return(MoqtFetchTask::kPending));
        EXPECT_CALL(mock_data_stream_, Writev)
            .WillOnce(Return(absl::OkStatus()));
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(open_stream_callback_,
              Call(4, MoqtTrackPriority{50, kDefaultPublisherPriority}))
      .WillOnce([&](uint64_t, MoqtTrackPriority) {
        stream->OnDataStreamOpen(&mock_data_stream_, &trace_recorder_);
      });
  EXPECT_CALL(mock_data_stream_, SetPriority);
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_data_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });
  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.parameters.subscriber_priority = 50;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
  ASSERT_NE(task_ptr, nullptr);
  EXPECT_NE(data_stream_visitor, nullptr);
}

TEST_F(MoqtFetchResponseStreamTest, OnDataStreamOpenCleanAsyncTeardown) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MockFetchTask* task_ptr = nullptr;
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        auto task = std::make_unique<MockFetchTask>(true);
        std::move(callback)(ok_data);
        EXPECT_CALL(*task, GetNextObject)
            .WillOnce([&](PublishedObject& object) {
              object = DefaultObject();
              return MoqtFetchTask::kSuccess;
            })
            .WillOnce(Return(MoqtFetchTask::kPending));
        EXPECT_CALL(mock_data_stream_, Writev)
            .WillOnce(Return(absl::OkStatus()));
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(open_stream_callback_,
              Call(4, MoqtTrackPriority{50, kDefaultPublisherPriority}))
      .WillOnce([&](uint64_t, MoqtTrackPriority) {
        stream->OnDataStreamOpen(&mock_data_stream_, &trace_recorder_);
      });
  EXPECT_CALL(mock_data_stream_, SetPriority);
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_data_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });
  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.parameters.subscriber_priority = 50;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
  ASSERT_NE(task_ptr, nullptr);
  EXPECT_NE(data_stream_visitor, nullptr);
  EXPECT_CALL(*task_ptr, GetNextObject).WillOnce(Return(MoqtFetchTask::kEof));
  ExpectFin(mock_data_stream_);
  ExpectFin(mock_stream_);
  task_ptr->CallObjectsAvailableCallback();
}

TEST_F(MoqtFetchResponseStreamTest, OnDataStreamOpenCleanSyncTeardown) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MockFetchTask* task_ptr = nullptr;
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        auto task = std::make_unique<MockFetchTask>(true);
        std::move(callback)(ok_data);
        EXPECT_CALL(*task, GetNextObject).WillOnce(Return(MoqtFetchTask::kEof));
        ExpectFin(mock_data_stream_);
        ExpectFin(mock_stream_);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(open_stream_callback_,
              Call(4, MoqtTrackPriority{50, kDefaultPublisherPriority}))
      .WillOnce([&](uint64_t, MoqtTrackPriority) {
        stream->OnDataStreamOpen(&mock_data_stream_, &trace_recorder_);
      });
  EXPECT_CALL(mock_data_stream_, SetPriority);
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_data_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });
  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.parameters.subscriber_priority = 50;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
}

TEST_F(MoqtFetchResponseStreamTest, OnDataStreamOpenErrorTeardown) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MockFetchTask* task_ptr = nullptr;
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        auto task = std::make_unique<MockFetchTask>();
        std::move(callback)(ok_data);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
  ASSERT_NE(task_ptr, nullptr);

  webtransport::test::MockStream mock_data_stream;
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_data_stream, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_data_stream, GetStreamId).WillRepeatedly(Return(10));
  EXPECT_CALL(mock_data_stream, SetPriority).Times(testing::AtLeast(1));
  EXPECT_CALL(mock_data_stream, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(*task_ptr, GetNextObject).WillOnce(Return(MoqtFetchTask::kError));
  EXPECT_CALL(*task_ptr, GetStatus())
      .WillOnce(Return(absl::InternalError("Fetch failed")));
  EXPECT_CALL(mock_data_stream, ResetWithUserCode(kResetCodeInternalError));
  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeInternalError));
  stream->OnDataStreamOpen(&mock_data_stream, &trace_recorder_);
}

TEST_F(MoqtFetchResponseStreamTest, ReceiveRequestUpdate) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        std::move(callback)(ok_data);
        return std::make_unique<MockFetchTask>();
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _))
      .WillOnce(Return(absl::OkStatus()));
  MoqtRequestUpdate update;
  update.request_id = kRequestId;
  update.parameters.subscriber_priority = 20;
  QUICHE_EXPECT_OK(stream->OnControlMessage(update));
}

TEST_F(MoqtFetchResponseStreamTest, OnRawControlMessage) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        std::move(callback)(ok_data);
        return std::make_unique<MockFetchTask>();
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(
      stream->OnRawControlMessage(GenericMessageToRawControlMessage(fetch)));
}

TEST_F(MoqtFetchResponseStreamTest, OnRawControlMessageUnexpectedType) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MoqtSubscribe subscribe;
  subscribe.request_id = kRequestId;
  subscribe.full_track_name = kTrackName;
  EXPECT_THAT(
      stream->OnRawControlMessage(GenericMessageToRawControlMessage(subscribe)),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(MoqtFetchResponseStreamTest, ReceiveJoiningFetchWithoutCallback) {
  std::unique_ptr<MoqtFetchResponseStream> stream =
      CreateAndBindStream(/*has_subscription_callback=*/false);
  MoqtRequestError expected_error = {RequestErrorCode::kInternalError,
                                     std::nullopt, "Internal error"};
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_error), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = JoiningFetchRelative(10, 1);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
}

TEST_F(MoqtFetchResponseStreamTest, ReceiveJoiningFetchSubscriptionNotFound) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  EXPECT_CALL(get_subscription_callback_, Call(10)).WillOnce(Return(nullptr));
  MoqtRequestError expected_error = {RequestErrorCode::kInvalidJoiningRequestId,
                                     std::nullopt,
                                     "Joining Fetch for non-existent request"};
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_error), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = JoiningFetchRelative(10, 1);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
}

TEST_F(MoqtFetchResponseStreamTest, DetachResetsDataStream) {
  std::unique_ptr<MoqtFetchResponseStream> stream = CreateAndBindStream();
  MockFetchTask* task_ptr = nullptr;
  EXPECT_CALL(mock_publisher_, GetTrack(kTrackName))
      .WillOnce(Return(track_publisher_));
  EXPECT_CALL(*track_publisher_,
              StandaloneFetch(kStart, kEnd, MoqtDeliveryOrder::kAscending, _))
      .WillOnce([&](Location, Location, MoqtDeliveryOrder,
                    FetchResponseCallback callback) {
        FetchOkData ok_data(true, kEnd);
        auto task = std::make_unique<MockFetchTask>();
        std::move(callback)(ok_data);
        task_ptr = task.get();
        return task;
      });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchOk), _))
      .WillOnce(Return(absl::OkStatus()));

  MoqtFetch fetch;
  fetch.request_id = kRequestId;
  fetch.fetch = StandaloneFetch(kTrackName, kStart, kEnd);
  QUICHE_EXPECT_OK(stream->OnControlMessage(fetch));
  ASSERT_NE(task_ptr, nullptr);

  webtransport::test::MockStream mock_data_stream;
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_data_stream, CanWrite).WillRepeatedly(Return(false));
  EXPECT_CALL(mock_data_stream, GetStreamId).WillRepeatedly(Return(10));
  EXPECT_CALL(mock_data_stream, SetPriority).Times(testing::AtLeast(1));
  EXPECT_CALL(mock_data_stream, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });

  stream->OnDataStreamOpen(&mock_data_stream, &trace_recorder_);

  EXPECT_CALL(mock_data_stream, ResetWithUserCode(kResetCodeCancelled));
  stream = nullptr;  // Destroys stream, triggering Detach().
}

}  // namespace
}  // namespace moqt::test
