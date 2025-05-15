// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <queue>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_session_peer.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

namespace {

using ::quic::test::MemSliceFromString;
using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;
using ::testing::StrictMock;

constexpr webtransport::StreamId kIncomingUniStreamId = 15;
constexpr webtransport::StreamId kOutgoingUniStreamId = 14;

FullTrackName kDefaultTrackName() { return FullTrackName("foo", "bar"); }

MoqtSubscribe DefaultSubscribe() {
  MoqtSubscribe subscribe = {
      /*request_id=*/1,
      /*track_alias=*/2,
      kDefaultTrackName(),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*forward=*/true,
      /*filter_type=*/MoqtFilterType::kAbsoluteStart,
      /*start=*/Location(0, 0),
      /*end_group=*/std::nullopt,
      /*parameters=*/VersionSpecificParameters(),
  };
  return subscribe;
}

MoqtFetch DefaultFetch() {
  MoqtFetch fetch = {
      /*fetch_id=*/1,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*joining_fetch=*/std::nullopt,
      kDefaultTrackName(),
      /*start=*/Location(0, 0),
      /*end_group=*/1,
      /*end_object=*/std::nullopt,
      /*parameters=*/VersionSpecificParameters(),
  };
  return fetch;
}

// TODO(martinduke): Eliminate MoqtSessionPeer::AddSubscription, which allows
// this to be removed as well.
static std::shared_ptr<MockTrackPublisher> SetupPublisher(
    FullTrackName track_name, MoqtForwardingPreference forwarding_preference,
    Location largest_sequence) {
  auto publisher = std::make_shared<MockTrackPublisher>(std::move(track_name));
  ON_CALL(*publisher, GetTrackStatus())
      .WillByDefault(Return(MoqtTrackStatusCode::kInProgress));
  ON_CALL(*publisher, GetForwardingPreference())
      .WillByDefault(Return(forwarding_preference));
  ON_CALL(*publisher, GetLargestLocation())
      .WillByDefault(Return(largest_sequence));
  return publisher;
}

}  // namespace

class MoqtSessionTest : public quic::test::QuicTest {
 public:
  MoqtSessionTest()
      : session_(&mock_session_,
                 MoqtSessionParameters(quic::Perspective::IS_CLIENT, ""),
                 std::make_unique<quic::test::TestAlarmFactory>(),
                 session_callbacks_.AsSessionCallbacks()) {
    session_.set_publisher(&publisher_);
    MoqtSessionPeer::set_peer_max_request_id(&session_,
                                             kDefaultInitialMaxRequestId);
    ON_CALL(mock_session_, GetStreamById).WillByDefault(Return(&mock_stream_));
  }
  ~MoqtSessionTest() {
    EXPECT_CALL(session_callbacks_.session_deleted_callback, Call());
  }

  MockTrackPublisher* CreateTrackPublisher() {
    auto publisher = std::make_shared<MockTrackPublisher>(kDefaultTrackName());
    publisher_.Add(publisher);
    ON_CALL(*publisher, GetTrackStatus())
        .WillByDefault(Return(MoqtTrackStatusCode::kNotYetBegun));
    ON_CALL(*publisher, GetForwardingPreference())
        .WillByDefault(Return(MoqtForwardingPreference::kSubgroup));
    ON_CALL(*publisher, GetDeliveryOrder)
        .WillByDefault(Return(MoqtDeliveryOrder::kAscending));
    return publisher.get();
  }

  void SetLargestId(MockTrackPublisher* publisher, Location largest_id) {
    ON_CALL(*publisher, GetTrackStatus())
        .WillByDefault(Return(MoqtTrackStatusCode::kInProgress));
    ON_CALL(*publisher, GetLargestLocation()).WillByDefault(Return(largest_id));
  }

  // The publisher receives SUBSCRIBE and synchronously announces it will
  // publish objects.
  MoqtObjectListener* ReceiveSubscribeSynchronousOk(
      MockTrackPublisher* publisher, MoqtSubscribe& subscribe,
      MoqtControlParserVisitor* control_parser) {
    MoqtObjectListener* listener_ptr = nullptr;
    EXPECT_CALL(*publisher, AddObjectListener)
        .WillOnce([&](MoqtObjectListener* listener) {
          listener_ptr = listener;
          listener->OnSubscribeAccepted();
        });
    absl::StatusOr<MoqtTrackStatusCode> track_status =
        publisher->GetTrackStatus();
    if (!track_status.ok()) {
      return nullptr;
    }
    MoqtSubscribeOk expected_ok = {
        /*request_id=*/subscribe.request_id,
        /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
        /*group_order=*/MoqtDeliveryOrder::kAscending,
        (*track_status == MoqtTrackStatusCode::kInProgress)
            ? std::make_optional(publisher->GetLargestLocation())
            : std::optional<Location>(),
        /*parameters=*/VersionSpecificParameters(),
    };
    EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
    control_parser->OnSubscribeMessage(subscribe);
    return listener_ptr;
  }

  // If visitor == nullptr, it's the first object in the stream, and will be
  // assigned to the visitor the session creates.
  // TODO(martinduke): Support delivering object payload.
  void DeliverObject(MoqtObject& object, bool fin,
                     webtransport::test::MockSession& session,
                     webtransport::test::MockStream* stream,
                     std::unique_ptr<webtransport::StreamVisitor>& visitor,
                     MockSubscribeRemoteTrackVisitor* track_visitor) {
    MoqtFramer framer(quiche::SimpleBufferAllocator::Get(), true);
    quiche::QuicheBuffer buffer = framer.SerializeObjectHeader(
        object, MoqtDataStreamType::kStreamHeaderSubgroup, visitor == nullptr);
    size_t data_read = 0;
    if (visitor == nullptr) {  // It's the first object in the stream
      EXPECT_CALL(session, AcceptIncomingUnidirectionalStream())
          .WillOnce(Return(stream))
          .WillOnce(Return(nullptr));
      EXPECT_CALL(*stream, SetVisitor(_))
          .WillOnce(Invoke(
              [&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
                visitor = std::move(new_visitor);
              }));
      EXPECT_CALL(*stream, visitor()).WillRepeatedly(Invoke([&]() {
        return visitor.get();
      }));
    }
    EXPECT_CALL(*stream, PeekNextReadableRegion()).WillRepeatedly(Invoke([&]() {
      return quiche::ReadStream::PeekResult(
          absl::string_view(buffer.data() + data_read,
                            buffer.size() - data_read),
          fin && data_read == buffer.size(), fin);
    }));
    EXPECT_CALL(*stream, ReadableBytes()).WillRepeatedly(Invoke([&]() {
      return buffer.size() - data_read;
    }));
    EXPECT_CALL(*stream, Read(testing::An<absl::Span<char>>()))
        .WillRepeatedly(Invoke([&](absl::Span<char> bytes_to_read) {
          size_t read_size =
              std::min(bytes_to_read.size(), buffer.size() - data_read);
          memcpy(bytes_to_read.data(), buffer.data() + data_read, read_size);
          data_read += read_size;
          return quiche::ReadStream::ReadResult(
              read_size, fin && data_read == buffer.size());
        }));
    EXPECT_CALL(*stream, SkipBytes(_)).WillRepeatedly(Invoke([&](size_t bytes) {
      data_read += bytes;
      return fin && data_read == buffer.size();
    }));
    EXPECT_CALL(*track_visitor, OnObjectFragment).Times(1);
    if (visitor == nullptr) {
      session_.OnIncomingUnidirectionalStreamAvailable();
    } else {
      visitor->OnCanRead();
    }
  }

  webtransport::test::MockStream mock_stream_;
  MockSessionCallbacks session_callbacks_;
  webtransport::test::MockSession mock_session_;
  MoqtSession session_;
  MoqtKnownTrackPublisher publisher_;
};

TEST_F(MoqtSessionTest, Queries) {
  EXPECT_EQ(session_.perspective(), quic::Perspective::IS_CLIENT);
}

// Verify the session sends CLIENT_SETUP on the control stream.
TEST_F(MoqtSessionTest, OnSessionReady) {
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillOnce(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] { return visitor.get(); });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kClientSetup), _));
  session_.OnSessionReady();

  // Receive SERVER_SETUP
  MoqtControlParserVisitor* stream_input =
      MoqtSessionPeer::FetchParserVisitorFromWebtransportStreamVisitor(
          &session_, visitor.get());
  // Handle the server setup
  MoqtServerSetup setup = {
      kDefaultMoqtVersion,
  };
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnServerSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnClientSetup) {
  MoqtSession server_session(
      &mock_session_, MoqtSessionParameters(quic::Perspective::IS_SERVER),
      std::make_unique<quic::test::TestAlarmFactory>(),
      session_callbacks_.AsSessionCallbacks());
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream_);
  MoqtClientSetup setup = {
      /*supported_versions=*/{kDefaultMoqtVersion},
      MoqtSessionParameters(quic::Perspective::IS_CLIENT),
  };
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kServerSetup), _));
  EXPECT_CALL(mock_stream_, GetStreamId()).WillOnce(Return(0));
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnClientSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnSessionClosed) {
  bool reported_error = false;
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = true;
        EXPECT_EQ(error_message, "foo");
      });
  session_.OnSessionClosed(webtransport::SessionErrorCode(1), "foo");
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, OnIncomingBidirectionalStream) {
  ::testing::InSequence seq;
  StrictMock<webtransport::test::MockStreamVisitor> mock_stream_visitor;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream_, visitor()).WillOnce(Return(&mock_stream_visitor));
  EXPECT_CALL(mock_stream_visitor, OnCanRead()).Times(1);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(nullptr));
  session_.OnIncomingBidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, OnIncomingUnidirectionalStream) {
  ::testing::InSequence seq;
  StrictMock<webtransport::test::MockStreamVisitor> mock_stream_visitor;
  EXPECT_CALL(mock_session_, AcceptIncomingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream_, visitor()).WillOnce(Return(&mock_stream_visitor));
  EXPECT_CALL(mock_stream_visitor, OnCanRead()).Times(1);
  EXPECT_CALL(mock_session_, AcceptIncomingUnidirectionalStream())
      .WillOnce(Return(nullptr));
  session_.OnIncomingUnidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, Error) {
  bool reported_error = false;
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation), "foo"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "foo");
      });
  session_.Error(MoqtError::kProtocolViolation, "foo");
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, AddLocalTrack) {
  MoqtSubscribe request = DefaultSubscribe();
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  // Request for track returns SUBSCRIBE_ERROR.
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeError), _));
  stream_input->OnSubscribeMessage(request);

  // Add the track. Now Subscribe should succeed.
  MockTrackPublisher* track = CreateTrackPublisher();
  std::make_shared<MockTrackPublisher>(request.full_track_name);
  request.request_id += 2;
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, AnnounceWithOkAndCancel) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kAnnounce), _));
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction(),
                    VersionSpecificParameters());

  MoqtAnnounceOk ok = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        EXPECT_FALSE(error.has_value());
      });
  stream_input->OnAnnounceOkMessage(ok);

  MoqtAnnounceCancel cancel = {
      /*track_namespace=*/FullTrackName{"foo"},
      /*error_code=*/RequestErrorCode::kInternalError,
      /*reason_phrase=*/"Test error",
  };
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, RequestErrorCode::kInternalError);
        EXPECT_EQ(error->reason_phrase, "Test error");
      });
  stream_input->OnAnnounceCancelMessage(cancel);
  // State is gone.
  EXPECT_FALSE(session_.Unannounce(FullTrackName{"foo"}));
}

TEST_F(MoqtSessionTest, AnnounceWithOkAndUnannounce) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kAnnounce), _));
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction(),
                    VersionSpecificParameters());

  MoqtAnnounceOk ok = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        EXPECT_FALSE(error.has_value());
      });
  stream_input->OnAnnounceOkMessage(ok);

  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kUnannounce), _));
  session_.Unannounce(FullTrackName{"foo"});
  // State is gone.
  EXPECT_FALSE(session_.Unannounce(FullTrackName{"foo"}));
}

TEST_F(MoqtSessionTest, AnnounceWithError) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kAnnounce), _));
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction(),
                    VersionSpecificParameters());

  MoqtAnnounceError error = {
      /*track_namespace=*/FullTrackName{"foo"},
      /*error_code=*/RequestErrorCode::kInternalError,
      /*reason_phrase=*/"Test error",
  };
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, RequestErrorCode::kInternalError);
        EXPECT_EQ(error->reason_phrase, "Test error");
      });
  stream_input->OnAnnounceErrorMessage(error);
  // State is gone.
  EXPECT_FALSE(session_.Unannounce(FullTrackName{"foo"}));
}

TEST_F(MoqtSessionTest, AsynchronousSubscribeReturnsOk) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSubscribe request = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtObjectListener* listener;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce(
          [&](MoqtObjectListener* listener_ptr) { listener = listener_ptr; });
  stream_input->OnSubscribeMessage(request);

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribeOk), _));
  listener->OnSubscribeAccepted();
  EXPECT_NE(MoqtSessionPeer::GetSubscription(&session_, 1), nullptr);
}

TEST_F(MoqtSessionTest, AsynchronousSubscribeReturnsError) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSubscribe request = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtObjectListener* listener;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce(
          [&](MoqtObjectListener* listener_ptr) { listener = listener_ptr; });
  stream_input->OnSubscribeMessage(request);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeError), _));
  listener->OnSubscribeRejected(
      MoqtSubscribeErrorReason(RequestErrorCode::kInternalError, "Test error"),
      request.track_alias);
  EXPECT_EQ(MoqtSessionPeer::GetSubscription(&session_, 1), nullptr);
}

TEST_F(MoqtSessionTest, SubscribeForPast) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(10, 20));
  MoqtSubscribe request = DefaultSubscribe();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, SubscribeDoNotForward) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  request.forward = false;
  request.filter_type = MoqtFilterType::kLatestObject;
  EXPECT_CALL(*track, GetTrackStatus)
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
  // forward=false, so incoming objects are ignored.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  listener->OnNewObjectAvailable(Location(0, 0));
}

TEST_F(MoqtSessionTest, SubscribeAbsoluteStartNoDataYet) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  request.start = Location(1, 0);
  EXPECT_CALL(*track, GetTrackStatus)
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
  // Window was not set to (0, 0) by SUBSCRIBE acceptance.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  listener->OnNewObjectAvailable(Location(0, 0));
}

TEST_F(MoqtSessionTest, SubscribeNextGroup) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  request.filter_type = MoqtFilterType::kNextGroupStart;
  SetLargestId(track, Location(10, 20));
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
  // Later objects in group 10 ignored.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  listener->OnNewObjectAvailable(Location(10, 21));
  // Group 11 is sent.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  listener->OnNewObjectAvailable(Location(11, 0));
}

TEST_F(MoqtSessionTest, TwoSubscribesForTrack) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());

  request.request_id = 3;
  request.start = Location(12, 0);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Duplicate subscribe for track"))
      .Times(1);
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, UnsubscribeAllowsSecondSubscribe) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());

  // Peer unsubscribes.
  MoqtUnsubscribe unsubscribe = {
      /*request_id=*/1,
  };
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_EQ(MoqtSessionPeer::GetSubscription(&session_, 1), nullptr);

  // Subscribe again, succeeds.
  request.request_id = 3;
  request.start = Location(12, 0);
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, RequestIdTooHigh) {
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = DefaultSubscribe();
  request.request_id = kDefaultInitialMaxRequestId + 1;

  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kTooManyRequests),
                           "Received request with too large ID"));
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, RequestIdWrongLsb) {
  // TODO(martinduke): Implement this test.
}

TEST_F(MoqtSessionTest, SubscribeIdNotIncreasing) {
  MoqtSubscribe request = DefaultSubscribe();
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  // Request for track returns SUBSCRIBE_ERROR.
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeError), _));
  stream_input->OnSubscribeMessage(request);

  // Second request is a protocol violation.
  ++request.track_alias;
  request.full_track_name = FullTrackName({"dead", "beef"});
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kInvalidRequestId),
                           "Request ID not monotonically increasing"));
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, TooManySubscribes) {
  MoqtSessionPeer::set_next_request_id(&session_,
                                       kDefaultInitialMaxRequestId - 1);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                              &remote_track_visitor,
                                              VersionSpecificParameters()));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestsBlocked), _))
      .Times(1);
  EXPECT_FALSE(session_.SubscribeCurrentObject(FullTrackName("foo2", "bar2"),
                                               &remote_track_visitor,
                                               VersionSpecificParameters()));
  // Second time does not send requests_blocked.
  EXPECT_FALSE(session_.SubscribeCurrentObject(FullTrackName("foo2", "bar2"),
                                               &remote_track_visitor,
                                               VersionSpecificParameters()));
}

TEST_F(MoqtSessionTest, SubscribeDuplicateTrackName) {
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                              &remote_track_visitor,
                                              VersionSpecificParameters()));
  EXPECT_FALSE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                               &remote_track_visitor,
                                               VersionSpecificParameters()));
}

TEST_F(MoqtSessionTest, SubscribeWithOk) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                  &remote_track_visitor,
                                  VersionSpecificParameters());

  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  EXPECT_CALL(remote_track_visitor, OnReply(_, _, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<Location> /*largest_location*/,
                    std::optional<absl::string_view> error_message) {
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_FALSE(error_message.has_value());
      });
  stream_input->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, SubscribeNextGroupWithOk) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  MoqtSubscribe subscribe = {
      /*request_id=*/0,
      /*track_alias=*/0,
      FullTrackName("foo", "bar"),
      kDefaultSubscriberPriority,
      /*group_order=*/std::nullopt,
      /*forward=*/true,
      MoqtFilterType::kNextGroupStart,
      std::nullopt,
      std::nullopt,
      VersionSpecificParameters(),
  };
  subscribe.filter_type = MoqtFilterType::kNextGroupStart;
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(subscribe), _));
  session_.SubscribeNextGroup(FullTrackName("foo", "bar"),
                              &remote_track_visitor,
                              VersionSpecificParameters());

  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  EXPECT_CALL(remote_track_visitor, OnReply(_, _, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<Location> /*largest_location*/,
                    std::optional<absl::string_view> error_message) {
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_FALSE(error_message.has_value());
      });
  stream_input->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, OutgoingSubscribeUpdate) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById)
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  session_.SubscribeAbsolute(FullTrackName("foo", "bar"), 1, 0, 10,
                             &remote_track_visitor,
                             VersionSpecificParameters());
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  EXPECT_CALL(remote_track_visitor, OnReply);
  stream_input->OnSubscribeOkMessage(ok);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeUpdate), _));
  EXPECT_TRUE(session_.SubscribeUpdate(
      FullTrackName("foo", "bar"), Location(2, 1), 9, std::nullopt,
      std::nullopt, VersionSpecificParameters()));
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  EXPECT_FALSE(track->InWindow(Location(2, 0)));
  EXPECT_TRUE(track->InWindow(Location(2, 1)));
  EXPECT_TRUE(track->InWindow(Location(9, UINT64_MAX)));
  EXPECT_FALSE(track->InWindow(Location(10, 0)));
}

TEST_F(MoqtSessionTest, OutgoingSubscribeUpdateInvalid) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById)
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  session_.SubscribeAbsolute(FullTrackName("foo", "bar"), 1, 0, 10,
                             &remote_track_visitor,
                             VersionSpecificParameters());
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  EXPECT_CALL(remote_track_visitor, OnReply);
  stream_input->OnSubscribeOkMessage(ok);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeUpdate), _))
      .Times(0);
  EXPECT_FALSE(session_.SubscribeUpdate(
      FullTrackName("foo", "bar"), Location(0, 0), 10, std::nullopt,
      std::nullopt, VersionSpecificParameters()));
  EXPECT_FALSE(session_.SubscribeUpdate(
      FullTrackName("foo", "bar"), Location(1, 0), 11, std::nullopt,
      std::nullopt, VersionSpecificParameters()));
  EXPECT_FALSE(session_.SubscribeUpdate(
      FullTrackName("foo", "bar"), Location(7, 0), 6, std::nullopt,
      std::nullopt, VersionSpecificParameters()));
}

TEST_F(MoqtSessionTest, MaxRequestIdChangesResponse) {
  MoqtSessionPeer::set_next_request_id(&session_, kDefaultInitialMaxRequestId);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestsBlocked), _));
  EXPECT_FALSE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                               &remote_track_visitor,
                                               VersionSpecificParameters()));
  MoqtMaxRequestId max_request_id = {
      /*max_request_id=*/kDefaultInitialMaxRequestId + 1,
  };
  stream_input->OnMaxRequestIdMessage(max_request_id);

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                              &remote_track_visitor,
                                              VersionSpecificParameters()));
}

TEST_F(MoqtSessionTest, LowerMaxRequestIdIsAnError) {
  MoqtMaxRequestId max_request_id = {
      /*max_request_id=*/kDefaultInitialMaxRequestId - 1,
  };
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "MAX_REQUEST_ID has lower value than previous"))
      .Times(1);
  stream_input->OnMaxRequestIdMessage(max_request_id);
}

TEST_F(MoqtSessionTest, GrantMoreRequests) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kMaxRequestId), _));
  session_.GrantMoreRequests(1);
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = DefaultSubscribe();
  MoqtSessionPeer::set_next_incoming_request_id(
      &session_, kDefaultInitialMaxRequestId + 1);
  request.request_id = kDefaultInitialMaxRequestId + 1;
  MockTrackPublisher* track = CreateTrackPublisher();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, SubscribeWithError) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                  &remote_track_visitor,
                                  VersionSpecificParameters());

  MoqtSubscribeError error = {
      /*request_id=*/0,
      /*error_code=*/RequestErrorCode::kInvalidRange,
      /*reason_phrase=*/"deadbeef",
      /*track_alias=*/2,
  };
  EXPECT_CALL(remote_track_visitor, OnReply(_, _, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<Location> /*largest_id*/,
                    std::optional<absl::string_view> error_message) {
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_EQ(*error_message, "deadbeef");
      });
  stream_input->OnSubscribeErrorMessage(error);
}

TEST_F(MoqtSessionTest, Unsubscribe) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     &remote_track_visitor);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kUnsubscribe), _));
  EXPECT_NE(MoqtSessionPeer::remote_track(&session_, 2), nullptr);
  session_.Unsubscribe(FullTrackName("foo", "bar"));
  // State is destroyed.
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 2), nullptr);
}

TEST_F(MoqtSessionTest, ReplyToAnnounceWithOkThenUnannounce) {
  FullTrackName track_namespace{"foo"};
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  auto parameters = std::make_optional<VersionSpecificParameters>(
      AuthTokenType::kOutOfBand, "foo");
  MoqtAnnounce announce = {
      track_namespace,
      *parameters,
  };
  EXPECT_CALL(session_callbacks_.incoming_announce_callback,
              Call(track_namespace, parameters))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(
      mock_stream_,
      Writev(SerializedControlMessage(MoqtAnnounceOk{track_namespace}), _));
  stream_input->OnAnnounceMessage(announce);
  MoqtUnannounce unannounce = {
      track_namespace,
  };
  EXPECT_CALL(session_callbacks_.incoming_announce_callback,
              Call(track_namespace, std::optional<VersionSpecificParameters>()))
      .WillOnce(Return(std::nullopt));
  stream_input->OnUnannounceMessage(unannounce);
}

TEST_F(MoqtSessionTest, ReplyToAnnounceWithOkThenAnnounceCancel) {
  FullTrackName track_namespace{"foo"};

  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  auto parameters = std::make_optional<VersionSpecificParameters>(
      AuthTokenType::kOutOfBand, "foo");
  MoqtAnnounce announce = {
      track_namespace,
      *parameters,
  };
  EXPECT_CALL(session_callbacks_.incoming_announce_callback,
              Call(track_namespace, parameters))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(
      mock_stream_,
      Writev(SerializedControlMessage(MoqtAnnounceOk{track_namespace}), _));
  stream_input->OnAnnounceMessage(announce);
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(MoqtAnnounceCancel{
                         track_namespace, RequestErrorCode::kInternalError,
                         "deadbeef"}),
                     _));
  session_.CancelAnnounce(track_namespace, RequestErrorCode::kInternalError,
                          "deadbeef");
}

TEST_F(MoqtSessionTest, ReplyToAnnounceWithError) {
  FullTrackName track_namespace{"foo"};

  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  auto parameters = std::make_optional<VersionSpecificParameters>(
      AuthTokenType::kOutOfBand, "foo");
  MoqtAnnounce announce = {
      track_namespace,
      *parameters,
  };
  MoqtAnnounceErrorReason error = {
      RequestErrorCode::kNotSupported,
      "deadbeef",
  };
  EXPECT_CALL(session_callbacks_.incoming_announce_callback,
              Call(track_namespace, parameters))
      .WillOnce(Return(error));
  EXPECT_CALL(
      mock_stream_,
      Writev(SerializedControlMessage(MoqtAnnounceError{
                 track_namespace, error.error_code, error.reason_phrase}),
             _));
  stream_input->OnAnnounceMessage(announce);
}

TEST_F(MoqtSessionTest, SubscribeAnnouncesLifeCycle) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  FullTrackName track_namespace("foo", "bar");
  track_namespace.NameToNamespace();
  bool got_callback = false;
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeAnnounces), _));
  session_.SubscribeAnnounces(
      track_namespace,
      [&](const FullTrackName& ftn, std::optional<RequestErrorCode> error,
          absl::string_view reason) {
        got_callback = true;
        EXPECT_EQ(track_namespace, ftn);
        EXPECT_FALSE(error.has_value());
        EXPECT_EQ(reason, "");
      },
      VersionSpecificParameters());
  MoqtSubscribeAnnouncesOk ok = {
      /*track_namespace=*/track_namespace,
  };
  stream_input->OnSubscribeAnnouncesOkMessage(ok);
  EXPECT_TRUE(got_callback);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kUnsubscribeAnnounces), _));
  EXPECT_TRUE(session_.UnsubscribeAnnounces(track_namespace));
  EXPECT_FALSE(session_.UnsubscribeAnnounces(track_namespace));
}

TEST_F(MoqtSessionTest, SubscribeAnnouncesError) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  FullTrackName track_namespace("foo", "bar");
  track_namespace.NameToNamespace();
  bool got_callback = false;
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeAnnounces), _));
  session_.SubscribeAnnounces(
      track_namespace,
      [&](const FullTrackName& ftn, std::optional<RequestErrorCode> error,
          absl::string_view reason) {
        got_callback = true;
        EXPECT_EQ(track_namespace, ftn);
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(*error, RequestErrorCode::kInvalidRange);
        EXPECT_EQ(reason, "deadbeef");
      },
      VersionSpecificParameters());
  MoqtSubscribeAnnouncesError error = {
      /*track_namespace=*/track_namespace,
      /*error_code=*/RequestErrorCode::kInvalidRange,
      /*reason_phrase=*/"deadbeef",
  };
  stream_input->OnSubscribeAnnouncesErrorMessage(error);
  EXPECT_TRUE(got_callback);
  // Entry is immediately gone.
  EXPECT_FALSE(session_.UnsubscribeAnnounces(track_namespace));
}

TEST_F(MoqtSessionTest, IncomingObject) {
  MockSubscribeRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, IncomingPartialObject) {
  MockSubscribeRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/16,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, IncomingPartialObjectNoBuffer) {
  MoqtSessionParameters parameters(quic::Perspective::IS_CLIENT);
  parameters.deliver_partial_objects = true;
  MoqtSession session(&mock_session_, parameters,
                      std::make_unique<quic::test::TestAlarmFactory>(),
                      session_callbacks_.AsSessionCallbacks());
  MockSubscribeRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session, DefaultSubscribe(), &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/16,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _)).Times(2);
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeOk) {
  MockSubscribeRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, Location sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*request_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_location=*/std::nullopt,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(visitor_, OnReply(_, _, _)).Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeError) {
  MockSubscribeRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, Location sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_ERROR arrives
  MoqtSubscribeError subscribe_error = {
      /*request_id=*/1,
      /*error_code=*/RequestErrorCode::kRetryTrackAlias,
      /*reason_phrase=*/"foo",
      /*track_alias =*/3,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                   "Received SUBSCRIBE_ERROR after SUBSCRIBE_OK or objects"))
      .Times(1);
  control_stream->OnSubscribeErrorMessage(subscribe_error);
}

TEST_F(MoqtSessionTest, SubscribeErrorWithTrackAlias) {
  MockSubscribeRemoteTrackVisitor visitor;
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor);

  // SUBSCRIBE_ERROR arrives
  MoqtSubscribeError subscribe_error = {
      /*request_id=*/1,
      /*error_code=*/RequestErrorCode::kRetryTrackAlias,
      /*reason_phrase=*/"foo",
      /*track_alias =*/3,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _))
      .Times(1);
  control_stream->OnSubscribeErrorMessage(subscribe_error);
}

TEST_F(MoqtSessionTest, SubscribeErrorWithBadTrackAlias) {
  MockSubscribeRemoteTrackVisitor visitor;
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor);

  // SUBSCRIBE_ERROR arrives
  MoqtSubscribeError subscribe_error = {
      /*request_id=*/1,
      /*error_code=*/RequestErrorCode::kRetryTrackAlias,
      /*reason_phrase=*/"foo",
      /*track_alias =*/2,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Provided track alias already in use"))
      .Times(1);
  control_stream->OnSubscribeErrorMessage(subscribe_error);
}

TEST_F(MoqtSessionTest, CreateOutgoingDataStreamAndSend) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));

  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x00, 0x7f};
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin |= options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([&] {
    return PublishedObject{Location(5, 0),
                           MoqtObjectStatus::kNormal,
                           127,
                           MemSliceFromString("deadbeef"),
                           MoqtSessionPeer::Now(&session_),
                           false};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));
  EXPECT_TRUE(correct_message);
  EXPECT_FALSE(fin);
  EXPECT_EQ(MoqtSessionPeer::LargestSentForSubscription(&session_, 0),
            Location(5, 0));
}

TEST_F(MoqtSessionTest, FinDataStreamFromCache) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));

  // Verify first five message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x00, 0x7f};
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin = options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([&] {
    return PublishedObject{Location(5, 0),
                           MoqtObjectStatus::kNormal,
                           127,
                           MemSliceFromString("deadbeef"),
                           MoqtSessionPeer::Now(&session_),
                           true};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));
  EXPECT_TRUE(correct_message);
  EXPECT_TRUE(fin);
}

TEST_F(MoqtSessionTest, GroupAbandoned) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));

  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x00, 0x7f};
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin |= options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([&] {
    return PublishedObject{Location(5, 0),
                           MoqtObjectStatus::kNormal,
                           127,
                           MemSliceFromString("deadbeef"),
                           MoqtSessionPeer::Now(&session_),
                           true};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));
  EXPECT_TRUE(correct_message);
  EXPECT_TRUE(fin);

  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeTimedOut));
  subscription->OnGroupAbandoned(5);
}

TEST_F(MoqtSessionTest, LateFinDataStream) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillRepeatedly([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));

  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x00, 0x7f};
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin = options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([&] {
    return PublishedObject{Location(5, 0),
                           MoqtObjectStatus::kNormal,
                           127,
                           MemSliceFromString("deadbeef"),
                           MoqtSessionPeer::Now(&session_),
                           false};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));
  EXPECT_TRUE(correct_message);
  EXPECT_FALSE(fin);
  fin = false;
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        EXPECT_TRUE(data.empty());
        fin = options.send_fin();
        return absl::OkStatus();
      });
  subscription->OnNewFinAvailable(Location(5, 0));
}

TEST_F(MoqtSessionTest, SeparateFinForFutureObject) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillRepeatedly([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));

  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x7f, 0x00, 0x00};
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin = options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([&] {
    return PublishedObject{Location(5, 0),
                           MoqtObjectStatus::kNormal,
                           127,
                           MemSliceFromString("deadbeef"),
                           MoqtSessionPeer::Now(&session_),
                           false};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));
  EXPECT_FALSE(fin);
  // Try to deliver (5,1), but fail.
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return false; });
  EXPECT_CALL(*track, GetCachedObject(_)).Times(0);
  EXPECT_CALL(mock_stream_, Writev(_, _)).Times(0);
  subscription->OnNewObjectAvailable(Location(5, 1));
  // Notify that FIN arrived, but do nothing with it because (5, 1) isn't sent.
  EXPECT_CALL(mock_stream_, Writev(_, _)).Times(0);
  subscription->OnNewFinAvailable(Location(5, 1));

  // Reopen the window.
  correct_message = false;
  // object id, extensions, payload length, status.
  const std::string kExpectedMessage2 = {0x01, 0x00, 0x00, 0x03};
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return true; });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([&] {
    return PublishedObject{
        Location(5, 1),         MoqtObjectStatus::kEndOfGroup,   127,
        MemSliceFromString(""), MoqtSessionPeer::Now(&session_), true};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 2))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage2);
        fin = options.send_fin();
        return absl::OkStatus();
      });
  stream_visitor->OnCanWrite();
  EXPECT_TRUE(correct_message);
  EXPECT_TRUE(fin);
}

TEST_F(MoqtSessionTest, PublisherAbandonsSubgroup) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Deliver first object.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillRepeatedly([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));
  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x7f, 0x00, 0x00};
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin = options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([&] {
    return PublishedObject{Location(5, 0),
                           MoqtObjectStatus::kNormal,
                           127,
                           MemSliceFromString("deadbeef"),
                           MoqtSessionPeer::Now(&session_),
                           false};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));

  // Abandon the subgroup.
  EXPECT_CALL(mock_stream_, ResetWithUserCode(0x1)).Times(1);
  subscription->OnSubgroupAbandoned(Location(5, 0), 0x1);
}

// TODO: Test operation with multiple streams.

TEST_F(MoqtSessionTest, UnidirectionalStreamCannotBeOpened) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Queue the outgoing stream.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  subscription->OnNewObjectAvailable(Location(5, 0));

  // Unblock the session, and cause the queued stream to be sent.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([] {
    return PublishedObject{Location(5, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, QueuedStreamIsCleared) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Queue the outgoing stream.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(false));
  subscription->OnNewObjectAvailable(Location(5, 0, 0));
  subscription->OnNewObjectAvailable(Location(6, 0, 0));
  subscription->OnGroupAbandoned(5);

  // Unblock the session, and cause the queued stream to be sent. There should
  // be only one stream.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(true));
  bool fin = false;
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(Location(6, 0))).WillRepeatedly([] {
    return PublishedObject{Location(6, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(6, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, OutgoingStreamDisappears) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Set up an outgoing stream for a group.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_stream_, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor()).WillRepeatedly([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));

  EXPECT_CALL(mock_stream_, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(Location(5, 0))).WillRepeatedly([] {
    return PublishedObject{Location(5, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).WillOnce([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(Location(5, 0));

  // Now that the stream exists and is recorded within subscription, make it
  // disappear by returning nullptr.
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(nullptr));
  EXPECT_CALL(*track, GetCachedObject(Location(5, 1))).Times(0);
  subscription->OnNewObjectAvailable(Location(5, 1));
}

TEST_F(MoqtSessionTest, OneBidirectionalStreamClient) {
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillOnce(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, visitor()).WillOnce([&] { return visitor.get(); });
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kClientSetup), _));
  session_.OnSessionReady();

  // Peer tries to open a bidi stream.
  bool reported_error = false;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Bidirectional stream already open"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "Bidirectional stream already open");
      });
  session_.OnIncomingBidirectionalStreamAvailable();
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, OneBidirectionalStreamServer) {
  MoqtSession server_session(
      &mock_session_, MoqtSessionParameters(quic::Perspective::IS_SERVER),
      std::make_unique<quic::test::TestAlarmFactory>(),
      session_callbacks_.AsSessionCallbacks());
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream_);
  MoqtClientSetup setup = {
      /*supported_versions*/ {kDefaultMoqtVersion},
      MoqtSessionParameters(),
  };
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kServerSetup), _));
  EXPECT_CALL(mock_stream_, GetStreamId()).WillOnce(Return(0));
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnClientSetupMessage(setup);

  // Peer tries to open a bidi stream.
  bool reported_error = false;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Bidirectional stream already open"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "Bidirectional stream already open");
      });
  server_session.OnIncomingBidirectionalStreamAvailable();
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, ReceiveUnsubscribe) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(4, 2));
  MoqtSessionPeer::AddSubscription(&session_, track, 0, 1, 3, 4);
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtUnsubscribe unsubscribe = {
      /*request_id=*/0,
  };
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_EQ(MoqtSessionPeer::GetSubscription(&session_, 0), nullptr);
}

TEST_F(MoqtSessionTest, SendDatagram) {
  FullTrackName ftn("foo", "bar");
  std::shared_ptr<MockTrackPublisher> track_publisher =
      SetupPublisher(ftn, MoqtForwardingPreference::kDatagram, Location{4, 0});
  MoqtObjectListener* listener =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 0, 2, 5, 0);

  // Publish in window.
  bool correct_message = false;
  uint8_t kExpectedMessage[] = {
      0x01, 0x02, 0x05, 0x00, 0x80, 0x00, 0x08, 0x64,
      0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66,
  };
  EXPECT_CALL(mock_session_, SendOrQueueDatagram(_))
      .WillOnce([&](absl::string_view datagram) {
        if (datagram.size() == sizeof(kExpectedMessage)) {
          correct_message = (0 == memcmp(datagram.data(), kExpectedMessage,
                                         sizeof(kExpectedMessage)));
        }
        return webtransport::DatagramStatus(
            webtransport::DatagramStatusCode::kSuccess, "");
      });
  EXPECT_CALL(*track_publisher, GetCachedObject(Location{5, 0}))
      .WillRepeatedly([] {
        return PublishedObject{Location{5, 0}, MoqtObjectStatus::kNormal, 128,
                               MemSliceFromString("deadbeef")};
      });
  listener->OnNewObjectAvailable(Location(5, 0));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, ReceiveDatagram) {
  MockSubscribeRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/std::nullopt,
      /*payload_length=*/8,
  };
  char datagram[] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x08, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(visitor_,
              OnObjectFragment(ftn, Location{object.group_id, object.object_id},
                               object.publisher_priority, object.object_status,
                               payload, true))
      .Times(1);
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, DataStreamTypeMismatch) {
  MockSubscribeRemoteTrackVisitor visitor_;
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(), &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  char datagram[] = {0x01, 0x02, 0x00, 0x10, 0x00, 0x00, 0x08, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received DATAGRAM for non-datagram track"))
      .Times(1);
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, StreamObjectOutOfWindow) {
  MockSubscribeRemoteTrackVisitor visitor_;
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = DefaultSubscribe();
  subscribe.start = Location(1, 0);
  MoqtSessionPeer::CreateRemoteTrack(&session_, subscribe, &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_, MoqtDataStreamType::kStreamHeaderSubgroup);
  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _)).Times(0);
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, DatagramOutOfWindow) {
  MockSubscribeRemoteTrackVisitor visitor_;
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = DefaultSubscribe();
  subscribe.start = Location(1, 0);
  MoqtSessionPeer::CreateRemoteTrack(&session_, subscribe, &visitor_);
  char datagram[] = {0x01, 0x02, 0x00, 0x00, 0x80, 0x00, 0x08, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _)).Times(0);
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, QueuedStreamsOpenedInOrder) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(0, 0));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 14, 0, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription->OnNewObjectAvailable(Location(1, 0));
  subscription->OnNewObjectAvailable(Location(0, 0));
  subscription->OnNewObjectAvailable(Location(2, 0));
  // These should be opened in the sequence (0, 0), (1, 0), (2, 0).
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  webtransport::test::MockStream mock_stream0, mock_stream1, mock_stream2;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream0))
      .WillOnce(Return(&mock_stream1))
      .WillOnce(Return(&mock_stream2));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor[3];
  EXPECT_CALL(mock_stream0, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor[0] = std::move(visitor);
      });
  EXPECT_CALL(mock_stream1, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor[1] = std::move(visitor);
      });
  EXPECT_CALL(mock_stream2, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor[2] = std::move(visitor);
      });
  EXPECT_CALL(mock_stream0, GetStreamId()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_stream1, GetStreamId()).WillRepeatedly(Return(1));
  EXPECT_CALL(mock_stream2, GetStreamId()).WillRepeatedly(Return(2));
  EXPECT_CALL(mock_stream0, visitor()).WillOnce([&]() {
    return stream_visitor[0].get();
  });
  EXPECT_CALL(mock_stream1, visitor()).WillOnce([&]() {
    return stream_visitor[1].get();
  });
  EXPECT_CALL(mock_stream2, visitor()).WillOnce([&]() {
    return stream_visitor[2].get();
  });
  EXPECT_CALL(*track, GetCachedObject(Location(0, 0)))
      .WillOnce(
          Return(PublishedObject{Location(0, 0), MoqtObjectStatus::kNormal, 127,
                                 MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(Location(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*track, GetCachedObject(Location(1, 0)))
      .WillOnce(
          Return(PublishedObject{Location(1, 0), MoqtObjectStatus::kNormal, 127,
                                 MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(Location(1, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*track, GetCachedObject(Location(2, 0)))
      .WillOnce(
          Return(PublishedObject{Location(2, 0), MoqtObjectStatus::kNormal, 127,
                                 MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(Location(2, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream0, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream1, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream2, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream0, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // The Group ID is the 3rd byte of the stream.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 0);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream1, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // The Group ID is the 3rd byte of the stream.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 1);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream2, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // The Group ID is the 3rd byte of the stream.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 2);
        return absl::OkStatus();
      });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, StreamQueuedForSubscriptionThatDoesntExist) {
  FullTrackName ftn("foo", "bar");
  auto track =
      SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup, Location(0, 0));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 14, 0, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription->OnNewObjectAvailable(Location(0, 0));

  // Delete the subscription, then grant stream credit.
  MoqtSessionPeer::DeleteSubscription(&session_, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream()).Times(0);
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, QueuedStreamPriorityChanged) {
  FullTrackName ftn1("foo", "bar");
  auto track1 =
      SetupPublisher(ftn1, MoqtForwardingPreference::kSubgroup, Location(0, 0));
  FullTrackName ftn2("dead", "beef");
  auto track2 =
      SetupPublisher(ftn2, MoqtForwardingPreference::kSubgroup, Location(0, 0));
  EXPECT_CALL(*track1, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  EXPECT_CALL(*track2, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription0 =
      MoqtSessionPeer::AddSubscription(&session_, track1, 0, 14, 0, 0);
  MoqtObjectListener* subscription1 =
      MoqtSessionPeer::AddSubscription(&session_, track2, 1, 15, 0, 0);
  MoqtSessionPeer::UpdateSubscriberPriority(&session_, 0, 1);
  MoqtSessionPeer::UpdateSubscriberPriority(&session_, 1, 2);

  // Two published objects will queue four streams.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false))
      .WillOnce(Return(false));
  EXPECT_CALL(*track1, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track2, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription0->OnNewObjectAvailable(Location(0, 0));
  subscription1->OnNewObjectAvailable(Location(0, 0));
  subscription0->OnNewObjectAvailable(Location(1, 0));
  subscription1->OnNewObjectAvailable(Location(1, 0));

  // Allow one stream to be opened. It will be group 0, subscription 0.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  webtransport::test::MockStream mock_stream0;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream0));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor0;
  EXPECT_CALL(mock_stream0, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor0 = std::move(visitor);
      });
  EXPECT_CALL(mock_stream0, GetStreamId()).WillRepeatedly(Return(0));
  EXPECT_CALL(mock_stream0, visitor()).WillOnce([&]() {
    return stream_visitor0.get();
  });
  EXPECT_CALL(*track1, GetCachedObject(Location(0, 0)))
      .WillOnce(
          Return(PublishedObject{Location(0, 0), MoqtObjectStatus::kNormal, 127,
                                 MemSliceFromString("foobar")}));
  EXPECT_CALL(*track1, GetCachedObject(Location(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream0, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream0, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // Check track alias is 14.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][1]), 14);
        // Check Group ID is 0
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 0);
        return absl::OkStatus();
      });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();

  // Raise the priority of subscription 1 and allow another stream. It will be
  // group 0, subscription 1.
  MoqtSessionPeer::UpdateSubscriberPriority(&session_, 1, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillRepeatedly(Return(false));
  webtransport::test::MockStream mock_stream1;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream1));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor1;
  EXPECT_CALL(mock_stream1, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor1 = std::move(visitor);
      });
  EXPECT_CALL(mock_stream1, GetStreamId()).WillRepeatedly(Return(1));
  EXPECT_CALL(mock_stream1, visitor()).WillOnce([&]() {
    return stream_visitor1.get();
  });
  EXPECT_CALL(*track2, GetCachedObject(Location(0, 0)))
      .WillOnce(
          Return(PublishedObject{Location(0, 0), MoqtObjectStatus::kNormal, 127,
                                 MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track2, GetCachedObject(Location(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream1, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream1, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        // Check track alias is 15.
        EXPECT_EQ(static_cast<const uint8_t>(data[0][1]), 15);
        // Check Group ID is 0
        EXPECT_EQ(static_cast<const uint8_t>(data[0][2]), 0);
        return absl::OkStatus();
      });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

// Helper functions to handle the many EXPECT_CALLs for FETCH processing and
// delivery.
namespace {
// Handles all the mock calls for the first object available for a FETCH.
void ExpectStreamOpen(
    webtransport::test::MockSession& session, MockFetchTask* fetch_task,
    webtransport::test::MockStream& data_stream,
    std::unique_ptr<webtransport::StreamVisitor>& stream_visitor) {
  EXPECT_CALL(session, CanOpenNextOutgoingUnidirectionalStream)
      .WillOnce(Return(true));
  EXPECT_CALL(session, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_stream));
  EXPECT_CALL(data_stream, SetVisitor)
      .WillOnce(
          Invoke([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
            stream_visitor = std::move(visitor);
          }));
  EXPECT_CALL(data_stream, SetPriority).Times(1);
}

// Sets expectations to send one object at the start of the stream, and then
// return a different status on the second GetNextObject call. |second_result|
// cannot be kSuccess.
void ExpectSendObject(MockFetchTask* fetch_task,
                      webtransport::test::MockStream& data_stream,
                      MoqtObjectStatus status, Location location,
                      absl::string_view payload,
                      MoqtFetchTask::GetNextObjectResult second_result) {
  // Nothing is sent for status = kObjectDoesNotExist. Do not use this function.
  QUICHE_DCHECK(status != MoqtObjectStatus::kObjectDoesNotExist);
  QUICHE_DCHECK(second_result != MoqtFetchTask::GetNextObjectResult::kSuccess);
  EXPECT_CALL(data_stream, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(*fetch_task, GetNextObject)
      .WillOnce(Invoke([=](PublishedObject& output) {
        output.sequence = location;
        output.status = status;
        output.publisher_priority = 128;
        output.payload = quiche::QuicheMemSlice::Copy(payload);
        output.fin_after_this = true;  // should be ignored.
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      }))
      .WillOnce(
          Invoke([=](PublishedObject& /*output*/) { return second_result; }));
  if (second_result == MoqtFetchTask::GetNextObjectResult::kEof) {
    EXPECT_CALL(data_stream, Writev)
        .WillOnce(Invoke([](absl::Span<const absl::string_view> data,
                            const quiche::StreamWriteOptions& options) {
          quic::QuicDataReader reader(data[0]);
          uint64_t type;
          EXPECT_TRUE(reader.ReadVarInt62(&type));
          EXPECT_EQ(type, static_cast<uint64_t>(
                              MoqtDataStreamType::kStreamHeaderFetch));
          EXPECT_FALSE(options.send_fin());  // fin_after_this is ignored.
          return absl::OkStatus();
        }))
        .WillOnce(Invoke([](absl::Span<const absl::string_view> data,
                            const quiche::StreamWriteOptions& options) {
          EXPECT_TRUE(data.empty());
          EXPECT_TRUE(options.send_fin());
          return absl::OkStatus();
        }));
    return;
  }
  EXPECT_CALL(data_stream, Writev)
      .WillOnce(Invoke([](absl::Span<const absl::string_view> data,
                          const quiche::StreamWriteOptions& options) {
        quic::QuicDataReader reader(data[0]);
        uint64_t type;
        EXPECT_TRUE(reader.ReadVarInt62(&type));
        EXPECT_EQ(type, static_cast<uint64_t>(
                            MoqtDataStreamType::kStreamHeaderFetch));
        EXPECT_FALSE(options.send_fin());  // fin_after_this is ignored.
        return absl::OkStatus();
      }));
  if (second_result == MoqtFetchTask::GetNextObjectResult::kError) {
    EXPECT_CALL(data_stream, ResetWithUserCode);
  }
}
}  // namespace

// All callbacks are called asynchronously.
TEST_F(MoqtSessionTest, ProcessFetchGetEverythingFromUpstream) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  // No callbacks are synchronous. MockFetchTask will store the callbacks.
  auto fetch_task_ptr = std::make_unique<MockFetchTask>();
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, Fetch).WillOnce(Return(std::move(fetch_task_ptr)));
  stream_input->OnFetchMessage(fetch);

  // Compose and send the FETCH_OK.
  MoqtFetchOk expected_ok;
  expected_ok.subscribe_id = fetch.fetch_id;
  expected_ok.group_order = MoqtDeliveryOrder::kAscending;
  expected_ok.largest_id = Location(1, 4);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
  fetch_task->CallFetchResponseCallback(expected_ok);
  // Data arrives.
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  fetch_task->CallObjectsAvailableCallback();
}

// All callbacks are called synchronously. All relevant data is cached (or this
// is the original publisher).
TEST_F(MoqtSessionTest, ProcessFetchWholeRangeIsPresent) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  MoqtFetchOk expected_ok;
  expected_ok.subscribe_id = fetch.fetch_id;
  expected_ok.group_order = MoqtDeliveryOrder::kAscending;
  expected_ok.largest_id = Location(1, 4);
  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(expected_ok, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, Fetch).WillOnce(Return(std::move(fetch_task_ptr)));
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  // Everything spins upon message receipt. FetchTask is generating the
  // necessary callbacks.
  stream_input->OnFetchMessage(fetch);
}

// The publisher has the first object locally, but has to go upstream to get
// the rest.
TEST_F(MoqtSessionTest, FetchReturnsObjectBeforeOk) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  // Object returns synchronously.
  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, Fetch).WillOnce(Return(std::move(fetch_task_ptr)));
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  stream_input->OnFetchMessage(fetch);

  MoqtFetchOk expected_ok;
  expected_ok.subscribe_id = fetch.fetch_id;
  expected_ok.group_order = MoqtDeliveryOrder::kAscending;
  expected_ok.largest_id = Location(1, 4);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
  fetch_task->CallFetchResponseCallback(expected_ok);
}

TEST_F(MoqtSessionTest, FetchReturnsObjectBeforeError) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, Fetch).WillOnce(Return(std::move(fetch_task_ptr)));
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  stream_input->OnFetchMessage(fetch);

  MoqtFetchError expected_error;
  expected_error.subscribe_id = fetch.fetch_id;
  expected_error.error_code = RequestErrorCode::kTrackDoesNotExist;
  expected_error.reason_phrase = "foo";
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_error), _));
  fetch_task->CallFetchResponseCallback(expected_error);
}

TEST_F(MoqtSessionTest, InvalidFetch) {
  // Update the state so that it expects ID > 0 next time.
  MoqtSessionPeer::ValidateRequestId(&session_, 1);
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  MoqtFetch fetch = DefaultFetch();
  fetch.fetch_id = 1;  // Too low.
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kInvalidRequestId),
                           "Request ID not monotonically increasing"))
      .Times(1);
  stream_input->OnFetchMessage(fetch);
}

TEST_F(MoqtSessionTest, FetchFails) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  auto fetch_task_ptr = std::make_unique<MockFetchTask>();
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, Fetch).WillOnce(Return(std::move(fetch_task_ptr)));
  EXPECT_CALL(*fetch_task, GetStatus())
      .WillRepeatedly(Return(absl::Status(absl::StatusCode::kInternal, "foo")));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchError), _));
  stream_input->OnFetchMessage(fetch);
}

TEST_F(MoqtSessionTest, FullFetchDeliveryWithFlowControl) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, Fetch).WillOnce(Return(std::move(fetch_task_ptr)));

  stream_input->OnFetchMessage(fetch);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  fetch_task->CallObjectsAvailableCallback();

  // Stream opens, but with no credit.
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  EXPECT_CALL(data_stream, CanWrite()).WillOnce(Return(false));
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
  // Object with FIN
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kEof);
  stream_visitor->OnCanWrite();
}

TEST_F(MoqtSessionTest, IncomingJoiningFetch) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  // Give it the latest object filter.
  subscribe.filter_type = MoqtFilterType::kLatestObject;
  subscribe.start = std::nullopt;
  subscribe.end_group = std::nullopt;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(4, 0, 10));
  ReceiveSubscribeSynchronousOk(track, subscribe, stream_input.get());

  MoqtObjectListener* subscription =
      MoqtSessionPeer::GetSubscription(&session_, subscribe.request_id);
  ASSERT_NE(subscription, nullptr);
  EXPECT_TRUE(
      MoqtSessionPeer::InSubscriptionWindow(subscription, Location(4, 0, 11)));
  EXPECT_FALSE(
      MoqtSessionPeer::InSubscriptionWindow(subscription, Location(4, 0, 10)));

  // Joining FETCH arrives. The resulting Fetch should begin at (2, 0).
  MoqtFetch fetch = DefaultFetch();
  fetch.fetch_id = 3;
  fetch.joining_fetch = {1, 2};
  EXPECT_CALL(*track, Fetch(Location(2, 0), 4, std::optional<uint64_t>(10), _))
      .WillOnce(Return(std::make_unique<MockFetchTask>()));
  stream_input->OnFetchMessage(fetch);
}

TEST_F(MoqtSessionTest, IncomingJoiningFetchBadSubscribeId) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  fetch.joining_fetch = {1, 2};
  MoqtFetchError expected_error = {
      /*request_id=*/1,
      /*error_code=*/RequestErrorCode::kTrackDoesNotExist,
      /*reason_phrase=*/"Joining Fetch for non-existent subscribe",
  };
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_error), _));
  stream_input->OnFetchMessage(fetch);
}

TEST_F(MoqtSessionTest, IncomingJoiningFetchNonLatestObject) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(2, 0, 10));
  ReceiveSubscribeSynchronousOk(track, subscribe, stream_input.get());

  MoqtFetch fetch = DefaultFetch();
  fetch.fetch_id = 3;
  fetch.joining_fetch = {1, 2};
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Joining Fetch for non-LatestObject subscribe"))
      .Times(1);
  stream_input->OnFetchMessage(fetch);
}

TEST_F(MoqtSessionTest, SendJoiningFetch) {
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  MoqtSubscribe expected_subscribe = {
      /*request_id=*/0,
      /*track_alias=*/0,
      /*full_track_name=*/FullTrackName("foo", "bar"),
      /*subscriber_priority=*/0x80,
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*forward=*/true,
      /*filter_type=*/MoqtFilterType::kLatestObject,
      /*start=*/std::nullopt,
      /*end_group=*/std::nullopt,
      VersionSpecificParameters(),
  };
  MoqtFetch expected_fetch = {
      /*fetch_id=*/2,
      /*subscriber_priority=*/0x80,
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*joining_fetch=*/JoiningFetch(0, 1),
  };
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_subscribe), _));
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_fetch), _));
  EXPECT_TRUE(session_.JoiningFetch(
      expected_subscribe.full_track_name, &remote_track_visitor, nullptr, 1,
      0x80, MoqtDeliveryOrder::kAscending, VersionSpecificParameters()));
}

TEST_F(MoqtSessionTest, SendJoiningFetchNoFlowControl) {
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetch), _));
  EXPECT_TRUE(session_.JoiningFetch(FullTrackName("foo", "bar"),
                                    &remote_track_visitor, 0,
                                    VersionSpecificParameters()));

  EXPECT_CALL(remote_track_visitor, OnReply).Times(1);
  stream_input->OnSubscribeOkMessage(
      MoqtSubscribeOk(0, quic::QuicTimeDelta::FromMilliseconds(0),
                      MoqtDeliveryOrder::kAscending, Location(2, 0),
                      VersionSpecificParameters()));
  stream_input->OnFetchOkMessage(MoqtFetchOk(2, MoqtDeliveryOrder::kAscending,
                                             Location(2, 0),
                                             VersionSpecificParameters()));
  // Packet arrives on FETCH stream.
  MoqtObject object = {
      /*fetch_id=*/2,
      /*group_id, object_id=*/0,
      0,
      /*publisher_priority=*/128,
      /*extension_headers=*/"",
      /*status=*/MoqtObjectStatus::kNormal,
      /*subgroup=*/0,
      /*payload_length=*/3,
  };
  MoqtFramer framer(quiche::SimpleBufferAllocator::Get(), true);
  quiche::QuicheBuffer header = framer.SerializeObjectHeader(
      object, MoqtDataStreamType::kStreamHeaderFetch, true);

  // Open stream, deliver two objects before FETCH_OK. Neither should be read.
  webtransport::test::InMemoryStream data_stream(kIncomingUniStreamId);
  data_stream.SetVisitor(
      MoqtSessionPeer::CreateIncomingStreamVisitor(&session_, &data_stream));
  data_stream.Receive(header.AsStringView(), false);
  EXPECT_CALL(remote_track_visitor, OnObjectFragment).Times(1);
  data_stream.Receive("foo", false);
}

TEST_F(MoqtSessionTest, IncomingSubscribeAnnounces) {
  FullTrackName track_namespace = FullTrackName{"foo"};
  auto parameters = std::make_optional<VersionSpecificParameters>(
      AuthTokenType::kOutOfBand, "foo");
  MoqtSubscribeAnnounces announces = {
      track_namespace,
      *parameters,
  };
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(session_callbacks_.incoming_subscribe_announces_callback,
              Call(_, parameters))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(
      control_stream,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeAnnouncesOk), _));
  stream_input->OnSubscribeAnnouncesMessage(announces);
  MoqtUnsubscribeAnnounces unsubscribe_announces = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  EXPECT_CALL(session_callbacks_.incoming_subscribe_announces_callback,
              Call(track_namespace, std::optional<VersionSpecificParameters>()))
      .WillOnce(Return(std::nullopt));
  stream_input->OnUnsubscribeAnnouncesMessage(unsubscribe_announces);
}

TEST_F(MoqtSessionTest, IncomingSubscribeAnnouncesWithError) {
  FullTrackName track_namespace = FullTrackName{"foo"};
  auto parameters = std::make_optional<VersionSpecificParameters>(
      AuthTokenType::kOutOfBand, "foo");
  MoqtSubscribeAnnounces announces = {
      track_namespace,
      *parameters,
  };
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(session_callbacks_.incoming_subscribe_announces_callback,
              Call(_, parameters))
      .WillOnce(Return(
          MoqtSubscribeErrorReason{RequestErrorCode::kUnauthorized, "foo"}));
  EXPECT_CALL(
      control_stream,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeAnnouncesError),
             _));
  stream_input->OnSubscribeAnnouncesMessage(announces);
}

TEST_F(MoqtSessionTest, FetchThenOkThenCancel) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  std::unique_ptr<MoqtFetchTask> fetch_task;
  session_.Fetch(
      FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task = std::move(task);
      },
      Location(0, 0), 4, std::nullopt, 128, std::nullopt,
      VersionSpecificParameters());
  MoqtFetchOk ok = {
      /*request_id=*/0,
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/Location(3, 25),
      VersionSpecificParameters(),
  };
  stream_input->OnFetchOkMessage(ok);
  ASSERT_NE(fetch_task, nullptr);
  EXPECT_TRUE(fetch_task->GetStatus().ok());
  PublishedObject object;
  EXPECT_EQ(fetch_task->GetNextObject(object),
            MoqtFetchTask::GetNextObjectResult::kPending);
  // Cancel the fetch.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchCancel), _));
  fetch_task.reset();
}

TEST_F(MoqtSessionTest, FetchThenError) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  std::unique_ptr<MoqtFetchTask> fetch_task;
  session_.Fetch(
      FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task = std::move(task);
      },
      Location(0, 0), 4, std::nullopt, 128, std::nullopt,
      VersionSpecificParameters());
  MoqtFetchError error = {
      /*request_id=*/0,
      /*error_code=*/RequestErrorCode::kUnauthorized,
      /*reason_phrase=*/"No username provided",
  };
  stream_input->OnFetchErrorMessage(error);
  ASSERT_NE(fetch_task, nullptr);
  EXPECT_TRUE(absl::IsPermissionDenied(fetch_task->GetStatus()));
  EXPECT_EQ(fetch_task->GetStatus().message(), "No username provided");
}

// The application takes objects as they arrive.
TEST_F(MoqtSessionTest, IncomingFetchObjectsGreedyApp) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  std::unique_ptr<MoqtFetchTask> fetch_task;
  uint64_t expected_object_id = 0;
  session_.Fetch(
      FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task = std::move(task);
        fetch_task->SetObjectAvailableCallback([&]() {
          PublishedObject object;
          MoqtFetchTask::GetNextObjectResult result;
          do {
            result = fetch_task->GetNextObject(object);
            if (result == MoqtFetchTask::GetNextObjectResult::kSuccess) {
              EXPECT_EQ(object.sequence.object, expected_object_id);
              ++expected_object_id;
            }
          } while (result != MoqtFetchTask::GetNextObjectResult::kPending);
        });
      },
      Location(0, 0), 4, std::nullopt, 128, std::nullopt,
      VersionSpecificParameters());
  // Build queue of packets to arrive.
  std::queue<quiche::QuicheBuffer> headers;
  std::queue<std::string> payloads;
  MoqtObject object = {
      /*request_id=*/0,
      /*group_id, object_id=*/0,
      0,
      /*publisher_priority=*/128,
      /*extension_headers=*/"",
      /*status=*/MoqtObjectStatus::kNormal,
      /*subgroup=*/0,
      /*payload_length=*/3,
  };
  MoqtFramer framer_(quiche::SimpleBufferAllocator::Get(), true);
  for (int i = 0; i < 4; ++i) {
    object.object_id = i;
    headers.push(framer_.SerializeObjectHeader(
        object, MoqtDataStreamType::kStreamHeaderFetch, i == 0));
    payloads.push("foo");
  }

  // Open stream, deliver two objects before FETCH_OK. Neither should be read.
  webtransport::test::InMemoryStream data_stream(kIncomingUniStreamId);
  data_stream.SetVisitor(
      MoqtSessionPeer::CreateIncomingStreamVisitor(&session_, &data_stream));
  for (int i = 0; i < 2; ++i) {
    data_stream.Receive(headers.front().AsStringView(), false);
    data_stream.Receive(payloads.front(), false);
    headers.pop();
    payloads.pop();
  }
  EXPECT_EQ(fetch_task, nullptr);
  EXPECT_GT(data_stream.ReadableBytes(), 0);

  // FETCH_OK arrives, objects are delivered.
  MoqtFetchOk ok = {
      /*request_id=*/0,
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/Location(3, 25),
      VersionSpecificParameters(),
  };
  stream_input->OnFetchOkMessage(ok);
  ASSERT_NE(fetch_task, nullptr);
  EXPECT_EQ(expected_object_id, 2);

  // Deliver the rest of the objects.
  for (int i = 2; i < 4; ++i) {
    data_stream.Receive(headers.front().AsStringView(), false);
    data_stream.Receive(payloads.front(), false);
    headers.pop();
    payloads.pop();
  }
  EXPECT_EQ(expected_object_id, 4);
}

TEST_F(MoqtSessionTest, IncomingFetchObjectsSlowApp) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  std::unique_ptr<MoqtFetchTask> fetch_task;
  uint64_t expected_object_id = 0;
  bool objects_available = false;
  session_.Fetch(
      FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task = std::move(task);
        fetch_task->SetObjectAvailableCallback(
            [&]() { objects_available = true; });
      },
      Location(0, 0), 4, std::nullopt, 128, std::nullopt,
      VersionSpecificParameters());
  // Build queue of packets to arrive.
  std::queue<quiche::QuicheBuffer> headers;
  std::queue<std::string> payloads;
  MoqtObject object = {
      /*request_id=*/0,
      /*group_id, object_id=*/0,
      0,
      /*publisher_priority=*/128,
      /*extension_headers=*/"",
      /*status=*/MoqtObjectStatus::kNormal,
      /*subgroup=*/0,
      /*payload_length=*/3,
  };
  MoqtFramer framer_(quiche::SimpleBufferAllocator::Get(), true);
  for (int i = 0; i < 4; ++i) {
    object.object_id = i;
    headers.push(framer_.SerializeObjectHeader(
        object, MoqtDataStreamType::kStreamHeaderFetch, i == 0));
    payloads.push("foo");
  }

  // Open stream, deliver two objects before FETCH_OK. Neither should be read.
  webtransport::test::InMemoryStream data_stream(kIncomingUniStreamId);
  data_stream.SetVisitor(
      MoqtSessionPeer::CreateIncomingStreamVisitor(&session_, &data_stream));
  for (int i = 0; i < 2; ++i) {
    data_stream.Receive(headers.front().AsStringView(), false);
    data_stream.Receive(payloads.front(), false);
    headers.pop();
    payloads.pop();
  }
  EXPECT_EQ(fetch_task, nullptr);
  EXPECT_GT(data_stream.ReadableBytes(), 0);

  // FETCH_OK arrives, objects are available.
  MoqtFetchOk ok = {
      /*request_id=*/0,
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/Location(3, 25),
      VersionSpecificParameters(),
  };
  stream_input->OnFetchOkMessage(ok);
  ASSERT_NE(fetch_task, nullptr);
  EXPECT_TRUE(objects_available);

  // Get the objects
  MoqtFetchTask::GetNextObjectResult result;
  do {
    PublishedObject new_object;
    result = fetch_task->GetNextObject(new_object);
    if (result == MoqtFetchTask::GetNextObjectResult::kSuccess) {
      EXPECT_EQ(new_object.sequence.object, expected_object_id);
      ++expected_object_id;
    }
  } while (result != MoqtFetchTask::GetNextObjectResult::kPending);
  EXPECT_EQ(expected_object_id, 2);
  objects_available = false;

  // Deliver the rest of the objects.
  for (int i = 2; i < 4; ++i) {
    data_stream.Receive(headers.front().AsStringView(), false);
    data_stream.Receive(payloads.front(), false);
    headers.pop();
    payloads.pop();
  }
  EXPECT_TRUE(objects_available);
  EXPECT_EQ(expected_object_id, 2);  // Not delivered yet.
  // Get the objects
  do {
    PublishedObject new_object;
    result = fetch_task->GetNextObject(new_object);
    if (result == MoqtFetchTask::GetNextObjectResult::kSuccess) {
      EXPECT_EQ(new_object.sequence.object, expected_object_id);
      ++expected_object_id;
    }
  } while (result != MoqtFetchTask::GetNextObjectResult::kPending);
  EXPECT_EQ(expected_object_id, 4);
}

TEST_F(MoqtSessionTest, PartialObjectFetch) {
  MoqtSessionParameters parameters(quic::Perspective::IS_CLIENT);
  parameters.deliver_partial_objects = true;
  MoqtSession session(&mock_session_, parameters,
                      std::make_unique<quic::test::TestAlarmFactory>(),
                      session_callbacks_.AsSessionCallbacks());
  webtransport::test::InMemoryStream stream(kIncomingUniStreamId);
  std::unique_ptr<MoqtFetchTask> fetch_task =
      MoqtSessionPeer::CreateUpstreamFetch(&session, &stream);
  UpstreamFetch::UpstreamFetchTask* task =
      static_cast<UpstreamFetch::UpstreamFetchTask*>(fetch_task.get());
  ASSERT_NE(task, nullptr);
  EXPECT_FALSE(task->HasObject());
  bool object_ready = false;
  task->SetObjectAvailableCallback([&]() { object_ready = true; });
  MoqtObject object = {
      /*request_id=*/0,
      /*group_id, object_id=*/0,
      0,
      /*publisher_priority=*/128,
      /*extension_headers=*/"",
      /*status=*/MoqtObjectStatus::kNormal,
      /*subgroup=*/0,
      /*payload_length=*/6,
  };
  MoqtFramer framer_(quiche::SimpleBufferAllocator::Get(), true);
  quiche::QuicheBuffer header = framer_.SerializeObjectHeader(
      object, MoqtDataStreamType::kStreamHeaderFetch, true);
  stream.Receive(header.AsStringView(), false);
  EXPECT_FALSE(task->HasObject());
  EXPECT_FALSE(object_ready);
  stream.Receive("foo", false);
  EXPECT_TRUE(task->HasObject());
  EXPECT_TRUE(task->NeedsMorePayload());
  EXPECT_FALSE(object_ready);
  stream.Receive("bar", false);
  EXPECT_TRUE(object_ready);
  EXPECT_TRUE(task->HasObject());
  EXPECT_FALSE(task->NeedsMorePayload());
}

TEST_F(MoqtSessionTest, DeliveryTimeoutParameter) {
  MoqtSubscribe request = DefaultSubscribe();
  request.parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  ReceiveSubscribeSynchronousOk(track, request, control_stream.get());

  MoqtObjectListener* subscription =
      MoqtSessionPeer::GetSubscription(&session_, 1);
  ASSERT_NE(subscription, nullptr);
  EXPECT_EQ(MoqtSessionPeer::GetDeliveryTimeout(subscription),
            quic::QuicTimeDelta::FromSeconds(1));
}

TEST_F(MoqtSessionTest, DeliveryTimeoutExpiredOnArrival) {
  auto track_publisher =
      std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"));
  EXPECT_CALL(*track_publisher, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 1, 2, 0, 0);
  ASSERT_NE(subscription, nullptr);
  MoqtSessionPeer::SetDeliveryTimeout(subscription,
                                      quic::QuicTimeDelta::FromSeconds(1));

  webtransport::test::MockStream data_mock;
  EXPECT_CALL(*track_publisher, GetForwardingPreference())
      .WillRepeatedly(Return(MoqtForwardingPreference::kSubgroup));
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_mock));
  EXPECT_CALL(data_mock, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(data_mock, SetVisitor(_))
      .WillOnce(
          Invoke([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
            stream_visitor = std::move(visitor);
          }));
  EXPECT_CALL(data_mock, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(data_mock, visitor()).WillRepeatedly(Invoke([&]() {
    return stream_visitor.get();
  }));
  EXPECT_CALL(*track_publisher, GetCachedObject(_))
      .WillOnce(Return(PublishedObject{
          Location(0, 0), MoqtObjectStatus::kObjectDoesNotExist, 0,
          quiche::QuicheMemSlice(),
          MoqtSessionPeer::Now(&session_) - quic::QuicTimeDelta::FromSeconds(1),
          false}));
  EXPECT_CALL(data_mock, ResetWithUserCode(kResetCodeTimedOut))
      .WillOnce(Invoke([&](webtransport::StreamErrorCode /*error*/) {
        stream_visitor.reset();
      }));
  // Arrival time is very old; reset immediately.
  subscription->OnNewObjectAvailable(Location(0, 0, 0));
  // Subsequent objects for that subgroup are ignored.
  EXPECT_CALL(*track_publisher, GetCachedObject(_)).Times(0);
  EXPECT_CALL(mock_session_, GetStreamById(_)).Times(0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  subscription->OnNewObjectAvailable(Location(0, 0, 1));
  // Check that reset_subgroups_ is pruned.
  EXPECT_TRUE(
      MoqtSessionPeer::SubgroupHasBeenReset(subscription, Location(0, 0, 1)));
  subscription->OnGroupAbandoned(0);
  EXPECT_FALSE(
      MoqtSessionPeer::SubgroupHasBeenReset(subscription, Location(0, 0, 1)));
}

TEST_F(MoqtSessionTest, DeliveryTimeoutAfterIntegratedFin) {
  auto track_publisher =
      std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"));
  EXPECT_CALL(*track_publisher, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 1, 2, 0, 0);
  ASSERT_NE(subscription, nullptr);
  MoqtSessionPeer::SetDeliveryTimeout(subscription,
                                      quic::QuicTimeDelta::FromSeconds(1));

  webtransport::test::MockStream data_mock;
  EXPECT_CALL(*track_publisher, GetForwardingPreference())
      .WillRepeatedly(Return(MoqtForwardingPreference::kSubgroup));
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_mock));
  EXPECT_CALL(data_mock, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(data_mock, SetVisitor(_))
      .WillOnce(
          Invoke([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
            stream_visitor = std::move(visitor);
          }));
  EXPECT_CALL(data_mock, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(data_mock, visitor()).WillRepeatedly(Invoke([&]() {
    return stream_visitor.get();
  }));
  EXPECT_CALL(*track_publisher, GetCachedObject(_))
      .WillOnce(Return(PublishedObject{
          Location(0, 0), MoqtObjectStatus::kObjectDoesNotExist, 0,
          quiche::QuicheMemSlice(), MoqtSessionPeer::Now(&session_), true}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(data_mock, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(data_mock, ResetWithUserCode(kResetCodeTimedOut)).Times(0);
  subscription->OnNewObjectAvailable(Location(0, 0, 0));
  auto* delivery_alarm = static_cast<quic::test::MockAlarmFactory::TestAlarm*>(
      MoqtSessionPeer::GetAlarm(stream_visitor.get()));
  EXPECT_CALL(data_mock, ResetWithUserCode(kResetCodeTimedOut))
      .WillOnce(Invoke([&](webtransport::StreamErrorCode /*error*/) {
        stream_visitor.reset();
      }));
  delivery_alarm->Fire();
}

TEST_F(MoqtSessionTest, DeliveryTimeoutAfterSeparateFin) {
  auto track_publisher =
      std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"));
  EXPECT_CALL(*track_publisher, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 1, 2, 0, 0);
  ASSERT_NE(subscription, nullptr);
  MoqtSessionPeer::SetDeliveryTimeout(subscription,
                                      quic::QuicTimeDelta::FromSeconds(1));

  webtransport::test::MockStream data_mock;
  EXPECT_CALL(*track_publisher, GetForwardingPreference())
      .WillRepeatedly(Return(MoqtForwardingPreference::kSubgroup));
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_mock));
  EXPECT_CALL(data_mock, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&data_mock));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(data_mock, SetVisitor(_))
      .WillOnce(
          Invoke([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
            stream_visitor = std::move(visitor);
          }));
  EXPECT_CALL(data_mock, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(data_mock, visitor()).WillRepeatedly(Invoke([&]() {
    return stream_visitor.get();
  }));
  EXPECT_CALL(*track_publisher, GetCachedObject(_))
      .WillOnce(Return(PublishedObject{
          Location(0, 0), MoqtObjectStatus::kObjectDoesNotExist, 0,
          quiche::QuicheMemSlice(), MoqtSessionPeer::Now(&session_), false}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(data_mock, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  subscription->OnNewObjectAvailable(Location(0, 0, 0));

  EXPECT_CALL(data_mock, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  subscription->OnNewFinAvailable(Location(0, 0, 0));
  auto* delivery_alarm = static_cast<quic::test::MockAlarmFactory::TestAlarm*>(
      MoqtSessionPeer::GetAlarm(stream_visitor.get()));
  EXPECT_CALL(data_mock, ResetWithUserCode(kResetCodeTimedOut))
      .WillOnce(Invoke([&](webtransport::StreamErrorCode /*error*/) {
        stream_visitor.reset();
      }));
  delivery_alarm->Fire();
}

TEST_F(MoqtSessionTest, DeliveryTimeoutAlternateDesign) {
  session_.UseAlternateDeliveryTimeout();
  auto track_publisher =
      std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"));
  EXPECT_CALL(*track_publisher, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 1, 2, 0, 0);
  ASSERT_NE(subscription, nullptr);
  MoqtSessionPeer::SetDeliveryTimeout(subscription,
                                      quic::QuicTimeDelta::FromSeconds(1));

  webtransport::test::MockStream data_mock1;
  EXPECT_CALL(*track_publisher, GetForwardingPreference())
      .WillRepeatedly(Return(MoqtForwardingPreference::kSubgroup));
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_mock1));
  EXPECT_CALL(data_mock1, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&data_mock1));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor1;
  EXPECT_CALL(data_mock1, SetVisitor(_))
      .WillOnce(
          Invoke([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
            stream_visitor1 = std::move(visitor);
          }));
  EXPECT_CALL(data_mock1, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(data_mock1, visitor()).WillRepeatedly(Invoke([&]() {
    return stream_visitor1.get();
  }));
  EXPECT_CALL(*track_publisher, GetCachedObject(_))
      .WillOnce(Return(PublishedObject{
          Location(0, 0), MoqtObjectStatus::kObjectDoesNotExist, 0,
          quiche::QuicheMemSlice(), MoqtSessionPeer::Now(&session_), false}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(data_mock1, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  subscription->OnNewObjectAvailable(Location(0, 0, 0));

  webtransport::test::MockStream data_mock2;
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_mock2));
  EXPECT_CALL(data_mock2, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId + 4));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId + 4))
      .WillRepeatedly(Return(&data_mock2));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor2;
  EXPECT_CALL(data_mock2, SetVisitor(_))
      .WillOnce(
          Invoke([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
            stream_visitor2 = std::move(visitor);
          }));
  EXPECT_CALL(data_mock2, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(data_mock2, visitor()).WillRepeatedly(Invoke([&]() {
    return stream_visitor2.get();
  }));
  EXPECT_CALL(*track_publisher, GetCachedObject(_))
      .WillOnce(Return(PublishedObject{
          Location(1, 0), MoqtObjectStatus::kObjectDoesNotExist, 0,
          quiche::QuicheMemSlice(), MoqtSessionPeer::Now(&session_), false}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(data_mock2, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  subscription->OnNewObjectAvailable(Location(1, 0, 0));

  // Group 1 should start the timer on the Group 0 stream.
  auto* delivery_alarm = static_cast<quic::test::MockAlarmFactory::TestAlarm*>(
      MoqtSessionPeer::GetAlarm(stream_visitor1.get()));
  EXPECT_CALL(data_mock1, ResetWithUserCode(kResetCodeTimedOut))
      .WillOnce(Invoke([&](webtransport::StreamErrorCode /*error*/) {
        stream_visitor1.reset();
      }));
  delivery_alarm->Fire();
}

TEST_F(MoqtSessionTest, ReceiveGoAwayEnforcement) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(session_callbacks_.goaway_received_callback, Call("foo"));
  stream_input->OnGoAwayMessage(MoqtGoAway("foo"));
  // New requests not allowed.
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_FALSE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                               &remote_track_visitor,
                                               VersionSpecificParameters()));
  EXPECT_FALSE(session_.SubscribeAnnounces(
      FullTrackName{"foo"},
      +[](FullTrackName /*track_namespace*/,
          std::optional<RequestErrorCode> /*error*/,
          absl::string_view /*reason*/) {},
      VersionSpecificParameters()));
  session_.Announce(
      FullTrackName{"foo"},
      +[](FullTrackName /*track_namespace*/,
          std::optional<MoqtAnnounceErrorReason> /*error*/) {},
      VersionSpecificParameters());
  EXPECT_FALSE(session_.Fetch(
      FullTrackName{"foo", "bar"},
      +[](std::unique_ptr<MoqtFetchTask> /*fetch_task*/) {}, Location(0, 0), 5,
      std::nullopt, 127, std::nullopt, VersionSpecificParameters()));
  // Error on additional GOAWAY.
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received multiple GOAWAY messages"))
      .Times(1);
  bool reported_error = false;
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = true;
        EXPECT_EQ(error_message, "Received multiple GOAWAY messages");
      });
  stream_input->OnGoAwayMessage(MoqtGoAway("foo"));
}

TEST_F(MoqtSessionTest, SendGoAwayEnforcement) {
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  CreateTrackPublisher();
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kGoAway), _));
  session_.GoAway("");
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeError), _));
  stream_input->OnSubscribeMessage(DefaultSubscribe());
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kAnnounceError), _));
  stream_input->OnAnnounceMessage(
      MoqtAnnounce(FullTrackName("foo", "bar"), VersionSpecificParameters()));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchError), _));
  MoqtFetch fetch = DefaultFetch();
  fetch.fetch_id = 3;
  stream_input->OnFetchMessage(fetch);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeAnnouncesError),
             _));
  stream_input->OnSubscribeAnnouncesMessage(
      MoqtSubscribeAnnounces(FullTrackName("foo", "bar")));
  // Block all outgoing SUBSCRIBE, ANNOUNCE, GOAWAY,etc.
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  EXPECT_FALSE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                               &remote_track_visitor,
                                               VersionSpecificParameters()));
  EXPECT_FALSE(session_.SubscribeAnnounces(
      FullTrackName{"foo"},
      +[](FullTrackName /*track_namespace*/,
          std::optional<RequestErrorCode> /*error*/,
          absl::string_view /*reason*/) {},
      VersionSpecificParameters()));
  session_.Announce(
      FullTrackName{"foo"},
      +[](FullTrackName /*track_namespace*/,
          std::optional<MoqtAnnounceErrorReason> /*error*/) {},
      VersionSpecificParameters());
  EXPECT_FALSE(session_.Fetch(
      FullTrackName{"foo", "bar"},
      +[](std::unique_ptr<MoqtFetchTask> /*fetch_task*/) {}, Location(0, 0), 5,
      std::nullopt, 127, std::nullopt, VersionSpecificParameters()));
  session_.GoAway("");
  // GoAway timer fires.
  auto* goaway_alarm = static_cast<quic::test::MockAlarmFactory::TestAlarm*>(
      MoqtSessionPeer::GetGoAwayTimeoutAlarm(&session_));
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<webtransport::SessionErrorCode>(
                               MoqtError::kGoawayTimeout),
                           _));
  goaway_alarm->Fire();
}

TEST_F(MoqtSessionTest, ClientCannotSendNewSessionUri) {
  // session_ is a client session.
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  // Client GOAWAY not sent.
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  session_.GoAway("foo");
}

TEST_F(MoqtSessionTest, ServerCannotReceiveNewSessionUri) {
  webtransport::test::MockSession mock_session;
  MoqtSession session(&mock_session,
                      MoqtSessionParameters(quic::Perspective::IS_SERVER),
                      std::make_unique<quic::test::TestAlarmFactory>(),
                      session_callbacks_.AsSessionCallbacks());
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session, &mock_stream_);
  MoqtSessionPeer::CreateControlStream(&session, &mock_stream_);
  EXPECT_CALL(
      mock_session,
      CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                   "Received GOAWAY with new_session_uri on the server"))
      .Times(1);
  bool reported_error = false;
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = true;
        EXPECT_EQ(error_message,
                  "Received GOAWAY with new_session_uri on the server");
      });
  stream_input->OnGoAwayMessage(MoqtGoAway("foo"));
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, ReceiveSubscribeDoneWithOpenStreams) {
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                              &remote_track_visitor,
                                              VersionSpecificParameters()));
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(10000),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_location=*/std::nullopt,
      /*parameters=*/VersionSpecificParameters(),
  };
  stream_input->OnSubscribeOkMessage(ok);
  constexpr uint64_t kNumStreams = 3;
  webtransport::test::MockStream data[kNumStreams];
  std::unique_ptr<webtransport::StreamVisitor> data_streams[kNumStreams];

  MoqtObject object = {
      /*track_alias=*/0,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kGroupDoesNotExist,
      /*subgroup_id=*/0,
      /*payload_length=*/0,
  };
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    EXPECT_CALL(data[i], GetStreamId())
        .WillRepeatedly(Return(kOutgoingUniStreamId + i * 4));
    EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId + i * 4))
        .WillRepeatedly(Return(&data[i]));
    object.group_id = i;
    DeliverObject(object, false, mock_session_, &data[i], data_streams[i],
                  &remote_track_visitor);
  }
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  EXPECT_FALSE(track->all_streams_closed());
  stream_input->OnSubscribeDoneMessage(
      MoqtSubscribeDone(0, SubscribeDoneCode::kTrackEnded, kNumStreams, "foo"));
  track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  EXPECT_FALSE(track->all_streams_closed());
  EXPECT_CALL(remote_track_visitor, OnSubscribeDone(_));
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    data_streams[i].reset();
  }
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 0), nullptr);
}

TEST_F(MoqtSessionTest, ReceiveSubscribeDoneWithClosedStreams) {
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                              &remote_track_visitor,
                                              VersionSpecificParameters()));
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(10000),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_location=*/std::nullopt,
      /*parameters=*/VersionSpecificParameters(),
  };
  stream_input->OnSubscribeOkMessage(ok);
  constexpr uint64_t kNumStreams = 3;
  webtransport::test::MockStream data[kNumStreams];
  std::unique_ptr<webtransport::StreamVisitor> data_streams[kNumStreams];

  MoqtObject object = {
      /*track_alias=*/0,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kGroupDoesNotExist,
      /*subgroup_id=*/0,
      /*payload_length=*/0,
  };
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    EXPECT_CALL(data[i], GetStreamId())
        .WillRepeatedly(Return(kOutgoingUniStreamId + i * 4));
    EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId + i * 4))
        .WillRepeatedly(Return(&data[i]));
    object.group_id = i;
    DeliverObject(object, true, mock_session_, &data[i], data_streams[i],
                  &remote_track_visitor);
  }
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    data_streams[i].reset();
  }
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  EXPECT_FALSE(track->all_streams_closed());
  EXPECT_CALL(remote_track_visitor, OnSubscribeDone(_));
  stream_input->OnSubscribeDoneMessage(
      MoqtSubscribeDone(0, SubscribeDoneCode::kTrackEnded, kNumStreams, "foo"));
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 0), nullptr);
}

TEST_F(MoqtSessionTest, SubscribeDoneTimeout) {
  MockSubscribeRemoteTrackVisitor remote_track_visitor;
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.SubscribeCurrentObject(FullTrackName("foo", "bar"),
                                              &remote_track_visitor,
                                              VersionSpecificParameters()));
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(10000),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_location=*/std::nullopt,
      /*parameters=*/VersionSpecificParameters(),
  };
  stream_input->OnSubscribeOkMessage(ok);
  constexpr uint64_t kNumStreams = 3;
  webtransport::test::MockStream data[kNumStreams];
  std::unique_ptr<webtransport::StreamVisitor> data_streams[kNumStreams];

  MoqtObject object = {
      /*track_alias=*/0,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kGroupDoesNotExist,
      /*subgroup_id=*/0,
      /*payload_length=*/0,
  };
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    EXPECT_CALL(data[i], GetStreamId())
        .WillRepeatedly(Return(kOutgoingUniStreamId + i * 4));
    EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId + i * 4))
        .WillRepeatedly(Return(&data[i]));
    object.group_id = i;
    DeliverObject(object, true, mock_session_, &data[i], data_streams[i],
                  &remote_track_visitor);
  }
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    data_streams[i].reset();
  }
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  EXPECT_FALSE(track->all_streams_closed());
  // stream_count includes a stream that was never sent.
  stream_input->OnSubscribeDoneMessage(MoqtSubscribeDone(
      0, SubscribeDoneCode::kTrackEnded, kNumStreams + 1, "foo"));
  EXPECT_FALSE(track->all_streams_closed());
  auto* subscribe_done_alarm =
      static_cast<quic::test::MockAlarmFactory::TestAlarm*>(
          MoqtSessionPeer::GetSubscribeDoneAlarm(track));
  EXPECT_CALL(remote_track_visitor, OnSubscribeDone(_));
  subscribe_done_alarm->Fire();
  // quic::test::MockAlarmFactory::FireAlarm(subscribe_done_alarm);;
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 0), nullptr);
}

// TODO: re-enable this test once this behavior is re-implemented.
#if 0
TEST_F(MoqtSessionTest, SubscribeUpdateClosesSubscription) {
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kSubgroup,
                         &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);
  // Get the window, set the maximum delivered.
  LocalTrack* track = MoqtSessionPeer::local_track(&session_, ftn);
  track->GetWindow(0)->OnObjectSent(Location(7, 3),
                                    MoqtObjectStatus::kNormal);
  // Update the end to fall at the last delivered object.
  MoqtSubscribeUpdate update = {
      /*request_id=*/0,
      /*start_group=*/5,
      /*start_object=*/0,
      /*end_group=*/7,
  };
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream_));
  bool correct_message = false;
  EXPECT_CALL(mock_stream_, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeDone);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeUpdateMessage(update);
  EXPECT_TRUE(correct_message);
  EXPECT_FALSE(session_.HasSubscribers(ftn));
}
#endif

}  // namespace test

}  // namespace moqt
