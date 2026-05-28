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
#include <variant>
#include <vector>

#include "absl/base/casts.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_namespace_stream.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/session_namespace_tree.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/moqt/test_tools/moqt_session_peer.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

namespace {

using ::testing::_;
using ::testing::Optional;
using ::testing::Return;
using ::testing::StrictMock;

constexpr webtransport::StreamId kIncomingUniStreamId = 15;
constexpr webtransport::StreamId kOutgoingUniStreamId = 14;
constexpr uint64_t kDefaultLocalRequestId = 0;
constexpr uint64_t kDefaultPeerRequestId = 1;
const MoqtDataStreamType kDefaultSubgroupStreamType =
    MoqtDataStreamType::Subgroup(2, 4, false, false);
constexpr MoqtPriority kDefaultPublisherPriority = 0x80;
const TrackExtensions kNoExtensions;

std::vector<quiche::QuicheMemSlice> PayloadFromString(absl::string_view s) {
  std::vector<quiche::QuicheMemSlice> payload;
  payload.push_back(quiche::QuicheMemSlice::Copy(s));
  return payload;
}

FullTrackName kDefaultTrackName() { return FullTrackName("foo", "bar"); }

MoqtSubscribe DefaultSubscribe(uint64_t request_id) {
  MoqtSubscribe subscribe = {
      request_id,
      kDefaultTrackName(),
      MessageParameters(),
  };
  return subscribe;
}

MessageParameters SubscribeForTest() {
  MessageParameters parameters;
  parameters.delivery_timeout = quic::QuicTimeDelta::FromMilliseconds(10000);
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "bar");
  parameters.set_forward(true);
  parameters.subscriber_priority = 0x20;
  parameters.subscription_filter.emplace(Location(4, 1));
  parameters.group_order = MoqtDeliveryOrder::kDescending;
  return parameters;
}

// The usual test case is that a SUBSCRIBE is coming in.
MoqtSubscribe DefaultSubscribe() {
  return DefaultSubscribe(kDefaultPeerRequestId);
}

// Used when a test sets up a remote track.
MoqtSubscribe DefaultLocalSubscribe() {
  return DefaultSubscribe(kDefaultLocalRequestId);
}

MoqtFetch DefaultFetch() {
  MoqtFetch fetch = {
      kDefaultPeerRequestId,
      StandaloneFetch(kDefaultTrackName(), Location(0, 0),
                      Location(1, kMaxObjectId)),
      MessageParameters(),
  };
  return fetch;
}

std::optional<MoqtMessageType> PeekControlMessageType(absl::string_view data) {
  quiche::QuicheDataReader reader(data);
  uint64_t varint;
  if (!reader.ReadVarInt62(&varint)) {
    return std::nullopt;
  }
  return static_cast<MoqtMessageType>(varint);
}

}  // namespace

class MoqtSessionTest : public quic::test::QuicTest {
 public:
  MoqtSessionTest()
      : session_(&mock_session_,
                 MoqtSessionParameters(quic::Perspective::IS_CLIENT, "", ""),
                 std::make_unique<quic::test::TestAlarmFactory>(),
                 session_callbacks_.AsSessionCallbacks()) {
    session_.set_publisher(&publisher_);
    MoqtSessionPeer::set_peer_max_request_id(&session_,
                                             kDefaultInitialMaxRequestId);
    ON_CALL(mock_session_, GetStreamById).WillByDefault(Return(&mock_stream_));
    EXPECT_EQ(MoqtSessionPeer::GetImplementationString(&session_),
              kImplementationName);
  }
  ~MoqtSessionTest() {
    EXPECT_CALL(session_callbacks_.session_deleted_callback, Call());
  }

  MockTrackPublisher* CreateTrackPublisher() {
    auto publisher = std::make_shared<MockTrackPublisher>(kDefaultTrackName());
    publisher_.Add(publisher);
    ON_CALL(*publisher, largest_location()).WillByDefault(Return(std::nullopt));
    ON_CALL(*publisher, expiration()).WillByDefault(Return(std::nullopt));
    ON_CALL(*publisher, extensions())
        .WillByDefault(testing::ReturnRef(kNoExtensions));
    return publisher.get();
  }

  void SetLargestId(MockTrackPublisher* publisher, Location largest_id) {
    ON_CALL(*publisher, largest_location()).WillByDefault(Return(largest_id));
  }

  // The publisher receives SUBSCRIBE and synchronously publishes namespaces it
  // supports.
  MoqtObjectListener* ReceiveSubscribeSynchronousOk(
      MockTrackPublisher* publisher, MoqtSubscribe& subscribe,
      MoqtBidiStreamTestWrapper* control_parser, uint64_t track_alias = 0,
      TrackExtensions extensions = TrackExtensions()) {
    MoqtObjectListener* listener_ptr = nullptr;
    EXPECT_CALL(*publisher, AddObjectListener)
        .WillOnce([&](MoqtObjectListener* listener) {
          listener_ptr = listener;
          listener->OnSubscribeAccepted();
        });
    MessageParameters parameters;
    parameters.expires = publisher->expiration();
    parameters.largest_object = publisher->largest_location();
    MoqtSubscribeOk expected_ok = {
        subscribe.request_id,
        track_alias,
        parameters,
        extensions,
    };
    EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
    control_parser->ReceiveMessage(subscribe);
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
    MoqtFramer framer(true);
    std::optional<PublishedObjectMetadata> previous_object;
    if (visitor != nullptr) {
      previous_object = PublishedObjectMetadata();
      previous_object->location.object = object.object_id - 1;
    }
    quiche::QuicheBuffer buffer = framer.SerializeObjectHeader(
        object,
        MoqtDataStreamType::Subgroup(*object.subgroup_id, object.object_id,
                                     false, false),
        previous_object);
    size_t data_read = 0;
    if (visitor == nullptr) {  // It's the first object in the stream
      EXPECT_CALL(session, AcceptIncomingUnidirectionalStream())
          .WillOnce(Return(stream))
          .WillOnce(Return(nullptr));
      EXPECT_CALL(*stream, SetVisitor(_))
          .WillOnce(
              [&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
                visitor = std::move(new_visitor);
              });
      EXPECT_CALL(*stream, visitor()).WillRepeatedly([&]() {
        return visitor.get();
      });
    }
    EXPECT_CALL(*stream, PeekNextReadableRegion()).WillRepeatedly([&]() {
      return webtransport::Stream::PeekResult(
          absl::string_view(buffer.data() + data_read,
                            buffer.size() - data_read),
          fin && data_read == buffer.size(), fin);
    });
    EXPECT_CALL(*stream, ReadableBytes()).WillRepeatedly([&]() {
      return buffer.size() - data_read;
    });
    EXPECT_CALL(*stream, Read(testing::An<absl::Span<char>>()))
        .WillRepeatedly([&](absl::Span<char> bytes_to_read) {
          size_t read_size =
              std::min(bytes_to_read.size(), buffer.size() - data_read);
          memcpy(bytes_to_read.data(), buffer.data() + data_read, read_size);
          data_read += read_size;
          return webtransport::Stream::ReadResult(
              read_size, fin && data_read == buffer.size());
        });
    EXPECT_CALL(*stream, SkipBytes(_)).WillRepeatedly([&](size_t bytes) {
      data_read += bytes;
      return fin && data_read == buffer.size();
    });
    EXPECT_CALL(*track_visitor, OnObjectFragment).Times(1);
    if (visitor == nullptr) {
      session_.OnIncomingUnidirectionalStreamAvailable();
    } else {
      visitor->OnCanRead();
    }
  }

  webtransport::test::MockStream mock_stream_, control_stream_;
  MockSessionCallbacks session_callbacks_;
  webtransport::test::MockSession mock_session_;
  MockSubscribeRemoteTrackVisitor remote_track_visitor_;
  MoqtSession session_;
  MoqtKnownTrackPublisher publisher_;
};

TEST_F(MoqtSessionTest, Queries) {
  EXPECT_EQ(session_.perspective(), quic::Perspective::IS_CLIENT);
}

// Verify the session sends CLIENT_SETUP on the control stream.
TEST_F(MoqtSessionTest, OnSessionReady) {
  EXPECT_CALL(mock_session_, GetNegotiatedSubprotocol)
      .WillOnce(Return(std::optional<std::string>(kDefaultMoqtVersion)));
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingBidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream_, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kClientSetup), _));
  session_.OnSessionReady();

  // Receive SERVER_SETUP
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::FetchParserVisitorFromWebtransportStreamVisitor(
          std::move(visitor));
  // Handle the server setup
  MoqtServerSetup setup;  // No fields are set.
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->ReceiveMessage(setup);
}

TEST_F(MoqtSessionTest, OnSessionReadyNoControlStream) {
  EXPECT_CALL(mock_session_, GetNegotiatedSubprotocol)
      .WillOnce(Return(std::optional<std::string>(kDefaultMoqtVersion)));
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingBidirectionalStream)
      .WillOnce(Return(false));
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  session_.OnSessionReady();
}

TEST_F(MoqtSessionTest, PeerOpensBidiStream) {
  MoqtSession server_session(
      &mock_session_, MoqtSessionParameters(quic::Perspective::IS_SERVER),
      std::make_unique<quic::test::TestAlarmFactory>(),
      session_callbacks_.AsSessionCallbacks());
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream_))
      .WillOnce(Return(nullptr));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  webtransport::test::MockStreamVisitor mock_stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
        EXPECT_CALL(mock_stream_, visitor).WillOnce(Return(visitor.get()));
      });
  EXPECT_CALL(mock_stream_, PeekNextReadableRegion())
      .WillRepeatedly(Return(
          webtransport::Stream::PeekResult(absl::string_view(), false, false)));
  server_session.OnIncomingBidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, OnClientSetup) {
  MoqtSessionParameters session_parameters(quic::Perspective::IS_SERVER);
  MoqtSession server_session(&mock_session_, session_parameters,
                             std::make_unique<quic::test::TestAlarmFactory>(),
                             session_callbacks_.AsSessionCallbacks());
  // Load a CLIENT_SETUP message into an in-memory stream.
  webtransport::test::InMemoryStreamWithWriteBuffer in_memory_stream(0);
  MoqtFramer framer(session_parameters.using_webtrans);
  MoqtClientSetup setup;
  session_parameters.ToSetupParameters(setup.parameters);
  quiche::QuicheBuffer buffer = framer.SerializeClientSetup(setup);
  in_memory_stream.Receive(absl::string_view(buffer.data(), buffer.size()),
                           /*fin=*/false);

  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&in_memory_stream))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(session_callbacks_.session_established_callback, Call());
  server_session.OnIncomingBidirectionalStreamAvailable();
  EXPECT_EQ(PeekControlMessageType(in_memory_stream.write_buffer()),
            MoqtMessageType::kServerSetup);
  EXPECT_NE(MoqtSessionPeer::GetControlStream(&server_session), nullptr);
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
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  // Request for track returns REQUEST_ERROR.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(request);

  // Add the track. Now Subscribe should succeed.
  MockTrackPublisher* track = CreateTrackPublisher();
  std::make_shared<MockTrackPublisher>(request.full_track_name);
  request.request_id += 2;
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, IncomingPublishRejected) {
  MoqtPublish publish = {
      .request_id = 1,
      .full_track_name = FullTrackName("foo", "bar"),
      .track_alias = 2,
      .parameters = MessageParameters(),
  };
  publish.parameters.largest_object = Location(4, 5);
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  // Request for track returns REQUEST_ERROR.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(publish);
}

TEST_F(MoqtSessionTest, PublishNamespaceWithOkAndCancel) {
  testing::MockFunction<void(std::optional<MoqtRequestErrorInfo> error_message)>
      publish_namespace_response_callback;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kPublishNamespace), _));
  MoqtRequestErrorInfo cancel_error_info;
  session_.PublishNamespace(
      TrackNamespace({"foo"}), MessageParameters(),
      publish_namespace_response_callback.AsStdFunction(),
      [&](MoqtRequestErrorInfo info) { cancel_error_info = info; });

  MoqtRequestOk ok = {/*request_id=*/0, MessageParameters()};
  EXPECT_CALL(publish_namespace_response_callback, Call)
      .WillOnce([&](std::optional<MoqtRequestErrorInfo> error) {
        EXPECT_FALSE(error.has_value());
      });
  stream_input->ReceiveMessage(ok);

  MoqtPublishNamespaceCancel cancel = {
      /*request_id=*/0,
      RequestErrorCode::kInternalError,
      /*error_reason=*/"Test error",
  };
  stream_input->ReceiveMessage(cancel);
  EXPECT_EQ(cancel_error_info.error_code, RequestErrorCode::kInternalError);
  EXPECT_EQ(cancel_error_info.reason_phrase, "Test error");
  // State is gone.
  EXPECT_FALSE(session_.PublishNamespaceDone(TrackNamespace({"foo"})));
}

TEST_F(MoqtSessionTest, PublishNamespaceWithOkAndPublishNamespaceDone) {
  testing::MockFunction<void(std::optional<MoqtRequestErrorInfo> error_message)>
      publish_namespace_resolved_callback;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kPublishNamespace), _));
  session_.PublishNamespace(TrackNamespace{"foo"}, MessageParameters(),
                            publish_namespace_resolved_callback.AsStdFunction(),
                            [](MoqtRequestErrorInfo) {});

  MoqtRequestOk ok = {/*request_id=*/0, MessageParameters()};
  EXPECT_CALL(publish_namespace_resolved_callback, Call)
      .WillOnce([&](std::optional<MoqtRequestErrorInfo> error) {
        EXPECT_FALSE(error.has_value());
      });
  stream_input->ReceiveMessage(ok);

  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kPublishNamespaceDone), _));
  session_.PublishNamespaceDone(TrackNamespace{"foo"});
  // State is gone.
  EXPECT_FALSE(session_.PublishNamespaceDone(TrackNamespace{"foo"}));
}

TEST_F(MoqtSessionTest, PublishNamespaceWithError) {
  testing::MockFunction<void(std::optional<MoqtRequestErrorInfo> error_message)>
      publish_namespace_resolved_callback;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kPublishNamespace), _));
  session_.PublishNamespace(TrackNamespace{"foo"}, MessageParameters(),
                            publish_namespace_resolved_callback.AsStdFunction(),
                            [](MoqtRequestErrorInfo) {});

  MoqtRequestError error{/*request_id=*/0, RequestErrorCode::kInternalError,
                         std::nullopt, "Test error"};
  EXPECT_CALL(publish_namespace_resolved_callback, Call)
      .WillOnce([&](std::optional<MoqtRequestErrorInfo> error) {
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, RequestErrorCode::kInternalError);
        EXPECT_EQ(error->reason_phrase, "Test error");
      });
  stream_input->ReceiveMessage(error);
  // State is gone.
  EXPECT_FALSE(session_.PublishNamespaceDone(TrackNamespace{"foo"}));
}

TEST_F(MoqtSessionTest, AsynchronousSubscribeReturnsOk) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSubscribe request = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtObjectListener* listener;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce(
          [&](MoqtObjectListener* listener_ptr) { listener = listener_ptr; });
  stream_input->ReceiveMessage(request);

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribeOk), _));
  listener->OnSubscribeAccepted();
  EXPECT_TRUE(MoqtSessionPeer::RequestIdIsSubscriptionPublisher(
      &session_, kDefaultPeerRequestId));
}

TEST_F(MoqtSessionTest, AsynchronousSubscribeReturnsError) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSubscribe request = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtObjectListener* listener;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce(
          [&](MoqtObjectListener* listener_ptr) { listener = listener_ptr; });
  stream_input->ReceiveMessage(request);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  listener->OnSubscribeRejected(MoqtRequestErrorInfo(
      RequestErrorCode::kInternalError, std::nullopt, "Test error"));
  EXPECT_FALSE(MoqtSessionPeer::RequestIdIsSubscriptionPublisher(
      &session_, kDefaultPeerRequestId));
}

TEST_F(MoqtSessionTest, SynchronousSubscribeReturnsError) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSubscribe request = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce([&](MoqtObjectListener* listener) {
        EXPECT_CALL(
            mock_stream_,
            Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
        EXPECT_CALL(*track, RemoveObjectListener);
        listener->OnSubscribeRejected(MoqtRequestErrorInfo(
            RequestErrorCode::kInternalError, std::nullopt, "Test error"));
      });
  stream_input->ReceiveMessage(request);
  EXPECT_FALSE(MoqtSessionPeer::RequestIdIsSubscriptionPublisher(
      &session_, kDefaultPeerRequestId));
}

TEST_F(MoqtSessionTest, SubscribeForPast) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(10, 20));
  MoqtSubscribe request = DefaultSubscribe();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, SubscribeDoNotForward) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  request.parameters.set_forward(false);
  request.parameters.subscription_filter.emplace(
      MoqtFilterType::kLargestObject);
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
  // forward=false, so incoming objects are ignored.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  listener->OnNewObjectAvailable(Location(0, 0), 0, kDefaultPublisherPriority);
}

TEST_F(MoqtSessionTest, SubscribeAbsoluteStartNoDataYet) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  request.parameters.subscription_filter.emplace(Location(1, 0));
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
  // Window was not set to (0, 0) by SUBSCRIBE acceptance.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  listener->OnNewObjectAvailable(Location(0, 0), 0, kDefaultPublisherPriority);
}

TEST_F(MoqtSessionTest, SubscribeNextGroup) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  request.parameters.subscription_filter.emplace(
      MoqtFilterType::kNextGroupStart);
  SetLargestId(track, Location(10, 20));
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
  // Later objects in group 10 ignored.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .Times(0);
  listener->OnNewObjectAvailable(Location(10, 21), 0,
                                 kDefaultPublisherPriority);
  // Group 11 is sent.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  listener->OnNewObjectAvailable(Location(11, 0), 0, kDefaultPublisherPriority);
}

TEST_F(MoqtSessionTest, TwoSubscribesForTrack) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());

  request.request_id = 3;
  request.parameters.subscription_filter.emplace(Location(12, 0));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(request);
}

TEST_F(MoqtSessionTest, UnsubscribeAllowsSecondSubscribe) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());

  // Peer unsubscribes.
  MoqtUnsubscribe unsubscribe = {
      kDefaultPeerRequestId,
  };
  stream_input->ReceiveMessage(unsubscribe);
  EXPECT_FALSE(MoqtSessionPeer::RequestIdIsSubscriptionPublisher(&session_, 1));

  // Subscribe again, succeeds.
  request.request_id = 3;
  request.parameters.subscription_filter.emplace(Location(12, 0));
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get(),
                                /*track_alias=*/1);
}

TEST_F(MoqtSessionTest, RequestIdTooHigh) {
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = DefaultSubscribe();
  request.request_id = kDefaultInitialMaxRequestId + 1;

  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kTooManyRequests),
                           "Received request with too large ID"));
  stream_input->ReceiveMessage(request);
}

TEST_F(MoqtSessionTest, RequestIdWrongLsb) {
  // TODO(martinduke): Implement this test.
}

TEST_F(MoqtSessionTest, SubscribeIdNotIncreasing) {
  MoqtSubscribe request = DefaultSubscribe();
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  EXPECT_CALL(*track, AddObjectListener);
  stream_input->ReceiveMessage(request);

  // Second request is a protocol violation.
  request.full_track_name = FullTrackName({"dead", "beef"});
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kInvalidRequestId),
                           "Duplicate request ID"));
  stream_input->ReceiveMessage(request);
}

TEST_F(MoqtSessionTest, TooManySubscribes) {
  MoqtSessionPeer::set_next_request_id(&session_,
                                       kDefaultInitialMaxRequestId - 1);
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters(SubscribeForTest());
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestsBlocked), _))
      .Times(1);
  EXPECT_FALSE(session_.Subscribe(FullTrackName("foo2", "bar2"),
                                  &remote_track_visitor_, parameters));
  // Second time does not send requests_blocked.
  EXPECT_FALSE(session_.Subscribe(FullTrackName("foo2", "bar2"),
                                  &remote_track_visitor_, parameters));
}

TEST_F(MoqtSessionTest, SubscribeDuplicateTrackName) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters(SubscribeForTest());
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  EXPECT_FALSE(session_.Subscribe(FullTrackName("foo", "bar"),
                                  &remote_track_visitor_, parameters));
}

TEST_F(MoqtSessionTest, SubscribeWithOk) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters(SubscribeForTest());
  session_.Subscribe(FullTrackName("foo", "bar"), &remote_track_visitor_,
                     parameters);

  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*track_alias=*/2,
      MessageParameters(),
      TrackExtensions(),
  };
  EXPECT_CALL(remote_track_visitor_, OnReply)
      .WillOnce(
          [&](const FullTrackName& ftn,
              std::variant<SubscribeOkData, MoqtRequestErrorInfo> response) {
            EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(response));
          });
  stream_input->ReceiveMessage(ok);
}

TEST_F(MoqtSessionTest, SubscribeNextGroupWithOk) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSubscribe subscribe = DefaultLocalSubscribe();
  subscribe.parameters.subscription_filter.emplace(
      MoqtFilterType::kNextGroupStart);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(subscribe), _));
  session_.Subscribe(FullTrackName("foo", "bar"), &remote_track_visitor_,
                     subscribe.parameters);

  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*track_alias=*/2,
      MessageParameters(),
      TrackExtensions(),
  };
  EXPECT_CALL(remote_track_visitor_, OnReply)
      .WillOnce(
          [&](const FullTrackName& ftn,
              std::variant<SubscribeOkData, MoqtRequestErrorInfo> response) {
            EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(response));
          });
  stream_input->ReceiveMessage(ok);
}

TEST_F(MoqtSessionTest, OutgoingSubscribeUpdate) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById)
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters(SubscribeForTest());
  parameters.subscription_filter.emplace(Location(1, 0), 10);
  session_.Subscribe(FullTrackName("foo", "bar"), &remote_track_visitor_,
                     parameters);
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*track_alias=*/2,
      MessageParameters(),
      TrackExtensions(),
  };
  EXPECT_CALL(remote_track_visitor_, OnReply);
  stream_input->ReceiveMessage(ok);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestUpdate), _));
  MessageParameters update_parameters;
  update_parameters.subscription_filter.emplace(Location(2, 1), 9);
  // Set to a non-null value to ensure that the callback is called.
  std::optional<MoqtRequestErrorInfo> response =
      MoqtRequestErrorInfo{RequestErrorCode::kTimeout, std::nullopt, ""};
  EXPECT_TRUE(session_.SubscribeUpdate(
      FullTrackName("foo", "bar"), update_parameters,
      [&](std::optional<MoqtRequestErrorInfo> info) { response = info; }));
  stream_input->ReceiveMessage(MoqtRequestOk{
      /*request_id=*/2,
      MessageParameters(),
  });
  EXPECT_EQ(response, std::nullopt);
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 2);
  EXPECT_FALSE(track->InWindow(Location(2, 0)));
  EXPECT_TRUE(track->InWindow(Location(2, 1)));
  EXPECT_TRUE(track->InWindow(Location(9, UINT64_MAX)));
  EXPECT_FALSE(track->InWindow(Location(10, 0)));
}

TEST_F(MoqtSessionTest, OutgoingRequestUpdateInvalid) {
  // Wrong track name.
  EXPECT_FALSE(session_.SubscribeUpdate(
      FullTrackName("foo", "bar"), MessageParameters(),
      +[](std::optional<MoqtRequestErrorInfo>) {}));
}

TEST_F(MoqtSessionTest, MaxRequestIdChangesResponse) {
  MoqtSessionPeer::set_next_request_id(&session_, kDefaultInitialMaxRequestId);
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kRequestsBlocked), _));
  MessageParameters parameters(SubscribeForTest());
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_FALSE(session_.Subscribe(FullTrackName("foo", "bar"),
                                  &remote_track_visitor_, parameters));
  MoqtMaxRequestId max_request_id = {
      /*max_request_id=*/kDefaultInitialMaxRequestId + 1,
  };
  stream_input->ReceiveMessage(max_request_id);

  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
}

TEST_F(MoqtSessionTest, LowerMaxRequestIdIsAnError) {
  MoqtMaxRequestId max_request_id = {
      /*max_request_id=*/kDefaultInitialMaxRequestId - 1,
  };
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "MAX_REQUEST_ID has lower value than previous"))
      .Times(1);
  stream_input->ReceiveMessage(max_request_id);
}

TEST_F(MoqtSessionTest, GrantMoreRequests) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kMaxRequestId), _));
  session_.GrantMoreRequests(1);
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = DefaultSubscribe();
  request.request_id = kDefaultInitialMaxRequestId + 1;
  MockTrackPublisher* track = CreateTrackPublisher();
  ReceiveSubscribeSynchronousOk(track, request, stream_input.get());
}

TEST_F(MoqtSessionTest, SubscribeWithError) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters(SubscribeForTest());
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  session_.Subscribe(FullTrackName("foo", "bar"), &remote_track_visitor_,
                     parameters);

  MoqtRequestError error = {
      /*request_id=*/0,
      /*error_code=*/RequestErrorCode::kInvalidRange,
      /*retry_interval=*/std::nullopt,
      /*reason_phrase=*/"deadbeef",
  };
  EXPECT_CALL(remote_track_visitor_, OnReply)
      .WillOnce(
          [&](const FullTrackName& ftn,
              std::variant<SubscribeOkData, MoqtRequestErrorInfo> response) {
            EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
            EXPECT_TRUE(
                std::holds_alternative<MoqtRequestErrorInfo>(response) &&
                std::get<MoqtRequestErrorInfo>(response).reason_phrase ==
                    "deadbeef");
          });
  stream_input->ReceiveMessage(error);
}

TEST_F(MoqtSessionTest, Unsubscribe) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kUnsubscribe), _));
  EXPECT_NE(MoqtSessionPeer::remote_track(&session_, 2), nullptr);
  session_.Unsubscribe(FullTrackName("foo", "bar"));
  // State is destroyed.
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 2), nullptr);
}

TEST_F(MoqtSessionTest, ReplyToPublishNamespaceWithOkThenPublishNamespaceDone) {
  TrackNamespace track_namespace{"foo"};
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MessageParameters parameters;
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "foo");
  MoqtPublishNamespace publish_namespace = {
      kDefaultPeerRequestId,
      track_namespace,
      parameters,
  };
  EXPECT_CALL(session_callbacks_.incoming_publish_namespace_callback,
              Call(track_namespace, std::make_optional(parameters), _))
      .WillOnce([](const TrackNamespace&,
                   const std::optional<MessageParameters>&,
                   MoqtResponseCallback callback) {
        std::move(callback)(std::nullopt);
      });
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(MoqtRequestOk{
                         kDefaultPeerRequestId, MessageParameters()}),
                     _));
  stream_input->ReceiveMessage(publish_namespace);
  MoqtPublishNamespaceDone publish_namespace_done = {
      /*request_id=*/0,
  };
  EXPECT_CALL(session_callbacks_.incoming_publish_namespace_callback,
              Call(track_namespace, std::optional<MessageParameters>(), _))
      .WillOnce(
          [](const TrackNamespace&, const std::optional<MessageParameters>&,
             MoqtResponseCallback callback) { EXPECT_EQ(callback, nullptr); });
  stream_input->ReceiveMessage(publish_namespace_done);
}

TEST_F(MoqtSessionTest,
       ReplyToPublishNamespaceWithOkThenPublishNamespaceCancel) {
  TrackNamespace track_namespace{"foo"};

  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MessageParameters parameters;
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "foo");
  MoqtPublishNamespace publish_namespace = {
      kDefaultPeerRequestId,
      track_namespace,
      parameters,
  };
  EXPECT_CALL(session_callbacks_.incoming_publish_namespace_callback,
              Call(track_namespace, std::make_optional(parameters), _))
      .WillOnce([](const TrackNamespace&,
                   const std::optional<MessageParameters>&,
                   MoqtResponseCallback callback) {
        std::move(callback)(std::nullopt);
      });
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(MoqtRequestOk{
                         kDefaultPeerRequestId, MessageParameters()}),
                     _));
  stream_input->ReceiveMessage(publish_namespace);
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(MoqtPublishNamespaceCancel{
                         kDefaultPeerRequestId,
                         RequestErrorCode::kInternalError, "deadbeef"}),
                     _));
  session_.PublishNamespaceCancel(track_namespace,
                                  RequestErrorCode::kInternalError, "deadbeef");
}

TEST_F(MoqtSessionTest, ReplyToPublishNamespaceWithError) {
  TrackNamespace track_namespace{"foo"};

  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MessageParameters parameters;
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "foo");
  MoqtPublishNamespace publish_namespace = {
      kDefaultPeerRequestId,
      track_namespace,
      parameters,
  };
  MoqtRequestErrorInfo error = {
      RequestErrorCode::kNotSupported,
      /*retry_interval=*/std::nullopt,
      "deadbeef",
  };
  EXPECT_CALL(session_callbacks_.incoming_publish_namespace_callback,
              Call(track_namespace, std::make_optional(parameters), _))
      .WillOnce(
          [&](const TrackNamespace&, const std::optional<MessageParameters>&,
              MoqtResponseCallback callback) { std::move(callback)(error); });
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(MoqtRequestError{
                         kDefaultPeerRequestId, error.error_code,
                         error.retry_interval, error.reason_phrase}),
                     _));
  stream_input->ReceiveMessage(publish_namespace);
}

TEST_F(MoqtSessionTest, SubscribeNamespaceLifeCycle) {
  TrackNamespace prefix({"foo"});
  bool got_callback = false;
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingBidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<MoqtNamespaceSubscriberStream> stream_input;
  EXPECT_CALL(mock_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_input = absl::WrapUnique(
            absl::down_cast<MoqtNamespaceSubscriberStream*>(visitor.release()));
        ASSERT_NE(stream_input, nullptr);
      });
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeNamespace), _));
  std::unique_ptr<MoqtNamespaceTask> task = session_.SubscribeNamespace(
      prefix, SubscribeNamespaceOption::kNamespace, MessageParameters(),
      [&](std::optional<MoqtRequestErrorInfo> error) {
        got_callback = true;
        EXPECT_FALSE(error.has_value());
      });
  MoqtRequestOk ok = {kDefaultLocalRequestId, MessageParameters()};
  QUICHE_ASSERT_OK(stream_input->OnControlMessage(ok));
  EXPECT_TRUE(got_callback);
  EXPECT_CALL(mock_stream_, ResetWithUserCode);
}

TEST_F(MoqtSessionTest, SubscribeNamespaceError) {
  TrackNamespace prefix({"foo"});
  bool got_callback = false;
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingBidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<MoqtNamespaceSubscriberStream> stream_input;
  EXPECT_CALL(mock_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_input = std::unique_ptr<MoqtNamespaceSubscriberStream>(
            absl::down_cast<MoqtNamespaceSubscriberStream*>(visitor.release()));
        ASSERT_NE(stream_input, nullptr);
      });
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(
      mock_stream_,
      Writev(ControlMessageOfType(MoqtMessageType::kSubscribeNamespace), _));
  std::unique_ptr<MoqtNamespaceTask> task = session_.SubscribeNamespace(
      prefix, SubscribeNamespaceOption::kNamespace, MessageParameters(),
      [&](std::optional<MoqtRequestErrorInfo> error) {
        got_callback = true;
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, RequestErrorCode::kInvalidRange);
        EXPECT_EQ(error->reason_phrase, "deadbeef");
      });
  MoqtRequestError error = {kDefaultLocalRequestId,
                            RequestErrorCode::kInvalidRange, std::nullopt,
                            "deadbeef"};
  QUICHE_ASSERT_OK(stream_input->OnControlMessage(error));
  EXPECT_TRUE(got_callback);
}

TEST_F(MoqtSessionTest, SubscribeNamespacePublishOnly) {
  TrackNamespace prefix({"foo"});
  // kPublish is not allowed.
  EXPECT_EQ(session_.SubscribeNamespace(
                prefix, SubscribeNamespaceOption::kPublish, MessageParameters(),
                [&](std::optional<MoqtRequestErrorInfo>) {}),
            nullptr);
  // kBoth is treated as kNamespace.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingBidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(MoqtSubscribeNamespace{
                         0, prefix, SubscribeNamespaceOption::kNamespace,
                         MessageParameters()}),
                     _));
  EXPECT_NE(session_.SubscribeNamespace(
                prefix, SubscribeNamespaceOption::kBoth, MessageParameters(),
                [&](std::optional<MoqtRequestErrorInfo>) {}),
            nullptr);
}

TEST_F(MoqtSessionTest, IncomingObject) {
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*extension_headers=*/"foo",
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream_,
                                                kDefaultSubgroupStreamType, 2,
                                                &remote_track_visitor_);

  EXPECT_CALL(remote_track_visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    const absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(track_name, ftn);
        EXPECT_EQ(metadata.location, Location(0, 0));
        EXPECT_EQ(metadata.subgroup, 0);
        EXPECT_EQ(metadata.extensions, "foo");
        EXPECT_EQ(metadata.status, MoqtObjectStatus::kNormal);
        EXPECT_EQ(metadata.publisher_priority, 0);
        EXPECT_EQ(metadata.payload_length, payload.length());
        EXPECT_EQ(payload, received_payload);
        EXPECT_EQ(offset, 0);
      });
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, IncomingPartialObject) {
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
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
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream_,
                                                kDefaultSubgroupStreamType, 2,
                                                &remote_track_visitor_);

  EXPECT_CALL(remote_track_visitor_, OnObjectFragment).Times(1);
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
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
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
      MoqtSessionPeer::CreateIncomingDataStream(&session, &mock_stream_,
                                                kDefaultSubgroupStreamType, 2,
                                                &remote_track_visitor_);
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment(ftn, _, payload, 0));
  object_stream->OnObjectMessage(object, payload, false);
  EXPECT_CALL(remote_track_visitor_,
              OnObjectFragment(ftn, _, payload, payload.length()));
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
  // New object, check the offset was reset.
  ++object.object_id;
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment(ftn, _, payload, 0));
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeOk) {
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultLocalSubscribe(),
                                     std::nullopt, &remote_track_visitor_);
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
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream_,
                                                kDefaultSubgroupStreamType, 2);
  EXPECT_CALL(mock_stream_, SendStopSending);
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      kDefaultLocalRequestId,
      /*track_alias=*/2,
      MessageParameters(),
      TrackExtensions(),
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(remote_track_visitor_, OnReply).Times(1);
  control_stream->ReceiveMessage(ok);
}

TEST_F(MoqtSessionTest, SubscribeOkWithBadTrackAlias) {
  // Create open subscription. We cannot use CreateRemoteTrack because that
  // skips the code that sets the track alias callbacks.
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  session_.Subscribe(FullTrackName("foo", "bar"), &remote_track_visitor_,
                     MessageParameters());
  MoqtSubscribeOk subscribe_ok = {
      /*request_id=*/0,
      /*track_alias=*/2,
      MessageParameters(),
      TrackExtensions(),
  };
  control_stream->ReceiveMessage(subscribe_ok);
  // Second subscribe, but OK has the same track alias.
  session_.Subscribe(FullTrackName("foo2", "bar2"), &remote_track_visitor_,
                     MessageParameters());
  subscribe_ok.request_id += 2;
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kDuplicateTrackAlias), ""));
  control_stream->ReceiveMessage(subscribe_ok);
}

TEST_F(MoqtSessionTest, ReceiveUnsubscribe) {
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtSubscribe request = DefaultSubscribe();
  const MoqtPriority kLocalDefaultPriority = 0x20;
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  TrackExtensions extensions(std::nullopt, std::nullopt, kLocalDefaultPriority,
                             std::nullopt, std::nullopt, std::nullopt);
  EXPECT_CALL(*track, extensions)
      .WillRepeatedly(testing::ReturnRef(extensions));
  MoqtObjectListener* listener = ReceiveSubscribeSynchronousOk(
      track, request, control_stream.get(), /*track_alias=*/0, extensions);
  MoqtUnsubscribe unsubscribe = {/*request_id=*/1};
  EXPECT_CALL(*track, RemoveObjectListener(listener));
  control_stream->ReceiveMessage(unsubscribe);
}

TEST_F(MoqtSessionTest, ReceiveDatagram) {
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
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
  char datagram[] = {0x00, 0x02, 0x00, 0x00, 0x00, 0x64, 0x65,
                     0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName& track_name,
                    const PublishedObjectMetadata& metadata,
                    absl::string_view received_payload, uint64_t offset) {
        EXPECT_EQ(track_name, ftn);
        EXPECT_EQ(metadata.location,
                  Location(object.group_id, object.object_id));
        EXPECT_EQ(metadata.subgroup, object.subgroup_id);
        EXPECT_EQ(metadata.publisher_priority, object.publisher_priority);
        EXPECT_EQ(metadata.status, object.object_status);
        EXPECT_EQ(metadata.payload_length, payload.length());
        EXPECT_EQ(payload, received_payload);
        EXPECT_EQ(offset, 0);
      });
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, UsePeerDefaultPriority) {
  FullTrackName ftn("foo", "bar");
  const MoqtPriority kPeerDefaultPriority = 0x20;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  session_.Subscribe(ftn, &remote_track_visitor_, MessageParameters());
  MoqtSubscribeOk ok;
  ok.request_id = 0;
  ok.track_alias = 2;
  ok.extensions =
      TrackExtensions(std::nullopt, std::nullopt, kPeerDefaultPriority,
                      std::nullopt, std::nullopt, std::nullopt);
  EXPECT_CALL(remote_track_visitor_, OnReply);
  stream_input->ReceiveMessage(ok);
  // Omit priority from a datagram.
  char datagram[] = {0x0c, 0x02, 0x05, 0x64, 0x65, 0x61,
                     0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName&,
                    const PublishedObjectMetadata& metadata, absl::string_view,
                    uint64_t offset) {
        EXPECT_EQ(metadata.publisher_priority, kPeerDefaultPriority);
        EXPECT_EQ(metadata.payload_length, 8u);
        EXPECT_EQ(offset, 0);
      });
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
  // Omit priority from a stream.
  webtransport::test::InMemoryStream in_memory_stream(2);
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor =
      MoqtSessionPeer::CreateIncomingStreamVisitor(&session_,
                                                   &in_memory_stream);
  in_memory_stream.SetVisitor(std::move(stream_visitor));
  char stream_data[] = {0x30, 0x02, 0x06, 0x00, 0x03, 0x66, 0x6f, 0x6f};
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment)
      .WillOnce([&](const FullTrackName&,
                    const PublishedObjectMetadata& metadata, absl::string_view,
                    uint64_t offset) {
        EXPECT_EQ(metadata.publisher_priority, kPeerDefaultPriority);
        EXPECT_EQ(metadata.payload_length, 3u);
        EXPECT_EQ(offset, 0);
      });
  in_memory_stream.Receive(absl::string_view(stream_data, sizeof(stream_data)),
                           false);
}

TEST_F(MoqtSessionTest, OmitPublisherPriority) {
  MoqtSubscribe request = DefaultSubscribe();
  const MoqtPriority kLocalDefaultPriority = 0x20;
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  // Create the publisher and the SUBSCRIBE with kLocalDefaultPriority.
  MockTrackPublisher* track = CreateTrackPublisher();
  std::make_shared<MockTrackPublisher>(request.full_track_name);
  TrackExtensions extensions(std::nullopt, std::nullopt, kLocalDefaultPriority,
                             std::nullopt, std::nullopt, std::nullopt);
  EXPECT_CALL(*track, extensions)
      .WillRepeatedly(testing::ReturnRef(extensions));
  MoqtObjectListener* listener = ReceiveSubscribeSynchronousOk(
      track, request, control_stream.get(), /*track_alias=*/0, extensions);

  // Deliver an object with kLocalDefaultPriority; stream_type will omit
  // the priority.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_, GetStreamId()).WillRepeatedly(Return(1));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, SetPriority);
  EXPECT_CALL(mock_stream_, visitor()).WillRepeatedly([&]() {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(*track, GetCachedObject(_, _, _, _))
      .WillOnce(Return(PublishedObject{
          PublishedObjectMetadata{
              Location(0, 0), 0, "", MoqtObjectStatus::kNormal,
              kLocalDefaultPriority, 8, MoqtSessionPeer::Now(&session_)},
          PayloadFromString("deadbeef")}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream_, Writev)
      .WillOnce([&](absl::Span<quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        // The stream type omits the priority.
        EXPECT_TRUE(static_cast<const uint8_t>(data[0].AsStringView()[0]) &
                    MoqtDataStreamType::kDefaultPriority);
        return absl::OkStatus();
      });
  listener->OnNewObjectAvailable(Location(0, 0), 0, kLocalDefaultPriority);
  // Send a datagram with the default priority.
  EXPECT_CALL(*track, GetCachedObject(_, _, _, _))
      .WillOnce(Return(PublishedObject{
          PublishedObjectMetadata{
              Location(0, 1), std::nullopt, "", MoqtObjectStatus::kNormal,
              kLocalDefaultPriority, 8, MoqtSessionPeer::Now(&session_)},
          PayloadFromString("deadbeef")}));
  EXPECT_CALL(mock_session_, SendOrQueueDatagram)
      .WillOnce([](absl::string_view datagram) {
        EXPECT_TRUE(static_cast<const uint8_t>(datagram[0]) &
                    MoqtDatagramType::kDefaultPriority);
        return webtransport::DatagramStatus{
            webtransport::DatagramStatusCode::kSuccess, ""};
      });
  listener->OnNewObjectAvailable(Location(0, 1), std::nullopt,
                                 kLocalDefaultPriority);
  // Non-default priority
  EXPECT_CALL(*track, GetCachedObject(_, _, _, _))
      .WillOnce(Return(PublishedObject{
          PublishedObjectMetadata{
              Location(0, 2), std::nullopt, "", MoqtObjectStatus::kNormal,
              kLocalDefaultPriority + 1, 8, MoqtSessionPeer::Now(&session_)},
          PayloadFromString("deadbeef")}));
  EXPECT_CALL(mock_session_, SendOrQueueDatagram)
      .WillOnce([](absl::string_view datagram) {
        EXPECT_FALSE(static_cast<const uint8_t>(datagram[0]) &
                     MoqtDatagramType::kDefaultPriority);
        return webtransport::DatagramStatus{
            webtransport::DatagramStatusCode::kSuccess, ""};
      });
  listener->OnNewObjectAvailable(Location(0, 2), std::nullopt,
                                 kLocalDefaultPriority + 1);
}

TEST_F(MoqtSessionTest, StreamObjectOutOfWindow) {
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = DefaultSubscribe();
  subscribe.parameters.subscription_filter.emplace(Location(1, 0));
  MoqtSessionPeer::CreateRemoteTrack(&session_, subscribe, /*track_alias=*/2,
                                     &remote_track_visitor_);
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
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream_,
                                                kDefaultSubgroupStreamType, 2,
                                                &remote_track_visitor_);
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment).Times(0);
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, DatagramOutOfWindow) {
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = DefaultSubscribe();
  subscribe.parameters.subscription_filter.emplace(Location(1, 0));
  MoqtSessionPeer::CreateRemoteTrack(&session_, subscribe, /*track_alias=*/2,
                                     &remote_track_visitor_);
  char datagram[] = {0x01, 0x02, 0x00, 0x00, 0x80, 0x00, 0x08, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment).Times(0);
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, UpdateTrackPriority) {
  session_.UpdateTrackPriority(0, std::nullopt, MoqtTrackPriority{0x40, 0x82});
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 0);
  // Same track, higher priority.
  session_.UpdateTrackPriority(0, MoqtTrackPriority{0x40, 0x82},
                               MoqtTrackPriority{0x40, 0x80});
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 0);
  // New track, higher priority.
  session_.UpdateTrackPriority(2, std::nullopt, MoqtTrackPriority{0x20, 0x82});
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 2);
  // Pop request ID 2 from the queue.  The subscription doesn't really exist, so
  // nothing else happens.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 0);
  // There's another stream for request ID 2.
  session_.UpdateTrackPriority(2, std::nullopt, MoqtTrackPriority{0x20, 0x81});
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 2);
  // The subscriber demotes track 2. Track 0 is first now due to higher
  // publisher priority.
  session_.UpdateTrackPriority(2, MoqtTrackPriority{0x20, 0x81},
                               MoqtTrackPriority{0x40, 0x81});
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true))
      .WillOnce(Return(false));
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
  // The subscription will update with the first stream. It's lower priority
  // than request ID 2.
  session_.UpdateTrackPriority(0, std::nullopt, MoqtTrackPriority{0x40, 0x82});
  EXPECT_EQ(MoqtSessionPeer::NextQueuedRequestIdToServer(&session_), 2);
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
      .WillOnce(Return(true))
      .WillRepeatedly(Return(false));
  EXPECT_CALL(session, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_stream));
  EXPECT_CALL(data_stream, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
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
      .WillOnce([=](PublishedObject& output) {
        output.metadata.location = location;
        output.metadata.subgroup = 0;
        output.metadata.status = status;
        output.metadata.publisher_priority = 128;
        output.metadata.payload_length = payload.length();
        output.payload = PayloadFromString(payload);
        output.fin_after_this = true;  // should be ignored.
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce([=](PublishedObject& /*output*/) { return second_result; });
  if (second_result == MoqtFetchTask::GetNextObjectResult::kEof) {
    EXPECT_CALL(data_stream, Writev)
        .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                     const webtransport::StreamWriteOptions& options) {
          quic::QuicDataReader reader(data[0].AsStringView());
          uint64_t type;
          EXPECT_TRUE(reader.ReadVarInt62(&type));
          EXPECT_EQ(type, MoqtDataStreamType::Fetch().value());
          EXPECT_FALSE(options.send_fin());  // fin_after_this is ignored.
          return absl::OkStatus();
        })
        .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                     const webtransport::StreamWriteOptions& options) {
          EXPECT_TRUE(data.empty());
          EXPECT_TRUE(options.send_fin());
          return absl::OkStatus();
        });
    return;
  }
  EXPECT_CALL(data_stream, Writev)
      .WillOnce([](absl::Span<quiche::QuicheMemSlice> data,
                   const webtransport::StreamWriteOptions& options) {
        quic::QuicDataReader reader(data[0].AsStringView());
        uint64_t type;
        EXPECT_TRUE(reader.ReadVarInt62(&type));
        EXPECT_EQ(type, MoqtDataStreamType::Fetch().value());
        EXPECT_FALSE(options.send_fin());  // fin_after_this is ignored.
        return absl::OkStatus();
      });
  if (second_result == MoqtFetchTask::GetNextObjectResult::kError) {
    EXPECT_CALL(data_stream, ResetWithUserCode);
  }
}
}  // namespace

// All callbacks are called asynchronously.
TEST_F(MoqtSessionTest, ProcessFetchGetEverythingFromUpstream) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  // No callbacks are synchronous. MockFetchTask will store the callbacks.
  auto fetch_task_ptr = std::make_unique<MockFetchTask>();
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::move(fetch_task_ptr)));
  stream_input->ReceiveMessage(fetch);

  // Compose and send the FETCH_OK.
  MoqtFetchOk expected_ok;
  expected_ok.request_id = fetch.request_id;
  expected_ok.end_of_track = false;
  expected_ok.end_location = Location(1, 4);
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
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  MoqtFetchOk expected_ok;
  expected_ok.request_id = fetch.request_id;
  expected_ok.end_of_track = false;
  expected_ok.end_location = Location(1, 4);
  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(expected_ok, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::move(fetch_task_ptr)));
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  // Everything spins upon message receipt. FetchTask is generating the
  // necessary callbacks.
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, SendFragmentedFetchObject) {
  using ::testing::ByMove;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  fetch.request_id = 3;  // Use an odd ID for peer request in client session.
  MockTrackPublisher* track = CreateTrackPublisher();

  // Disable synchronous callback to have more control.
  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, false);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(ByMove(std::move(fetch_task_ptr))));

  // Receive FETCH, send FETCH_OK.
  stream_input->ReceiveMessage(fetch);
  // FETCH_OK responding to the request.
  MoqtFetchOk expected_ok;
  expected_ok.request_id = fetch.request_id;
  expected_ok.end_of_track = false;
  expected_ok.end_location = Location(1, 0);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
  fetch_task->CallFetchResponseCallback(expected_ok);

  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream)
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&data_stream));
  EXPECT_CALL(data_stream, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(data_stream, SetPriority);
  EXPECT_CALL(data_stream, CanWrite).WillRepeatedly(Return(true));
  // Trigger stream opening (calls SetObjectAvailableCallback with lambda1).
  // Setting the stream visitor will cause a second call to the callback.
  PublishedObjectMetadata metadata = {
      Location(0, 0), 0, "", MoqtObjectStatus::kNormal, 128, 10};
  EXPECT_CALL(*fetch_task, GetNextObject)
      .WillOnce([&](PublishedObject& output) {
        output.metadata = metadata;
        output.payload = PayloadFromString("part1");
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillOnce(Return(MoqtFetchTask::GetNextObjectResult::kPending));
  EXPECT_CALL(data_stream, Writev)
      .WillOnce([&](absl::Span<const quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(data.size(), 2);
        EXPECT_EQ(data[1].AsStringView(), "part1");
        return absl::OkStatus();
      });
  fetch_task->CallObjectsAvailableCallback();
  // lambda1 ran, data_stream captured, stream_visitor set.
  ASSERT_NE(stream_visitor, nullptr);

  // The second fragment is available.
  EXPECT_CALL(*fetch_task, GetNextObject)
      .WillOnce([&](PublishedObject& output) {
        output.metadata = metadata;
        output.payload = PayloadFromString("part2");
        return MoqtFetchTask::GetNextObjectResult::kSuccess;
      })
      .WillRepeatedly(Return(MoqtFetchTask::GetNextObjectResult::kPending));
  EXPECT_CALL(data_stream, Writev)
      .WillOnce([&](absl::Span<const quiche::QuicheMemSlice> data,
                    const webtransport::StreamWriteOptions& options) {
        EXPECT_EQ(data.size(), 1);  // No header.
        EXPECT_EQ(data[0].AsStringView(), "part2");
        return absl::OkStatus();
      });
  fetch_task->CallObjectsAvailableCallback();
}

// The publisher has the first object locally, but has to go upstream to get
// the rest.
TEST_F(MoqtSessionTest, FetchReturnsObjectBeforeOk) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  // Object returns synchronously.
  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::move(fetch_task_ptr)));
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  stream_input->ReceiveMessage(fetch);

  MoqtFetchOk expected_ok;
  expected_ok.request_id = fetch.request_id;
  expected_ok.end_of_track = false;
  expected_ok.end_location = Location(1, 4);
  EXPECT_CALL(mock_stream_, Writev(SerializedControlMessage(expected_ok), _));
  fetch_task->CallFetchResponseCallback(expected_ok);
}

TEST_F(MoqtSessionTest, FetchReturnsObjectBeforeError) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::move(fetch_task_ptr)));
  webtransport::test::MockStream data_stream;
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  ExpectStreamOpen(mock_session_, fetch_task, data_stream, stream_visitor);
  ExpectSendObject(fetch_task, data_stream, MoqtObjectStatus::kNormal,
                   Location(0, 0), "foo",
                   MoqtFetchTask::GetNextObjectResult::kPending);
  stream_input->ReceiveMessage(fetch);

  MoqtRequestError expected_error{
      fetch.request_id, RequestErrorCode::kDoesNotExist, std::nullopt, "foo"};
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_error), _));
  fetch_task->CallFetchResponseCallback(expected_error);
}

TEST_F(MoqtSessionTest, InvalidFetch) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  MockTrackPublisher* track = CreateTrackPublisher();
  MoqtFetch fetch = DefaultFetch();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::make_unique<MockFetchTask>()));
  stream_input->ReceiveMessage(fetch);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kInvalidRequestId),
                           "Duplicate request ID"))
      .Times(1);
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, FetchFails) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  auto fetch_task_ptr = std::make_unique<MockFetchTask>();
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::move(fetch_task_ptr)));
  EXPECT_CALL(*fetch_task, GetStatus())
      .WillRepeatedly(Return(absl::Status(absl::StatusCode::kInternal, "foo")));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, FullFetchDeliveryWithFlowControl) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  MockTrackPublisher* track = CreateTrackPublisher();

  auto fetch_task_ptr =
      std::make_unique<MockFetchTask>(std::nullopt, std::nullopt, true);
  MockFetchTask* fetch_task = fetch_task_ptr.get();
  EXPECT_CALL(*track, StandaloneFetch)
      .WillOnce(Return(std::move(fetch_task_ptr)));

  stream_input->ReceiveMessage(fetch);
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

TEST_F(MoqtSessionTest, IncomingRelativeJoiningFetch) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  // Give it the latest object filter.
  subscribe.parameters.subscription_filter.emplace(
      MoqtFilterType::kLargestObject);
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(4, 10));
  ReceiveSubscribeSynchronousOk(track, subscribe, stream_input.get());

  ASSERT_TRUE(MoqtSessionPeer::RequestIdIsSubscriptionPublisher(
      &session_, subscribe.request_id));
  MoqtFetch fetch = DefaultFetch();
  fetch.request_id = 3;
  fetch.fetch = JoiningFetchRelative(1, 2);
  EXPECT_CALL(*track, StandaloneFetch(Location(2, 0), Location(4, 10), _))
      .WillOnce(Return(std::make_unique<MockFetchTask>()));
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, IncomingAbsoluteJoiningFetch) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  // Give it the latest object filter.
  subscribe.parameters.subscription_filter.emplace(
      MoqtFilterType::kLargestObject);
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(4, 10));
  ReceiveSubscribeSynchronousOk(track, subscribe, stream_input.get());

  ASSERT_TRUE(MoqtSessionPeer::RequestIdIsSubscriptionPublisher(
      &session_, subscribe.request_id));
  MoqtFetch fetch = DefaultFetch();
  fetch.request_id = 3;
  fetch.fetch = JoiningFetchAbsolute(1, 2);
  EXPECT_CALL(*track, StandaloneFetch(Location(2, 0), Location(4, 10), _))
      .WillOnce(Return(std::make_unique<MockFetchTask>()));
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, IncomingJoiningFetchBadRequestId) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtFetch fetch = DefaultFetch();
  fetch.fetch = JoiningFetchRelative(1, 2);
  MoqtRequestError expected_error = {
      /*request_id=*/1,
      RequestErrorCode::kInvalidJoiningRequestId,
      /*retry_interval=*/std::nullopt,
      "Joining Fetch for non-existent request",
  };
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_error), _));
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, IncomingJoiningFetchForwardZero) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  subscribe.parameters.set_forward(false);
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  SetLargestId(track, Location(2, 10));
  ReceiveSubscribeSynchronousOk(track, subscribe, stream_input.get());

  MoqtFetch fetch = DefaultFetch();
  fetch.request_id = 3;
  fetch.fetch = JoiningFetchRelative(1, 2);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Joining Fetch for non-forwarding subscribe"))
      .Times(1);
  stream_input->ReceiveMessage(fetch);
}

TEST_F(MoqtSessionTest, SendJoiningFetch) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  MoqtSubscribe expected_subscribe(
      0, FullTrackName("foo", "bar"),
      MessageParameters(MoqtFilterType::kLargestObject));
  MoqtFetch expected_fetch = {
      /*request_id=*/2,
      /*fetch=*/JoiningFetchRelative(0, 1),
      MessageParameters(),
  };
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_subscribe), _));
  EXPECT_CALL(mock_stream_,
              Writev(SerializedControlMessage(expected_fetch), _));
  EXPECT_TRUE(session_.RelativeJoiningFetch(expected_subscribe.full_track_name,
                                            &remote_track_visitor_, nullptr, 1,
                                            MessageParameters()));
}

TEST_F(MoqtSessionTest, SendJoiningFetchNoFlowControl) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&mock_stream_));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetch), _));
  EXPECT_TRUE(session_.RelativeJoiningFetch(FullTrackName("foo", "bar"),
                                            &remote_track_visitor_, 0,
                                            MessageParameters()));

  EXPECT_CALL(remote_track_visitor_, OnReply).Times(1);
  MessageParameters parameters;
  parameters.largest_object = Location(2, 0);
  stream_input->ReceiveMessage(
      MoqtSubscribeOk(0, 2, parameters, TrackExtensions()));
  stream_input->ReceiveMessage(MoqtFetchOk(
      2, false, Location(2, 0), MessageParameters(), TrackExtensions()));
  // Packet arrives on FETCH stream.
  MoqtObject object = {
      /*request_id=*/2,
      /*group_id, object_id=*/2,
      0,
      /*publisher_priority=*/128,
      /*extension_headers=*/"",
      /*status=*/MoqtObjectStatus::kNormal,
      /*subgroup=*/0,
      /*payload_length=*/3,
  };
  MoqtFramer framer(true);
  std::optional<PublishedObjectMetadata> metadata;
  quiche::QuicheBuffer header = framer.SerializeObjectHeader(
      object, MoqtDataStreamType::Fetch(), metadata);
  webtransport::test::InMemoryStream data_stream(kIncomingUniStreamId);
  data_stream.SetVisitor(
      MoqtSessionPeer::CreateIncomingStreamVisitor(&session_, &data_stream));
  data_stream.Receive(header.AsStringView(), false);
  EXPECT_CALL(remote_track_visitor_, OnObjectFragment).Times(1);
  // Last object of the FETCH causes FETCH_CANCEL.
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchCancel), _));
  data_stream.Receive("foo", false);
}

TEST_F(MoqtSessionTest, IncomingSubscribeNamespace) {
  TrackNamespace prefix{"foo"};
  MessageParameters parameters;
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "foo");
  auto bidi_stream =
      std::make_unique<webtransport::test::InMemoryStreamWithWriteBuffer>(4);
  MoqtFramer framer(true);
  MoqtSubscribeNamespace subscribe_namespace = {
      /*request_id=*/1, prefix, SubscribeNamespaceOption::kBoth, parameters};
  bidi_stream->Receive(
      framer.SerializeSubscribeNamespace(subscribe_namespace).AsStringView(),
      /*fin=*/false);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(bidi_stream.get()))
      .WillOnce(Return(nullptr));
  quiche::QuicheWeakPtr<MockNamespaceTask> task;
  EXPECT_CALL(session_callbacks_.incoming_subscribe_namespace_callback,
              Call(prefix, SubscribeNamespaceOption::kBoth, parameters, _))
      .WillOnce([&](const TrackNamespace& prefix, SubscribeNamespaceOption,
                    const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(std::nullopt);
        auto task_ptr = std::make_unique<MockNamespaceTask>(prefix);
        task = task_ptr->GetWeakPtr();
        return task_ptr;
      });
  session_.OnIncomingBidirectionalStreamAvailable();
  EXPECT_EQ(PeekControlMessageType(bidi_stream->write_buffer()),
            MoqtMessageType::kRequestOk);
  bidi_stream->write_buffer().clear();

  // Deliver a NAMESPACE
  ASSERT_TRUE(task.IsValid());
  EXPECT_CALL(*task.GetIfAvailable(), GetNextSuffix)
      .WillOnce([](TrackNamespace& prefix, TransactionType& type) {
        prefix = TrackNamespace({"bar"});
        type = TransactionType::kAdd;
        return GetNextResult::kSuccess;
      })
      .WillOnce(Return(GetNextResult::kPending));
  task.GetIfAvailable()->InvokeCallback();
  char expected_data[] = {0x08, 0x00, 0x05, 0x01, 0x03, 'b', 'a', 'r'};
  absl::string_view expected_data_view(expected_data, sizeof(expected_data));
  EXPECT_EQ(expected_data_view,
            bidi_stream->write_buffer().substr(0, expected_data_view.length()));

  // Unsubscribe
  bidi_stream.reset();
  EXPECT_FALSE(task.IsValid());
}

TEST_F(MoqtSessionTest, IncomingSubscribeNamespaceWithSynchronousError) {
  TrackNamespace prefix{"foo"};
  MessageParameters parameters;
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "foo");
  webtransport::test::InMemoryStreamWithWriteBuffer bidi_stream(4);
  MoqtFramer framer(true);
  MoqtSubscribeNamespace subscribe_namespace = {
      /*request_id=*/1, prefix, SubscribeNamespaceOption::kBoth, parameters};
  bidi_stream.Receive(
      framer.SerializeSubscribeNamespace(subscribe_namespace).AsStringView(),
      /*fin=*/false);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&bidi_stream))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(session_callbacks_.incoming_subscribe_namespace_callback,
              Call(prefix, SubscribeNamespaceOption::kBoth, parameters, _))
      .WillOnce([&](const TrackNamespace&, SubscribeNamespaceOption,
                    const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(MoqtRequestErrorInfo{
            RequestErrorCode::kUnauthorized, std::nullopt, "foo"});
        return nullptr;
      });
  session_.OnIncomingBidirectionalStreamAvailable();
  EXPECT_EQ(PeekControlMessageType(bidi_stream.write_buffer()),
            MoqtMessageType::kRequestError);
  EXPECT_TRUE(bidi_stream.fin_sent());
}

TEST_F(MoqtSessionTest, IncomingSubscribeNamespaceWithPrefixOverlap) {
  TrackNamespace foo{"foo"}, foobar{"foo", "bar"};
  MessageParameters parameters;
  parameters.authorization_tokens.emplace_back(AuthTokenType::kOutOfBand,
                                               "foo");
  webtransport::test::InMemoryStreamWithWriteBuffer bidi_stream1(4),
      bidi_stream2(8);
  MoqtFramer framer(true);
  MoqtSubscribeNamespace subscribe_namespace = {
      /*request_id=*/1, foo, SubscribeNamespaceOption::kBoth, parameters};
  bidi_stream1.Receive(
      framer.SerializeSubscribeNamespace(subscribe_namespace).AsStringView(),
      /*fin=*/false);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&bidi_stream1))
      .WillOnce(Return(nullptr));
  EXPECT_CALL(session_callbacks_.incoming_subscribe_namespace_callback,
              Call(foo, SubscribeNamespaceOption::kBoth, parameters, _))
      .WillOnce([&](const TrackNamespace& prefix, SubscribeNamespaceOption,
                    const MessageParameters&,
                    MoqtResponseCallback response_callback) {
        std::move(response_callback)(std::nullopt);
        auto task_ptr = std::make_unique<MockNamespaceTask>(prefix);
        return task_ptr;
      });
  session_.OnIncomingBidirectionalStreamAvailable();
  EXPECT_EQ(PeekControlMessageType(bidi_stream1.write_buffer()),
            MoqtMessageType::kRequestOk);

  subscribe_namespace.request_id += 2;
  subscribe_namespace.track_namespace_prefix = foobar;
  bidi_stream2.Receive(
      framer.SerializeSubscribeNamespace(subscribe_namespace).AsStringView(),
      /*fin=*/false);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&bidi_stream2))
      .WillOnce(Return(nullptr));
  session_.OnIncomingBidirectionalStreamAvailable();
  EXPECT_EQ(PeekControlMessageType(bidi_stream2.write_buffer()),
            MoqtMessageType::kRequestError);
  EXPECT_TRUE(bidi_stream2.fin_sent());
}

TEST_F(MoqtSessionTest, FetchThenOkThenCancel) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  std::unique_ptr<MoqtFetchTask> fetch_task;
  session_.Fetch(
      FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task = std::move(task);
      },
      Location(0, 0), 4, std::nullopt, MessageParameters());
  MoqtFetchOk ok = {
      /*request_id=*/0,
      /*end_of_track=*/false, Location(3, 25),
      MessageParameters(),    TrackExtensions(),
  };
  stream_input->ReceiveMessage(ok);
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
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  std::unique_ptr<MoqtFetchTask> fetch_task;
  session_.Fetch(
      FullTrackName("foo", "bar"),
      [&](std::unique_ptr<MoqtFetchTask> task) {
        fetch_task = std::move(task);
      },
      Location(0, 0), 4, std::nullopt, MessageParameters());
  MoqtRequestError error = {
      /*request_id=*/0,
      RequestErrorCode::kUnauthorized,
      /*retry_interval=*/std::nullopt,
      "No username provided",
  };
  stream_input->ReceiveMessage(error);
  ASSERT_NE(fetch_task, nullptr);
  EXPECT_TRUE(absl::IsPermissionDenied(fetch_task->GetStatus()));
  EXPECT_EQ(fetch_task->GetStatus().message(), "No username provided");
}

// The application takes objects as they arrive.
TEST_F(MoqtSessionTest, IncomingFetchObjectsGreedyApp) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
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
              EXPECT_EQ(object.metadata.location.object, expected_object_id);
              ++expected_object_id;
            }
            if (result == MoqtFetchTask::GetNextObjectResult::kError) {
              break;
            }
          } while (result != MoqtFetchTask::GetNextObjectResult::kPending);
        });
      },
      Location(0, 0), 4, std::nullopt, MessageParameters());
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
  MoqtFramer framer_(true);
  std::optional<PublishedObjectMetadata> metadata;
  for (int i = 0; i < 4; ++i) {
    object.object_id = i;
    headers.push(framer_.SerializeObjectHeader(
        object, MoqtDataStreamType::Fetch(), metadata));
    metadata = PublishedObjectMetadata();
    metadata->location.object = i;  // only object ID matters.
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
      /*end_of_track=*/false,
      /*end_location=*/Location(3, 25),
      MessageParameters(),
      TrackExtensions(),
  };
  stream_input->ReceiveMessage(ok);
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
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
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
      Location(0, 0), 4, std::nullopt, MessageParameters());
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
  MoqtFramer framer_(true);
  std::optional<PublishedObjectMetadata> metadata;
  for (int i = 0; i < 4; ++i) {
    object.object_id = i;
    headers.push(framer_.SerializeObjectHeader(
        object, MoqtDataStreamType::Fetch(), metadata));
    metadata = PublishedObjectMetadata();
    metadata->location.object = i;  // only object ID matters.
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
      /*end_of_track=*/false, Location(3, 25),
      MessageParameters(),    TrackExtensions(),
  };
  stream_input->ReceiveMessage(ok);
  ASSERT_NE(fetch_task, nullptr);
  EXPECT_TRUE(objects_available);

  // Get the objects
  MoqtFetchTask::GetNextObjectResult result;
  do {
    PublishedObject new_object;
    result = fetch_task->GetNextObject(new_object);
    if (result == MoqtFetchTask::GetNextObjectResult::kSuccess) {
      EXPECT_EQ(new_object.metadata.location.object, expected_object_id);
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
      EXPECT_EQ(new_object.metadata.location.object, expected_object_id);
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
      absl::down_cast<UpstreamFetch::UpstreamFetchTask*>(fetch_task.get());
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
  MoqtFramer framer_(true);
  std::optional<PublishedObjectMetadata> metadata;
  quiche::QuicheBuffer header = framer_.SerializeObjectHeader(
      object, MoqtDataStreamType::Fetch(), metadata);
  stream.Receive(header.AsStringView(), false);
  EXPECT_FALSE(task->HasObject());
  EXPECT_FALSE(object_ready);
  stream.Receive("foo", false);
  EXPECT_TRUE(task->HasObject());
  EXPECT_TRUE(task->NeedsMorePayload());
  EXPECT_TRUE(object_ready);
  object_ready = false;
  stream.Receive("bar", false);
  EXPECT_FALSE(object_ready);  // No second call to the callback.
  EXPECT_TRUE(task->HasObject());
  EXPECT_FALSE(task->NeedsMorePayload());
  task->SetObjectAvailableCallback(nullptr);
}

TEST_F(MoqtSessionTest, DeliveryTimeoutParameter) {
  MoqtSubscribe request = DefaultSubscribe();
  request.parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MockTrackPublisher* track = CreateTrackPublisher();
  ReceiveSubscribeSynchronousOk(track, request, control_stream.get());
  std::optional<quic::QuicTimeDelta> delivery_timeout =
      MoqtSessionPeer::GetDeliveryTimeout(&session_, request.request_id);
  EXPECT_TRUE(delivery_timeout.has_value() &&
              *delivery_timeout == quic::QuicTimeDelta::FromSeconds(1));
}

TEST_F(MoqtSessionTest, ReceiveGoAwayEnforcement) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(session_callbacks_.goaway_received_callback, Call("foo"));
  stream_input->ReceiveMessage(MoqtGoAway("foo"));
  // New requests not allowed.
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_FALSE(session_.Subscribe(FullTrackName("foo", "bar"),
                                  &remote_track_visitor_, parameters));
  TrackNamespace prefix({"foo"});
  EXPECT_EQ(
      session_.SubscribeNamespace(
          prefix, SubscribeNamespaceOption::kNamespace, MessageParameters(),
          +[](std::optional<MoqtRequestErrorInfo>) {}),
      nullptr);
  session_.PublishNamespace(
      TrackNamespace{"foo"}, MessageParameters(),
      +[](std::optional<MoqtRequestErrorInfo>) {},
      +[](MoqtRequestErrorInfo) {});
  EXPECT_FALSE(session_.Fetch(
      FullTrackName{TrackNamespace({"foo"}), "bar"},
      +[](std::unique_ptr<MoqtFetchTask>) {}, Location(0, 0), 5, std::nullopt,
      MessageParameters()));
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
  stream_input->ReceiveMessage(MoqtGoAway("foo"));
}

TEST_F(MoqtSessionTest, SendGoAwayEnforcement) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  CreateTrackPublisher();
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kGoAway), _));
  session_.GoAway("");
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(DefaultSubscribe());
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(
      MoqtPublishNamespace(3, TrackNamespace({"foo"}), MessageParameters()));
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  MoqtFetch fetch = DefaultFetch();
  fetch.request_id = 5;
  stream_input->ReceiveMessage(fetch);

  MoqtFramer framer(true);
  SessionNamespaceTree tree;
  MoqtIncomingSubscribeNamespaceCallback callback =
      DefaultIncomingSubscribeNamespaceCallback;
  MoqtNamespacePublisherStream namespace_stream(
      &framer, MoqtControlMessageParser(kDefaultMoqtVersion, true), nullptr,
      &tree, callback);
  namespace_stream.BindStream(&mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  QUICHE_ASSERT_OK(
      namespace_stream.OnControlMessage(MoqtSubscribeNamespace(7)));
  MoqtTrackStatus track_status = DefaultSubscribe();
  track_status.request_id = 7;
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  stream_input->ReceiveMessage(track_status);
  // Block all outgoing SUBSCRIBE, PUBLISH_NAMESPACE, GOAWAY,etc.
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_FALSE(session_.Subscribe(FullTrackName({"foo"}, "bar"),
                                  &remote_track_visitor_, parameters));
  TrackNamespace prefix({"foo"});
  EXPECT_EQ(
      session_.SubscribeNamespace(
          prefix, SubscribeNamespaceOption::kNamespace, MessageParameters(),
          +[](std::optional<MoqtRequestErrorInfo>) {}),
      nullptr);
  session_.PublishNamespace(
      TrackNamespace{"foo"}, MessageParameters(),
      +[](std::optional<MoqtRequestErrorInfo>) {},
      +[](MoqtRequestErrorInfo) {});
  EXPECT_FALSE(session_.Fetch(
      FullTrackName(TrackNamespace({"foo"}), "bar"),
      +[](std::unique_ptr<MoqtFetchTask>) {}, Location(0, 0), 5, std::nullopt,
      MessageParameters()));
  session_.GoAway("");
  // GoAway timer fires.
  auto* goaway_alarm =
      absl::down_cast<quic::test::MockAlarmFactory::TestAlarm*>(
          MoqtSessionPeer::GetGoAwayTimeoutAlarm(&session_));
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<webtransport::SessionErrorCode>(
                               MoqtError::kGoawayTimeout),
                           _));
  goaway_alarm->Fire();
}

TEST_F(MoqtSessionTest, ClientCannotSendNewSessionUri) {
  // session_ is a client session.
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
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
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
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
  stream_input->ReceiveMessage(MoqtGoAway("foo"));
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, ReceivePublishDoneWithOpenStreams) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  parameters.expires = quic::QuicTimeDelta::FromMilliseconds(10000);
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*track_alias=*/0,
      parameters,
      TrackExtensions(),
  };
  stream_input->ReceiveMessage(ok);
  constexpr uint64_t kNumStreams = 3;
  webtransport::test::MockStream data[kNumStreams];
  std::unique_ptr<webtransport::StreamVisitor> data_streams[kNumStreams];

  MoqtObject object = {
      /*track_alias=*/0,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kEndOfGroup,
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
                  &remote_track_visitor_);
  }
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  stream_input->ReceiveMessage(
      MoqtPublishDone(0, PublishDoneCode::kTrackEnded, kNumStreams, "foo"));
  track = MoqtSessionPeer::remote_track(&session_, 0);
  EXPECT_CALL(remote_track_visitor_, OnPublishDone).Times(0);
  ASSERT_NE(track, nullptr);
  EXPECT_CALL(remote_track_visitor_, OnPublishDone(_));
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    data_streams[i].reset();
  }
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 0), nullptr);
}

TEST_F(MoqtSessionTest, ReceivePublishDoneWithClosedStreams) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  parameters.expires = quic::QuicTimeDelta::FromMilliseconds(10000);
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*track_alias=*/0,
      parameters,
      TrackExtensions(),
  };
  stream_input->ReceiveMessage(ok);
  constexpr uint64_t kNumStreams = 3;
  webtransport::test::MockStream data[kNumStreams];
  std::unique_ptr<webtransport::StreamVisitor> data_streams[kNumStreams];

  MoqtObject object = {
      /*track_alias=*/0,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kEndOfGroup,
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
                  &remote_track_visitor_);
  }
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    data_streams[i].reset();
  }
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  EXPECT_CALL(remote_track_visitor_, OnPublishDone(_));
  stream_input->ReceiveMessage(
      MoqtPublishDone(0, PublishDoneCode::kTrackEnded, kNumStreams, "foo"));
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 0), nullptr);
}

TEST_F(MoqtSessionTest, PublishDoneTimeout) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  parameters.expires = quic::QuicTimeDelta::FromMilliseconds(10000);
  MoqtSubscribeOk ok = {
      /*request_id=*/0,
      /*track_alias=*/0,
      parameters,
      TrackExtensions(),
  };
  stream_input->ReceiveMessage(ok);
  constexpr uint64_t kNumStreams = 3;
  webtransport::test::MockStream data[kNumStreams];
  std::unique_ptr<webtransport::StreamVisitor> data_streams[kNumStreams];

  MoqtObject object = {
      /*track_alias=*/0,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kEndOfGroup,
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
                  &remote_track_visitor_);
  }
  for (uint64_t i = 0; i < kNumStreams; ++i) {
    data_streams[i].reset();
  }
  SubscribeRemoteTrack* track = MoqtSessionPeer::remote_track(&session_, 0);
  ASSERT_NE(track, nullptr);
  EXPECT_CALL(remote_track_visitor_, OnPublishDone).Times(0);
  // stream_count includes a stream that was never sent.
  stream_input->ReceiveMessage(
      MoqtPublishDone(0, PublishDoneCode::kTrackEnded, kNumStreams + 1, "foo"));
  EXPECT_CALL(remote_track_visitor_, OnPublishDone).Times(0);
  auto* publish_done_alarm =
      absl::down_cast<quic::test::MockAlarmFactory::TestAlarm*>(
          MoqtSessionPeer::GetPublishDoneAlarm(track));
  EXPECT_CALL(remote_track_visitor_, OnPublishDone(_));
  publish_done_alarm->Fire();
  // quic::test::MockAlarmFactory::FireAlarm(publish_done_alarm);;
  EXPECT_EQ(MoqtSessionPeer::remote_track(&session_, 0), nullptr);
}

TEST_F(MoqtSessionTest, SubgroupStreamObjectAfterGroupEnd) {
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_,
          MoqtDataStreamType::Subgroup(/*subgroup_id=*/0, /*first_object_id=*/0,
                                       /*no_extension_headers=*/true,
                                       /*has_default_priority=*/false),
          2);
  object_stream->OnObjectMessage(
      MoqtObject(/*track_alias=*/2, /*group_id=*/0, /*object_id=*/0,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kEndOfGroup, /*subgroup_id=*/0,
                 /*payload_length=*/0),
      "", true);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kUnsubscribe), _));
  EXPECT_CALL(remote_track_visitor_, OnMalformedTrack);
  object_stream->OnObjectMessage(
      MoqtObject(/*track_alias=*/2, /*group_id=*/0, /*object_id=*/1,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kNormal, /*subgroup_id=*/0,
                 /*payload_length=*/3),
      "bar", true);
}

TEST_F(MoqtSessionTest, SubgroupStreamObjectAfterTrackEnd) {
  MoqtSessionPeer::CreateRemoteTrack(&session_, DefaultSubscribe(),
                                     /*track_alias=*/2, &remote_track_visitor_);
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(
          &session_, &mock_stream_,
          MoqtDataStreamType::Subgroup(/*subgroup_id=*/0, /*first_object_id=*/0,
                                       /*no_extension_headers=*/true,
                                       /*has_default_priority=*/false),
          /*track_alias=*/2);
  object_stream->OnObjectMessage(
      MoqtObject(/*track_alias=*/2, /*group_id=*/0, /*object_id=*/0,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kEndOfTrack, /*subgroup_id=*/0,
                 /*payload_length=*/0),
      "", true);
  EXPECT_CALL(mock_session_, GetStreamById(_))
      .WillRepeatedly(Return(&control_stream));
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kUnsubscribe), _));
  EXPECT_CALL(remote_track_visitor_, OnMalformedTrack);
  object_stream->OnObjectMessage(
      MoqtObject(/*track_alias=*/2, /*group_id=*/0, /*object_id=*/1,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kNormal, /*subgroup_id=*/0,
                 /*payload_length=*/3),
      "bar", true);
}

TEST_F(MoqtSessionTest, FetchStreamMalformedTrack) {
  webtransport::test::InMemoryStream stream(kIncomingUniStreamId);
  std::unique_ptr<MoqtFetchTask> task =
      MoqtSessionPeer::CreateUpstreamFetch(&session_, &stream);
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream_,
                                                MoqtDataStreamType::Fetch(), 0);
  object_stream->OnObjectMessage(
      MoqtObject(/*request_id=*/0, /*group_id=*/0, /*object_id=*/1,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kNormal, /*subgroup_id=*/0,
                 /*payload_length=*/3),
      "foo", true);
  EXPECT_FALSE(IsInvalidArgument(task->GetStatus()));
  object_stream->OnObjectMessage(
      MoqtObject(/*request_id=*/0, /*group_id=*/0, /*object_id=*/2,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kNormal, /*subgroup_id=*/0,
                 /*payload_length=*/3),
      "bar", true);
  EXPECT_FALSE(IsInvalidArgument(task->GetStatus()));
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kFetchCancel), _));
  object_stream->OnObjectMessage(
      MoqtObject(/*request_id=*/0, /*group_id=*/0, /*object_id=*/2,
                 /*publisher_priority=*/0x80, /*extension_headers=*/"",
                 MoqtObjectStatus::kNormal, /*subgroup_id=*/0,
                 /*payload_length=*/3),
      "bar", true);
  EXPECT_TRUE(IsInvalidArgument(task->GetStatus()));
}

TEST_F(MoqtSessionTest, IncomingTrackStatusThenSynchronousOk) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  auto* track = CreateTrackPublisher();

  MoqtTrackStatus track_status = DefaultSubscribe();
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce([&](MoqtObjectListener* listener) {
        EXPECT_CALL(*track, expiration)
            .WillRepeatedly(
                Return(quic::QuicTimeDelta::FromMilliseconds(10000)));
        EXPECT_CALL(*track, largest_location)
            .WillRepeatedly(Return(Location(5, 30)));
        MoqtRequestOk expected_ok;
        expected_ok.request_id = track_status.request_id;
        expected_ok.parameters.expires =
            quic::QuicTimeDelta::FromMilliseconds(10000);
        expected_ok.parameters.largest_object = Location(5, 30);
        EXPECT_CALL(control_stream,
                    Writev(SerializedControlMessage(expected_ok), _));
        EXPECT_CALL(*track, RemoveObjectListener);
        listener->OnSubscribeAccepted();
      });
  stream_input->ReceiveMessage(track_status);
}

TEST_F(MoqtSessionTest, IncomingTrackStatusThenAsynchronousOk) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  auto* track = CreateTrackPublisher();

  MoqtTrackStatus track_status = DefaultSubscribe();
  MoqtObjectListener* listener = nullptr;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce(testing::SaveArg<0>(&listener));
  stream_input->ReceiveMessage(track_status);
  ASSERT_NE(listener, nullptr);
  EXPECT_CALL(*track, expiration)
      .WillRepeatedly(Return(quic::QuicTimeDelta::FromMilliseconds(10000)));
  EXPECT_CALL(*track, largest_location).WillRepeatedly(Return(Location(5, 30)));
  MoqtRequestOk expected_ok;
  expected_ok.request_id = track_status.request_id;
  expected_ok.parameters.expires = quic::QuicTimeDelta::FromMilliseconds(10000);
  expected_ok.parameters.largest_object = Location(5, 30);
  EXPECT_CALL(control_stream, Writev(SerializedControlMessage(expected_ok), _));
  EXPECT_CALL(*track, RemoveObjectListener(listener));
  listener->OnSubscribeAccepted();
}

TEST_F(MoqtSessionTest, IncomingTrackStatusThenSynchronousError) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  auto* track = CreateTrackPublisher();

  MoqtTrackStatus track_status = DefaultSubscribe();
  bool executed_AddObjectListener = false;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce([&](MoqtObjectListener* listener) {
        EXPECT_CALL(
            control_stream,
            Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
        EXPECT_CALL(*track, RemoveObjectListener);
        listener->OnSubscribeRejected(MoqtRequestErrorInfo(
            RequestErrorCode::kInternalError, std::nullopt, "Test error"));
        executed_AddObjectListener = true;
      });
  stream_input->ReceiveMessage(track_status);
  EXPECT_TRUE(executed_AddObjectListener);
}

TEST_F(MoqtSessionTest, IncomingTrackStatusThenAsynchronousError) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  auto* track = CreateTrackPublisher();

  MoqtTrackStatus track_status = DefaultSubscribe();
  MoqtObjectListener* listener;
  EXPECT_CALL(*track, AddObjectListener)
      .WillOnce(testing::SaveArg<0>(&listener));
  stream_input->ReceiveMessage(track_status);
  ASSERT_NE(listener, nullptr);
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  EXPECT_CALL(*track, RemoveObjectListener(listener));
  listener->OnSubscribeRejected(MoqtRequestErrorInfo(
      RequestErrorCode::kInternalError, std::nullopt, "Test error"));
}

TEST_F(MoqtSessionTest, FinReportedToVisitor) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream_);
  EXPECT_CALL(mock_session_, GetStreamById)
      .WillRepeatedly(Return(&control_stream_));
  EXPECT_CALL(control_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  MoqtSubscribeOk ok = {/*request_id=*/0, /*track_alias=*/2,
                        MessageParameters(), TrackExtensions()};
  EXPECT_CALL(remote_track_visitor_, OnReply)
      .WillOnce(
          [&](const FullTrackName& ftn,
              std::variant<SubscribeOkData, MoqtRequestErrorInfo> response) {
            EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(response));
          });
  control_stream->ReceiveMessage(ok);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kEndOfGroup,
      /*subgroup_id=*/0,
      /*payload_length=*/0,
  };
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kIncomingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> data_stream;
  DeliverObject(object, /*fin=*/true, mock_session_, &mock_stream_, data_stream,
                &remote_track_visitor_);
  // The data stream died and destroyed the visitor (IncomingDataStream).
  EXPECT_CALL(remote_track_visitor_,
              OnStreamFin(FullTrackName("foo", "bar"), DataStreamIndex(0, 0)));
  data_stream.reset();
}

TEST_F(MoqtSessionTest, ResetReportedToVisitor) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream_);
  EXPECT_CALL(mock_session_, GetStreamById)
      .WillRepeatedly(Return(&control_stream_));
  EXPECT_CALL(control_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kSubscribe), _));
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  EXPECT_TRUE(session_.Subscribe(FullTrackName("foo", "bar"),
                                 &remote_track_visitor_, parameters));
  MoqtSubscribeOk ok = {/*request_id=*/0, /*track_alias=*/2,
                        MessageParameters(), TrackExtensions()};
  EXPECT_CALL(remote_track_visitor_, OnReply)
      .WillOnce(
          [&](const FullTrackName& ftn,
              std::variant<SubscribeOkData, MoqtRequestErrorInfo> response) {
            EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
            EXPECT_TRUE(std::holds_alternative<SubscribeOkData>(response));
          });
  control_stream->ReceiveMessage(ok);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_id=*/0,
      /*object_id=*/0,
      /*publisher_priority=*/7,
      /*extension_headers=*/"",
      /*object_status=*/MoqtObjectStatus::kEndOfGroup,
      /*subgroup_id=*/0,
      /*payload_length=*/0,
  };
  EXPECT_CALL(mock_stream_, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kIncomingUniStreamId))
      .WillRepeatedly(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> data_stream;
  DeliverObject(object, /*fin=*/false, mock_session_, &mock_stream_,
                data_stream, &remote_track_visitor_);
  // The data stream died and destroyed the visitor (IncomingDataStream).
  data_stream->OnResetStreamReceived(kResetCodeCancelled);
  EXPECT_CALL(remote_track_visitor_, OnStreamReset(FullTrackName("foo", "bar"),
                                                   DataStreamIndex(0, 0)));
  data_stream.reset();
}

TEST_F(MoqtSessionTest, IncomingPublishNamespaceCleanup) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  // Register two incoming PUBLISH_NAMESPACE.
  MoqtPublishNamespace publish_namespace{
      /*request_id=*/1, TrackNamespace{"foo"}, MessageParameters()};
  EXPECT_CALL(session_callbacks_.incoming_publish_namespace_callback,
              Call(TrackNamespace{"foo"}, _, _))
      .WillOnce([&](const TrackNamespace&,
                    const std::optional<MessageParameters>&,
                    MoqtResponseCallback callback) {
        std::move(callback)(std::nullopt);
      });
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  stream_input->ReceiveMessage(publish_namespace);

  publish_namespace = MoqtPublishNamespace(
      /*request_id=*/3, TrackNamespace{"bar"}, MessageParameters());
  EXPECT_CALL(session_callbacks_.incoming_publish_namespace_callback,
              Call(TrackNamespace{"bar"}, _, _))
      .WillOnce([&](const TrackNamespace&,
                    const std::optional<MessageParameters>&,
                    MoqtResponseCallback callback) {
        std::move(callback)(std::nullopt);
      });
  EXPECT_CALL(control_stream,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  stream_input->ReceiveMessage(publish_namespace);

  // Revoke "bar"
  MoqtPublishNamespaceDone done{/*request_id=*/3};
  EXPECT_CALL(
      session_callbacks_.incoming_publish_namespace_callback,
      Call(TrackNamespace{"bar"}, std::optional<MessageParameters>(), _))
      .WillOnce(
          [](const TrackNamespace&, const std::optional<MessageParameters>&,
             MoqtResponseCallback callback) { EXPECT_EQ(callback, nullptr); });
  stream_input->ReceiveMessage(done);

  // Destroying the session should revoke "foo".
  EXPECT_CALL(
      session_callbacks_.incoming_publish_namespace_callback,
      Call(TrackNamespace{"foo"}, std::optional<MessageParameters>(), _))
      .WillOnce(
          [](const TrackNamespace&, const std::optional<MessageParameters>&,
             MoqtResponseCallback callback) { EXPECT_EQ(callback, nullptr); });
  // Test teardown will destroy session_, triggering removal of "foo".
}

TEST_F(MoqtSessionTest, WrongSubprotocol) {
  EXPECT_CALL(mock_session_, GetNegotiatedSubprotocol)
      .WillOnce(
          Return(std::optional<std::string>(kUnrecognizedVersionForTests)));
  EXPECT_CALL(mock_session_, CloseSession);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  session_.OnSessionReady();
}

TEST_F(MoqtSessionTest, NoSubprotocol) {
  EXPECT_CALL(mock_session_, GetNegotiatedSubprotocol)
      .WillOnce(Return(std::optional<std::string>()));
  EXPECT_CALL(mock_session_, CloseSession);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  session_.OnSessionReady();
}

TEST_F(MoqtSessionTest, SubscribeThenRequestOk) {
  webtransport::test::MockStream control_stream;
  std::unique_ptr<MoqtBidiStreamTestWrapper> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &control_stream);
  MessageParameters parameters = SubscribeForTest();
  parameters.subscription_filter.emplace(MoqtFilterType::kLargestObject);
  session_.Subscribe(FullTrackName("foo", "bar"), &remote_track_visitor_,
                     parameters);
  EXPECT_CALL(mock_session_, CloseSession);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  stream_input->ReceiveMessage(MoqtRequestOk{0, MessageParameters()});
}

TEST_F(MoqtSessionTest, ClientSetupNotAllowedOnControlStream) {
  // While technically on the Control stream, when it arrives, it's an
  // UnknownBidiStream
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, CloseSession);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  control_stream->ReceiveMessage(
      MoqtClientSetup(SetupParameters("/", "example.com", 0)));
}

TEST_F(MoqtSessionTest, NamespaceNotAllowedOnControlStream) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, CloseSession);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  control_stream->ReceiveMessage(MoqtNamespace());
}

TEST_F(MoqtSessionTest, NamespaceDoneNotAllowedOnControlStream) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_session_, CloseSession);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call);
  control_stream->ReceiveMessage(MoqtNamespaceDone());
}

TEST_F(MoqtSessionTest, IncomingRequestUpdateTriggersRequestOk) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  ReceiveSubscribeSynchronousOk(track, subscribe, control_stream.get(), 0);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestOk), _));
  control_stream->ReceiveMessage(MoqtRequestUpdate{3, 1, MessageParameters()});
}

TEST_F(MoqtSessionTest, IncomingRequestUpdateTriggersRequestError) {
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  EXPECT_CALL(mock_stream_,
              Writev(ControlMessageOfType(MoqtMessageType::kRequestError), _));
  control_stream->ReceiveMessage(MoqtRequestUpdate{3, 1, MessageParameters()});
}

TEST_F(MoqtSessionTest, StopSendingBlocksSubgroup) {
  MoqtSubscribe subscribe = DefaultSubscribe();
  MockTrackPublisher* track = CreateTrackPublisher();
  std::unique_ptr<MoqtBidiStreamTestWrapper> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream_);
  MoqtObjectListener* listener =
      ReceiveSubscribeSynchronousOk(track, subscribe, control_stream.get(), 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream)
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream)
      .WillOnce(Return(&mock_stream_));
  std::unique_ptr<webtransport::StreamVisitor> data_stream_visitor;
  EXPECT_CALL(mock_stream_, SetVisitor)
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        data_stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream_, visitor).WillRepeatedly([&]() {
    return data_stream_visitor.get();
  });
  EXPECT_CALL(mock_stream_, CanWrite).WillRepeatedly(Return(true));
  EXPECT_CALL(*track, GetCachedObject(0, Optional(1), 0, 0))
      .WillOnce(Return(PublishedObject{
          PublishedObjectMetadata{Location(0, 0), 1, "",
                                  MoqtObjectStatus::kNormal, 0x80, 0,
                                  MoqtSessionPeer::Now(&session_)},
          PayloadFromString(""), false}));
  EXPECT_CALL(*track, GetCachedObject(0, Optional(1), 1, 0))
      .WillOnce(Return(std::nullopt));
  SetLargestId(track, Location(0, 0));
  EXPECT_CALL(mock_stream_, Writev).WillOnce(Return(absl::OkStatus()));
  listener->OnNewObjectAvailable(Location(0, 0), 1, 0x80);

  EXPECT_CALL(mock_stream_, ResetWithUserCode(kResetCodeCancelled));
  data_stream_visitor->OnStopSendingReceived(kResetCodeCancelled);
  // New object in the same subgroup should not be sent.
  EXPECT_CALL(*track, GetCachedObject).Times(0);
  EXPECT_CALL(mock_stream_, Writev).Times(0);
  listener->OnNewObjectAvailable(Location(0, 1), 1, 0x80);
}

}  // namespace test

}  // namespace moqt
