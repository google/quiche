// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>


#include "absl/status/status.h"
#include "absl/strings/match.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

namespace {

using ::quic::test::MemSliceFromString;
using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Return;
using ::testing::StrictMock;

constexpr webtransport::StreamId kControlStreamId = 4;
constexpr webtransport::StreamId kIncomingUniStreamId = 15;
constexpr webtransport::StreamId kOutgoingUniStreamId = 14;

// Returns nullopt if there is not enough in |message| to extract a type
static std::optional<MoqtMessageType> ExtractMessageType(
    const absl::string_view message) {
  quic::QuicDataReader reader(message);
  uint64_t value;
  if (!reader.ReadVarInt62(&value)) {
    return std::nullopt;
  }
  return static_cast<MoqtMessageType>(value);
}

static std::shared_ptr<MockTrackPublisher> SetupPublisher(
    FullTrackName track_name, MoqtForwardingPreference forwarding_preference,
    FullSequence largest_sequence) {
  auto publisher = std::make_shared<MockTrackPublisher>(std::move(track_name));
  ON_CALL(*publisher, GetTrackStatus())
      .WillByDefault(Return(MoqtTrackStatusCode::kInProgress));
  ON_CALL(*publisher, GetForwardingPreference())
      .WillByDefault(Return(forwarding_preference));
  ON_CALL(*publisher, GetLargestSequence())
      .WillByDefault(Return(largest_sequence));
  return publisher;
}

}  // namespace

class MoqtSessionPeer {
 public:
  static std::unique_ptr<MoqtControlParserVisitor> CreateControlStream(
      MoqtSession* session, webtransport::test::MockStream* stream) {
    auto new_stream =
        std::make_unique<MoqtSession::ControlStream>(session, stream);
    session->control_stream_ = kControlStreamId;
    ON_CALL(*stream, visitor()).WillByDefault(Return(new_stream.get()));
    webtransport::test::MockSession* mock_session =
        static_cast<webtransport::test::MockSession*>(session->session());
    EXPECT_CALL(*mock_session, GetStreamById(kControlStreamId))
        .Times(AnyNumber())
        .WillRepeatedly(Return(stream));
    return new_stream;
  }

  static std::unique_ptr<MoqtDataParserVisitor> CreateIncomingDataStream(
      MoqtSession* session, webtransport::Stream* stream) {
    auto new_stream =
        std::make_unique<MoqtSession::IncomingDataStream>(session, stream);
    return new_stream;
  }

  // In the test OnSessionReady, the session creates a stream and then passes
  // its unique_ptr to the mock webtransport stream. This function casts
  // that unique_ptr into a MoqtSession::Stream*, which is a private class of
  // MoqtSession, and then casts again into MoqtParserVisitor so that the test
  // can inject packets into that stream.
  // This function is useful for any test that wants to inject packets on a
  // stream created by the MoqtSession.
  static MoqtControlParserVisitor*
  FetchParserVisitorFromWebtransportStreamVisitor(
      MoqtSession* session, webtransport::StreamVisitor* visitor) {
    return static_cast<MoqtSession::ControlStream*>(visitor);
  }

  static void CreateRemoteTrack(MoqtSession* session, const FullTrackName& name,
                                RemoteTrack::Visitor* visitor,
                                uint64_t track_alias) {
    session->remote_tracks_.try_emplace(track_alias, name, track_alias,
                                        visitor);
    session->remote_track_aliases_.try_emplace(name, track_alias);
  }

  static void AddActiveSubscribe(MoqtSession* session, uint64_t subscribe_id,
                                 MoqtSubscribe& subscribe,
                                 RemoteTrack::Visitor* visitor) {
    session->active_subscribes_[subscribe_id] = {subscribe, visitor};
  }

  static MoqtObjectListener* AddSubscription(
      MoqtSession* session, std::shared_ptr<MoqtTrackPublisher> publisher,
      uint64_t subscribe_id, uint64_t track_alias, uint64_t start_group,
      uint64_t start_object) {
    MoqtSubscribe subscribe;
    subscribe.full_track_name = publisher->GetTrackName();
    subscribe.track_alias = track_alias;
    subscribe.subscribe_id = subscribe_id;
    subscribe.start_group = start_group;
    subscribe.start_object = start_object;
    subscribe.subscriber_priority = 0x80;
    session->published_subscriptions_.emplace(
        subscribe_id, std::make_unique<MoqtSession::PublishedSubscription>(
                          session, std::move(publisher), subscribe,
                          /*monitoring_interface=*/nullptr));
    return session->published_subscriptions_[subscribe_id].get();
  }

  static void DeleteSubscription(MoqtSession* session, uint64_t subscribe_id) {
    session->published_subscriptions_.erase(subscribe_id);
  }

  static void UpdateSubscriberPriority(MoqtSession* session,
                                       uint64_t subscribe_id,
                                       MoqtPriority priority) {
    session->published_subscriptions_[subscribe_id]->set_subscriber_priority(
        priority);
  }

  static void set_peer_role(MoqtSession* session, MoqtRole role) {
    session->peer_role_ = role;
  }

  static RemoteTrack& remote_track(MoqtSession* session, uint64_t track_alias) {
    return session->remote_tracks_.find(track_alias)->second;
  }

  static void set_next_subscribe_id(MoqtSession* session, uint64_t id) {
    session->next_subscribe_id_ = id;
  }

  static void set_peer_max_subscribe_id(MoqtSession* session, uint64_t id) {
    session->peer_max_subscribe_id_ = id;
  }
};

class MoqtSessionTest : public quic::test::QuicTest {
 public:
  MoqtSessionTest()
      : session_(&mock_session_,
                 MoqtSessionParameters(quic::Perspective::IS_CLIENT, ""),
                 session_callbacks_.AsSessionCallbacks()) {
    session_.set_publisher(&publisher_);
    MoqtSessionPeer::set_peer_max_subscribe_id(&session_,
                                               kDefaultInitialMaxSubscribeId);
  }
  ~MoqtSessionTest() {
    EXPECT_CALL(session_callbacks_.session_deleted_callback, Call());
  }

  MockSessionCallbacks session_callbacks_;
  StrictMock<webtransport::test::MockSession> mock_session_;
  MoqtSession session_;
  MoqtKnownTrackPublisher publisher_;
};

TEST_F(MoqtSessionTest, Queries) {
  EXPECT_EQ(session_.perspective(), quic::Perspective::IS_CLIENT);
}

// Verify the session sends CLIENT_SETUP on the control stream.
TEST_F(MoqtSessionTest, OnSessionReady) {
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillOnce(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] { return visitor.get(); });
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kClientSetup);
        return absl::OkStatus();
      });
  session_.OnSessionReady();
  EXPECT_TRUE(correct_message);

  // Receive SERVER_SETUP
  MoqtControlParserVisitor* stream_input =
      MoqtSessionPeer::FetchParserVisitorFromWebtransportStreamVisitor(
          &session_, visitor.get());
  // Handle the server setup
  MoqtServerSetup setup = {
      kDefaultMoqtVersion,
      MoqtRole::kPubSub,
  };
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnServerSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnClientSetup) {
  MoqtSession server_session(
      &mock_session_, MoqtSessionParameters(quic::Perspective::IS_SERVER),
      session_callbacks_.AsSessionCallbacks());
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream);
  MoqtClientSetup setup = {
      /*supported_versions=*/{kDefaultMoqtVersion},
      /*role=*/MoqtRole::kPubSub,
      /*path=*/std::nullopt,
  };
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kServerSetup);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream, GetStreamId()).WillOnce(Return(0));
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
  webtransport::test::MockStream mock_stream;
  StrictMock<webtransport::test::MockStreamVisitor> mock_stream_visitor;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, visitor()).WillOnce(Return(&mock_stream_visitor));
  EXPECT_CALL(mock_stream_visitor, OnCanRead()).Times(1);
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(nullptr));
  session_.OnIncomingBidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, OnIncomingUnidirectionalStream) {
  ::testing::InSequence seq;
  webtransport::test::MockStream mock_stream;
  StrictMock<webtransport::test::MockStreamVisitor> mock_stream_visitor;
  EXPECT_CALL(mock_session_, AcceptIncomingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, visitor()).WillOnce(Return(&mock_stream_visitor));
  EXPECT_CALL(mock_stream_visitor, OnCanRead()).Times(1);
  EXPECT_CALL(mock_session_, AcceptIncomingUnidirectionalStream())
      .WillOnce(Return(nullptr));
  session_.OnIncomingUnidirectionalStreamAvailable();
}

TEST_F(MoqtSessionTest, Error) {
  bool reported_error = false;
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kParameterLengthMismatch),
                   "foo"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "foo");
      });
  session_.Error(MoqtError::kParameterLengthMismatch, "foo");
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, AddLocalTrack) {
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  // Request for track returns SUBSCRIBE_ERROR.
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeError);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);

  // Add the track. Now Subscribe should succeed.
  auto track_publisher =
      std::make_shared<MockTrackPublisher>(FullTrackName("foo", "bar"));
  EXPECT_CALL(*track_publisher, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kStatusNotAvailable));
  publisher_.Add(track_publisher);
  correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithOk) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kAnnounce);
        return absl::OkStatus();
      });
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction());
  EXPECT_TRUE(correct_message);

  MoqtAnnounceOk ok = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        correct_message = true;
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        EXPECT_FALSE(error.has_value());
      });
  stream_input->OnAnnounceOkMessage(ok);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithError) {
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kAnnounce);
        return absl::OkStatus();
      });
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction());
  EXPECT_TRUE(correct_message);

  MoqtAnnounceError error = {
      /*track_namespace=*/FullTrackName{"foo"},
      /*error_code=*/MoqtAnnounceErrorCode::kInternalError,
      /*reason_phrase=*/"Test error",
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](FullTrackName track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        correct_message = true;
        EXPECT_EQ(track_namespace, FullTrackName{"foo"});
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, MoqtAnnounceErrorCode::kInternalError);
        EXPECT_EQ(error->reason_phrase, "Test error");
      });
  stream_input->OnAnnounceErrorMessage(error);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeForPast) {
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);

  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeError);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, TwoSubscribesForTrack) {
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);

  // Peer subscribes to (11, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/11,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);

  request.subscribe_id = 2;
  request.start_group = 12;
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Duplicate subscribe for track"))
      .Times(1);
  stream_input->OnSubscribeMessage(request);
  ;
}

TEST_F(MoqtSessionTest, UnsubscribeAllowsSecondSubscribe) {
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);

  // Peer subscribes to (11, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/11,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);

  // Peer unsubscribes.
  MoqtUnsubscribe unsubscribe = {
      /*subscribe_id=*/1,
  };
  correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeDone);
        return absl::OkStatus();
      });
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_TRUE(correct_message);

  // Subscribe again, succeeds.
  request.subscribe_id = 2;
  request.start_group = 12;
  correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeIdTooHigh) {
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/kDefaultInitialMaxSubscribeId + 1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kTooManySubscribes),
                           "Received SUBSCRIBE with too large ID"))
      .Times(1);
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, TooManySubscribes) {
  MoqtSessionPeer::set_next_subscribe_id(&session_,
                                         kDefaultInitialMaxSubscribeId);
  MockRemoteTrackVisitor remote_track_visitor;
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  EXPECT_TRUE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                             &remote_track_visitor));
  EXPECT_FALSE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                              &remote_track_visitor));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeWithOk) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MockRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                 &remote_track_visitor);

  MoqtSubscribeOk ok = {
      /*subscribe_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  correct_message = false;
  EXPECT_CALL(remote_track_visitor, OnReply(_, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<absl::string_view> error_message) {
        correct_message = true;
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_FALSE(error_message.has_value());
      });
  stream_input->OnSubscribeOkMessage(ok);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, MaxSubscribeIdChangesResponse) {
  MoqtSessionPeer::set_next_subscribe_id(&session_,
                                         kDefaultInitialMaxSubscribeId + 1);
  MockRemoteTrackVisitor remote_track_visitor;
  EXPECT_FALSE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                              &remote_track_visitor));
  MoqtMaxSubscribeId max_subscribe_id = {
      /*max_subscribe_id=*/kDefaultInitialMaxSubscribeId + 1,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  stream_input->OnMaxSubscribeIdMessage(max_subscribe_id);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  EXPECT_TRUE(session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                             &remote_track_visitor));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, LowerMaxSubscribeIdIsAnError) {
  MoqtMaxSubscribeId max_subscribe_id = {
      /*max_subscribe_id=*/kDefaultInitialMaxSubscribeId - 1,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(
      mock_session_,
      CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                   "MAX_SUBSCRIBE_ID message has lower value than previous"))
      .Times(1);
  stream_input->OnMaxSubscribeIdMessage(max_subscribe_id);
}

TEST_F(MoqtSessionTest, GrantMoreSubscribes) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kMaxSubscribeId);
        return absl::OkStatus();
      });
  session_.GrantMoreSubscribes(1);
  EXPECT_TRUE(correct_message);
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/kDefaultInitialMaxSubscribeId + 1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/10,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  correct_message = false;
  FullTrackName ftn("foo", "bar");
  auto track = std::make_shared<MockTrackPublisher>(ftn);
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  EXPECT_CALL(*track, GetCachedObject(_)).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  EXPECT_CALL(*track, GetCachedObjectsInRange(_, _))
      .WillRepeatedly(Return(std::vector<FullSequence>()));
  EXPECT_CALL(*track, GetLargestSequence())
      .WillRepeatedly(Return(FullSequence(10, 20)));
  publisher_.Add(track);
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SubscribeWithError) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MockRemoteTrackVisitor remote_track_visitor;
  EXPECT_CALL(mock_session_, GetStreamById(_)).WillOnce(Return(&mock_stream));
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribe);
        return absl::OkStatus();
      });
  session_.SubscribeCurrentGroup(FullTrackName("foo", "bar"),
                                 &remote_track_visitor);

  MoqtSubscribeError error = {
      /*subscribe_id=*/0,
      /*error_code=*/SubscribeErrorCode::kInvalidRange,
      /*reason_phrase=*/"deadbeef",
      /*track_alias=*/2,
  };
  correct_message = false;
  EXPECT_CALL(remote_track_visitor, OnReply(_, _))
      .WillOnce([&](const FullTrackName& ftn,
                    std::optional<absl::string_view> error_message) {
        correct_message = true;
        EXPECT_EQ(ftn, FullTrackName("foo", "bar"));
        EXPECT_EQ(*error_message, "deadbeef");
      });
  stream_input->OnSubscribeErrorMessage(error);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, ReplyToAnnounce) {
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtAnnounce announce = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  bool correct_message = false;
  EXPECT_CALL(session_callbacks_.incoming_announce_callback,
              Call(FullTrackName{"foo"}))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kAnnounceOk);
        return absl::OkStatus();
      });
  stream_input->OnAnnounceMessage(announce);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, IncomingObject) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, IncomingPartialObject) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/16,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, IncomingPartialObjectNoBuffer) {
  MoqtSessionParameters parameters(quic::Perspective::IS_CLIENT);
  parameters.deliver_partial_objects = true;
  MoqtSession session(&mock_session_, parameters,
                      session_callbacks_.AsSessionCallbacks());
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/16,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(2);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeOk) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor_);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*subscribe_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/std::nullopt,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(visitor_, OnReply(_, _)).Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, ObjectBeforeSubscribeError) {
  MockRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_ERROR arrives
  MoqtSubscribeError subscribe_error = {
      /*subscribe_id=*/1,
      /*error_code=*/SubscribeErrorCode::kRetryTrackAlias,
      /*reason_phrase=*/"foo",
      /*track_alias =*/3,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received SUBSCRIBE_ERROR after object"))
      .Times(1);
  control_stream->OnSubscribeErrorMessage(subscribe_error);
}

TEST_F(MoqtSessionTest, TwoEarlyObjectsDifferentForwarding) {
  MockRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  object.forwarding_preference = MoqtForwardingPreference::kTrack;
  ++object.object_id;
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference changes mid-track"))
      .Times(1);
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, EarlyObjectForwardingDoesNotMatchTrack) {
  MockRemoteTrackVisitor visitor;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSubscribe subscribe = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/ftn,
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name, FullSequence sequence,
                    MoqtPriority publisher_priority, MoqtObjectStatus status,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(sequence.group, object.group_id);
        EXPECT_EQ(sequence.object, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor, 2);
  // The track already exists, and has a different forwarding preference.
  MoqtSessionPeer::remote_track(&session_, 2)
      .CheckForwardingPreference(MoqtForwardingPreference::kTrack);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*subscribe_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*group_order=*/MoqtDeliveryOrder::kAscending,
      /*largest_id=*/std::nullopt,
  };
  webtransport::test::MockStream mock_control_stream;
  std::unique_ptr<MoqtControlParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference different in early objects"))
      .Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, CreateIncomingDataStreamAndSend) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_stream, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream));

  // Verify first six message fields are sent correctly
  bool correct_message = false;
  const std::string kExpectedMessage = {0x04, 0x02, 0x05, 0x00, 0x00};
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = absl::StartsWith(data[0], kExpectedMessage);
        fin |= options.send_fin();
        return absl::OkStatus();
      });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 0))).WillRepeatedly([] {
    return PublishedObject{FullSequence(5, 0), MoqtObjectStatus::kNormal, 127,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(FullSequence(5, 0));
  EXPECT_TRUE(correct_message);
}

// TODO: Test operation with multiple streams.

TEST_F(MoqtSessionTest, UnidirectionalStreamCannotBeOpened) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Queue the outgoing stream.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  subscription->OnNewObjectAvailable(FullSequence(5, 0));

  // Unblock the session, and cause the queued stream to be sent.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  bool fin = false;
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_stream, CanWrite()).WillRepeatedly([&] { return !fin; });
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream));
  EXPECT_CALL(mock_stream, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 0))).WillRepeatedly([] {
    return PublishedObject{FullSequence(5, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).WillRepeatedly([] {
    return std::optional<PublishedObject>();
  });
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, OutgoingStreamDisappears) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(4, 2));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 2, 5, 0);

  // Set up an outgoing stream for a group.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_stream, CanWrite()).WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> stream_visitor;
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> visitor) {
        stream_visitor = std::move(visitor);
      });
  EXPECT_CALL(mock_stream, visitor()).WillRepeatedly([&] {
    return stream_visitor.get();
  });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(&mock_stream));

  EXPECT_CALL(mock_stream, Writev(_, _)).WillOnce(Return(absl::OkStatus()));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 0))).WillRepeatedly([] {
    return PublishedObject{FullSequence(5, 0), MoqtObjectStatus::kNormal, 128,
                           MemSliceFromString("deadbeef")};
  });
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).WillOnce([] {
    return std::optional<PublishedObject>();
  });
  subscription->OnNewObjectAvailable(FullSequence(5, 0));

  // Now that the stream exists and is recorded within subscription, make it
  // disappear by returning nullptr.
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillRepeatedly(Return(nullptr));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(5, 1))).Times(0);
  subscription->OnNewObjectAvailable(FullSequence(5, 1));
}

TEST_F(MoqtSessionTest, OneBidirectionalStreamClient) {
  webtransport::test::MockStream mock_stream;
  EXPECT_CALL(mock_session_, OpenOutgoingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
  std::unique_ptr<webtransport::StreamVisitor> visitor;
  // Save a reference to MoqtSession::Stream
  EXPECT_CALL(mock_stream, SetVisitor(_))
      .WillOnce([&](std::unique_ptr<webtransport::StreamVisitor> new_visitor) {
        visitor = std::move(new_visitor);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillOnce(Return(webtransport::StreamId(4)));
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, visitor()).WillOnce([&] { return visitor.get(); });
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kClientSetup);
        return absl::OkStatus();
      });
  session_.OnSessionReady();
  EXPECT_TRUE(correct_message);

  // Peer tries to open a bidi stream.
  bool reported_error = false;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
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
      session_callbacks_.AsSessionCallbacks());
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream);
  MoqtClientSetup setup = {
      /*supported_versions*/ {kDefaultMoqtVersion},
      /*role=*/MoqtRole::kPubSub,
      /*path=*/std::nullopt,
  };
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kServerSetup);
        return absl::OkStatus();
      });
  EXPECT_CALL(mock_stream, GetStreamId()).WillOnce(Return(0));
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnClientSetupMessage(setup);

  // Peer tries to open a bidi stream.
  bool reported_error = false;
  EXPECT_CALL(mock_session_, AcceptIncomingBidirectionalStream())
      .WillOnce(Return(&mock_stream));
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
      SetupPublisher(ftn, MoqtForwardingPreference::kTrack, FullSequence(4, 2));
  MoqtSessionPeer::AddSubscription(&session_, track, 0, 1, 3, 4);
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtUnsubscribe unsubscribe = {
      /*subscribe_id=*/0,
  };
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeDone);
        return absl::OkStatus();
      });
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, SendDatagram) {
  FullTrackName ftn("foo", "bar");
  std::shared_ptr<MockTrackPublisher> track_publisher = SetupPublisher(
      ftn, MoqtForwardingPreference::kDatagram, FullSequence{4, 0});
  MoqtObjectListener* listener =
      MoqtSessionPeer::AddSubscription(&session_, track_publisher, 0, 2, 5, 0);

  // Publish in window.
  bool correct_message = false;
  uint8_t kExpectedMessage[] = {
      0x01, 0x02, 0x05, 0x00, 0x00, 0x08, 0x64,
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
  EXPECT_CALL(*track_publisher, GetCachedObject(FullSequence{5, 0}))
      .WillRepeatedly([] {
        return PublishedObject{FullSequence{5, 0}, MoqtObjectStatus::kNormal,
                               128, MemSliceFromString("deadbeef")};
      });
  listener->OnNewObjectAvailable(FullSequence(5, 0));
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, ReceiveDatagram) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kDatagram,
      /*subgroup_id=*/std::nullopt,
      /*payload_length=*/8,
  };
  char datagram[] = {0x01, 0x02, 0x00, 0x00, 0x00, 0x08, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(
      visitor_,
      OnObjectFragment(ftn, FullSequence{object.group_id, object.object_id},
                       object.publisher_priority, object.object_status,
                       object.forwarding_preference, payload, true))
      .Times(1);
  session_.OnDatagramReceived(absl::string_view(datagram, sizeof(datagram)));
}

TEST_F(MoqtSessionTest, ForwardingPreferenceMismatch) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*publisher_priority=*/0,
      /*object_status=*/MoqtObjectStatus::kNormal,
      /*forwarding_preference=*/MoqtForwardingPreference::kSubgroup,
      /*subgroup_id=*/0,
      /*payload_length=*/8,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtDataParserVisitor> object_stream =
      MoqtSessionPeer::CreateIncomingDataStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  ++object.object_id;
  object.forwarding_preference = MoqtForwardingPreference::kTrack;
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference changes mid-track"))
      .Times(1);
  object_stream->OnObjectMessage(object, payload, true);
}

TEST_F(MoqtSessionTest, AnnounceToPublisher) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kPublisher);
  testing::MockFunction<void(
      FullTrackName track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  EXPECT_CALL(announce_resolved_callback, Call(_, _)).Times(1);
  session_.Announce(FullTrackName{"foo"},
                    announce_resolved_callback.AsStdFunction());
}

TEST_F(MoqtSessionTest, SubscribeFromPublisher) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kPublisher);
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*full_track_name=*/FullTrackName({"foo", "bar"}),
      /*subscriber_priority=*/0x80,
      /*group_order=*/std::nullopt,
      /*start_group=*/0,
      /*start_object=*/0,
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*parameters=*/MoqtSubscribeParameters(),
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  // Request for track returns Protocol Violation.
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received SUBSCRIBE from publisher"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_)).Times(1);
  stream_input->OnSubscribeMessage(request);
}

TEST_F(MoqtSessionTest, AnnounceFromSubscriber) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kSubscriber);
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtControlParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtAnnounce announce = {
      /*track_namespace=*/FullTrackName{"foo"},
  };
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received ANNOUNCE from Subscriber"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_)).Times(1);
  stream_input->OnAnnounceMessage(announce);
}

TEST_F(MoqtSessionTest, QueuedStreamsOpenedInOrder) {
  FullTrackName ftn("foo", "bar");
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(0, 0));
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
  subscription->OnNewObjectAvailable(FullSequence(1, 0));
  subscription->OnNewObjectAvailable(FullSequence(0, 0));
  subscription->OnNewObjectAvailable(FullSequence(2, 0));
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
  EXPECT_CALL(*track, GetCachedObject(FullSequence(0, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(0, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(0, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(1, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(1, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(1, 1)))
      .WillOnce(Return(std::nullopt));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(2, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(2, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track, GetCachedObject(FullSequence(2, 1)))
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
  auto track = SetupPublisher(ftn, MoqtForwardingPreference::kSubgroup,
                              FullSequence(0, 0));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kNotYetBegun));
  MoqtObjectListener* subscription =
      MoqtSessionPeer::AddSubscription(&session_, track, 0, 14, 0, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  EXPECT_CALL(*track, GetTrackStatus())
      .WillRepeatedly(Return(MoqtTrackStatusCode::kInProgress));
  subscription->OnNewObjectAvailable(FullSequence(0, 0));

  // Delete the subscription, then grant stream credit.
  MoqtSessionPeer::DeleteSubscription(&session_, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillRepeatedly(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream()).Times(0);
  session_.OnCanCreateNewOutgoingUnidirectionalStream();
}

TEST_F(MoqtSessionTest, QueuedStreamPriorityChanged) {
  FullTrackName ftn1("foo", "bar");
  auto track1 = SetupPublisher(ftn1, MoqtForwardingPreference::kSubgroup,
                               FullSequence(0, 0));
  FullTrackName ftn2("dead", "beef");
  auto track2 = SetupPublisher(ftn2, MoqtForwardingPreference::kSubgroup,
                               FullSequence(0, 0));
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
  subscription0->OnNewObjectAvailable(FullSequence(0, 0));
  subscription1->OnNewObjectAvailable(FullSequence(0, 0));
  subscription0->OnNewObjectAvailable(FullSequence(1, 0));
  subscription1->OnNewObjectAvailable(FullSequence(1, 0));

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
  EXPECT_CALL(*track1, GetCachedObject(FullSequence(0, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(0, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("foobar")}));
  EXPECT_CALL(*track1, GetCachedObject(FullSequence(0, 1)))
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
  EXPECT_CALL(*track2, GetCachedObject(FullSequence(0, 0)))
      .WillOnce(
          Return(PublishedObject{FullSequence(0, 0), MoqtObjectStatus::kNormal,
                                 127, MemSliceFromString("deadbeef")}));
  EXPECT_CALL(*track2, GetCachedObject(FullSequence(0, 1)))
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

// TODO: re-enable this test once this behavior is re-implemented.
#if 0
TEST_F(MoqtSessionTest, SubscribeUpdateClosesSubscription) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kSubscriber);
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kTrack, &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);
  // Get the window, set the maximum delivered.
  LocalTrack* track = MoqtSessionPeer::local_track(&session_, ftn);
  track->GetWindow(0)->OnObjectSent(FullSequence(7, 3),
                                    MoqtObjectStatus::kNormal);
  // Update the end to fall at the last delivered object.
  MoqtSubscribeUpdate update = {
      /*subscribe_id=*/0,
      /*start_group=*/5,
      /*start_object=*/0,
      /*end_group=*/7,
      /*end_object=*/3,
  };
  webtransport::test::MockStream mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  EXPECT_CALL(mock_session_, GetStreamById(4)).WillOnce(Return(&mock_stream));
  bool correct_message = false;
  EXPECT_CALL(mock_stream, Writev(_, _))
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
