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

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {

namespace {

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Return;
using ::testing::StrictMock;

constexpr webtransport::StreamId kControlStreamId = 4;
constexpr webtransport::StreamId kIncomingUniStreamId = 15;
constexpr webtransport::StreamId kOutgoingUniStreamId = 14;

constexpr MoqtSessionParameters default_parameters = {
    /*version=*/MoqtVersion::kDraft03,
    /*perspective=*/quic::Perspective::IS_CLIENT,
    /*using_webtrans=*/true,
    /*path=*/std::string(),
    /*deliver_partial_objects=*/false,
};

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

}  // namespace

class MoqtSessionPeer {
 public:
  static std::unique_ptr<MoqtParserVisitor> CreateControlStream(
      MoqtSession* session, webtransport::test::MockStream* stream) {
    auto new_stream = std::make_unique<MoqtSession::Stream>(
        session, stream, /*is_control_stream=*/true);
    session->control_stream_ = kControlStreamId;
    EXPECT_CALL(*stream, visitor())
        .Times(AnyNumber())
        .WillRepeatedly(Return(new_stream.get()));
    return new_stream;
  }

  static std::unique_ptr<MoqtParserVisitor> CreateUniStream(
      MoqtSession* session, webtransport::Stream* stream) {
    auto new_stream = std::make_unique<MoqtSession::Stream>(
        session, stream, /*is_control_stream=*/false);
    return new_stream;
  }

  // In the test OnSessionReady, the session creates a stream and then passes
  // its unique_ptr to the mock webtransport stream. This function casts
  // that unique_ptr into a MoqtSession::Stream*, which is a private class of
  // MoqtSession, and then casts again into MoqtParserVisitor so that the test
  // can inject packets into that stream.
  // This function is useful for any test that wants to inject packets on a
  // stream created by the MoqtSession.
  static MoqtParserVisitor* FetchParserVisitorFromWebtransportStreamVisitor(
      MoqtSession* session, webtransport::StreamVisitor* visitor) {
    return (MoqtSession::Stream*)visitor;
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

  static void AddSubscription(MoqtSession* session, FullTrackName& name,
                              uint64_t subscribe_id, uint64_t track_alias,
                              uint64_t start_group, uint64_t start_object) {
    auto it = session->local_tracks_.find(name);
    ASSERT_NE(it, session->local_tracks_.end());
    LocalTrack& track = it->second;
    track.set_track_alias(track_alias);
    track.AddWindow(subscribe_id, start_group, start_object);
    session->used_track_aliases_.emplace(track_alias);
  }

  static FullSequence next_sequence(MoqtSession* session, FullTrackName& name) {
    auto it = session->local_tracks_.find(name);
    EXPECT_NE(it, session->local_tracks_.end());
    LocalTrack& track = it->second;
    return track.next_sequence();
  }

  static void set_peer_role(MoqtSession* session, MoqtRole role) {
    session->peer_role_ = role;
  }

  static RemoteTrack& remote_track(MoqtSession* session, uint64_t track_alias) {
    return session->remote_tracks_.find(track_alias)->second;
  }
};

class MoqtSessionTest : public quic::test::QuicTest {
 public:
  MoqtSessionTest()
      : session_(&mock_session_, default_parameters,
                 session_callbacks_.AsSessionCallbacks()) {}
  ~MoqtSessionTest() {
    EXPECT_CALL(session_callbacks_.session_deleted_callback, Call());
  }

  MockSessionCallbacks session_callbacks_;
  StrictMock<webtransport::test::MockSession> mock_session_;
  MoqtSession session_;
};

TEST_F(MoqtSessionTest, Queries) {
  EXPECT_EQ(session_.perspective(), quic::Perspective::IS_CLIENT);
}

// Verify the session sends CLIENT_SETUP on the control stream.
TEST_F(MoqtSessionTest, OnSessionReady) {
  StrictMock<webtransport::test::MockStream> mock_stream;
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
  MoqtParserVisitor* stream_input =
      MoqtSessionPeer::FetchParserVisitorFromWebtransportStreamVisitor(
          &session_, visitor.get());
  // Handle the server setup
  MoqtServerSetup setup = {
      MoqtVersion::kDraft03,
      MoqtRole::kPubSub,
  };
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnServerSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnClientSetup) {
  MoqtSessionParameters server_parameters = {
      /*version=*/MoqtVersion::kDraft03,
      /*perspective=*/quic::Perspective::IS_SERVER,
      /*using_webtrans=*/true,
      /*path=*/"",
      /*deliver_partial_objects=*/false,
  };
  MoqtSession server_session(&mock_session_, server_parameters,
                             session_callbacks_.AsSessionCallbacks());
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream);
  MoqtClientSetup setup = {
      /*supported_versions=*/{MoqtVersion::kDraft03},
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
  StrictMock<webtransport::test::MockStream> mock_stream;
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
  StrictMock<webtransport::test::MockStream> mock_stream;
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
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*authorization_info=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
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
  MockLocalTrackVisitor local_track_visitor;
  session_.AddLocalTrack(FullTrackName("foo", "bar"),
                         MoqtForwardingPreference::kObject,
                         &local_track_visitor);
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
      absl::string_view track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
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
  session_.Announce("foo", announce_resolved_callback.AsStdFunction());
  EXPECT_TRUE(correct_message);

  MoqtAnnounceOk ok = {
      /*track_namespace=*/"foo",
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](absl::string_view track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        correct_message = true;
        EXPECT_EQ(track_namespace, "foo");
        EXPECT_FALSE(error.has_value());
      });
  stream_input->OnAnnounceOkMessage(ok);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithError) {
  testing::MockFunction<void(
      absl::string_view track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
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
  session_.Announce("foo", announce_resolved_callback.AsStdFunction());
  EXPECT_TRUE(correct_message);

  MoqtAnnounceError error = {
      /*track_namespace=*/"foo",
      /*error_code=*/MoqtAnnounceErrorCode::kInternalError,
      /*reason_phrase=*/"Test error",
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](absl::string_view track_namespace,
                    std::optional<MoqtAnnounceErrorReason> error) {
        correct_message = true;
        EXPECT_EQ(track_namespace, "foo");
        ASSERT_TRUE(error.has_value());
        EXPECT_EQ(error->error_code, MoqtAnnounceErrorCode::kInternalError);
        EXPECT_EQ(error->reason_phrase, "Test error");
      });
  stream_input->OnAnnounceErrorMessage(error);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, HasSubscribers) {
  MockLocalTrackVisitor local_track_visitor;
  FullTrackName ftn("foo", "bar");
  EXPECT_FALSE(session_.HasSubscribers(ftn));
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kGroup,
                         &local_track_visitor);
  EXPECT_FALSE(session_.HasSubscribers(ftn));

  // Peer subscribes.
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*authorization_info=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeMessage(request);
  EXPECT_TRUE(correct_message);
  EXPECT_TRUE(session_.HasSubscribers(ftn));
}

TEST_F(MoqtSessionTest, SubscribeForPast) {
  MockLocalTrackVisitor local_track_visitor;
  FullTrackName ftn("foo", "bar");
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kObject,
                         &local_track_visitor);

  // Send Sequence (2, 0) so that next_sequence is set correctly.
  session_.PublishObject(ftn, 2, 0, 0, "foo", true);
  // Peer subscribes to (0, 0)
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*authorization_info=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = true;
  EXPECT_CALL(local_track_visitor, OnSubscribeForPast(_))
      .WillOnce(Return(std::nullopt));
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

TEST_F(MoqtSessionTest, SubscribeWithOk) {
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
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
  session_.SubscribeCurrentGroup("foo", "bar", &remote_track_visitor, "");

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

TEST_F(MoqtSessionTest, SubscribeWithError) {
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
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
  session_.SubscribeCurrentGroup("foo", "bar", &remote_track_visitor, "");

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
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtAnnounce announce = {
      /*track_namespace=*/"foo",
  };
  bool correct_message = false;
  EXPECT_CALL(session_callbacks_.incoming_announce_callback, Call("foo"))
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
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

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
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/16,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, false);
  object_stream->OnObjectMessage(object, payload, true);  // complete the object
}

TEST_F(MoqtSessionTest, IncomingPartialObjectNoBuffer) {
  MoqtSessionParameters parameters = {
      /*version=*/MoqtVersion::kDraft03,
      /*perspective=*/quic::Perspective::IS_CLIENT,
      /*using_webtrans=*/true,
      /*path=*/"",
      /*deliver_partial_objects=*/true,
  };
  MoqtSession session(&mock_session_, parameters,
                      session_callbacks_.AsSessionCallbacks());
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session, ftn, &visitor_, 2);
  MoqtObject object = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/16,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session, &mock_stream);

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
      /*track_namespace=*/ftn.track_namespace,
      /*track_name=*/ftn.track_name,
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor_);
  MoqtObject object = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name,
                    uint64_t group_sequence, uint64_t object_sequence,
                    uint64_t object_send_order,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(group_sequence, object.group_id);
        EXPECT_EQ(object_sequence, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*subscribe_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*largest_id=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_control_stream;
  std::unique_ptr<MoqtParserVisitor> control_stream =
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
      /*track_namespace=*/ftn.track_namespace,
      /*track_name=*/ftn.track_name,
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name,
                    uint64_t group_sequence, uint64_t object_sequence,
                    uint64_t object_send_order,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(group_sequence, object.group_id);
        EXPECT_EQ(object_sequence, object.object_id);
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
  StrictMock<webtransport::test::MockStream> mock_control_stream;
  std::unique_ptr<MoqtParserVisitor> control_stream =
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
      /*track_namespace=*/ftn.track_namespace,
      /*track_name=*/ftn.track_name,
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name,
                    uint64_t group_sequence, uint64_t object_sequence,
                    uint64_t object_send_order,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(group_sequence, object.group_id);
        EXPECT_EQ(object_sequence, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  object.forwarding_preference = MoqtForwardingPreference::kObject;
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
      /*track_namespace=*/ftn.track_namespace,
      /*track_name=*/ftn.track_name,
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
  };
  MoqtSessionPeer::AddActiveSubscribe(&session_, 1, subscribe, &visitor);
  MoqtObject object = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

  EXPECT_CALL(visitor, OnObjectFragment(_, _, _, _, _, _, _))
      .WillOnce([&](const FullTrackName& full_track_name,
                    uint64_t group_sequence, uint64_t object_sequence,
                    uint64_t object_send_order,
                    MoqtForwardingPreference forwarding_preference,
                    absl::string_view payload, bool end_of_message) {
        EXPECT_EQ(full_track_name, ftn);
        EXPECT_EQ(group_sequence, object.group_id);
        EXPECT_EQ(object_sequence, object.object_id);
      });
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);

  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor, 2);
  // The track already exists, and has a different forwarding preference.
  MoqtSessionPeer::remote_track(&session_, 2)
      .CheckForwardingPreference(MoqtForwardingPreference::kObject);

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*subscribe_id=*/1,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
      /*largest_id=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_control_stream;
  std::unique_ptr<MoqtParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Forwarding preference different in early objects"))
      .Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, CreateUniStreamAndSend) {
  StrictMock<webtransport::test::MockStream> mock_stream;
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kObject,
                         &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);

  // No subscription; this is a no-op except to update next_sequence.
  EXPECT_CALL(mock_stream, Writev(_, _)).Times(0);
  session_.PublishObject(ftn, 4, 1, 0, "deadbeef", true);
  EXPECT_EQ(MoqtSessionPeer::next_sequence(&session_, ftn), FullSequence(4, 2));

  // Publish in window.
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  // Send on the stream
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillOnce(Return(&mock_stream));
  bool correct_message = false;
  // Verify first six message fields are sent correctly
  uint8_t kExpectedMessage[] = {0x00, 0x00, 0x02, 0x05, 0x00, 0x00};
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = (0 == memcmp(data.data()->data(), kExpectedMessage,
                                       sizeof(kExpectedMessage)));
        return absl::OkStatus();
      });
  session_.PublishObject(ftn, 5, 0, 0, "deadbeef", true);
  EXPECT_TRUE(correct_message);
}

// TODO: Test operation with multiple streams.

// Error cases

TEST_F(MoqtSessionTest, CannotOpenUniStream) {
  StrictMock<webtransport::test::MockStream> mock_stream;
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kObject,
                         &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);
  ;
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  EXPECT_FALSE(session_.PublishObject(ftn, 5, 0, 0, "deadbeef", true));
}

TEST_F(MoqtSessionTest, GetStreamByIdFails) {
  StrictMock<webtransport::test::MockStream> mock_stream;
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kObject,
                         &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillOnce(Return(nullptr));
  EXPECT_FALSE(session_.PublishObject(ftn, 5, 0, 0, "deadbeef", true));
}

TEST_F(MoqtSessionTest, SubscribeProposesBadTrackAlias) {
  MockLocalTrackVisitor local_track_visitor;
  FullTrackName ftn("foo", "bar");
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kGroup,
                         &local_track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);

  // Peer subscribes.
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/3,  // Doesn't match 2.
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*authorization_info=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  bool correct_message = true;
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

TEST_F(MoqtSessionTest, OneBidirectionalStreamClient) {
  StrictMock<webtransport::test::MockStream> mock_stream;
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
  MoqtSessionParameters server_parameters = {
      /*version=*/MoqtVersion::kDraft03,
      /*perspective=*/quic::Perspective::IS_SERVER,
      /*using_webtrans=*/true,
      /*path=*/"",
      /*deliver_partial_objects=*/false,
  };
  MoqtSession server_session(&mock_session_, server_parameters,
                             session_callbacks_.AsSessionCallbacks());
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&server_session, &mock_stream);
  MoqtClientSetup setup = {
      /*supported_versions*/ {MoqtVersion::kDraft03},
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
  MockLocalTrackVisitor visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kTrack, &visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 1, 3, 4);
  EXPECT_TRUE(session_.HasSubscribers(ftn));
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtUnsubscribe unsubscribe = {
      /*subscribe_id=*/0,
  };
  stream_input->OnUnsubscribeMessage(unsubscribe);
  EXPECT_FALSE(session_.HasSubscribers(ftn));
}

TEST_F(MoqtSessionTest, SendDatagram) {
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, MoqtForwardingPreference::kDatagram,
                         &track_visitor);
  MoqtSessionPeer::AddSubscription(&session_, ftn, 0, 2, 5, 0);

  // Publish in window.
  bool correct_message = false;
  uint8_t kExpectedMessage[] = {
      0x01, 0x00, 0x02, 0x05, 0x00, 0x00, 0x64,
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
  session_.PublishObject(ftn, 5, 0, 0, "deadbeef", true);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, ReceiveDatagram) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_, 2);
  MoqtObject object = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kDatagram,
      /*payload_length=*/8,
  };
  char datagram[] = {0x01, 0x01, 0x02, 0x00, 0x00, 0x00, 0x64,
                     0x65, 0x61, 0x64, 0x62, 0x65, 0x65, 0x66};
  EXPECT_CALL(visitor_,
              OnObjectFragment(ftn, object.group_id, object.object_id,
                               object.object_send_order,
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
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*forwarding_preference=*/MoqtForwardingPreference::kGroup,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

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
      absl::string_view track_namespace,
      std::optional<MoqtAnnounceErrorReason> error_message)>
      announce_resolved_callback;
  EXPECT_CALL(announce_resolved_callback, Call(_, _)).Times(1);
  session_.Announce("foo", announce_resolved_callback.AsStdFunction());
}

TEST_F(MoqtSessionTest, SubscribeFromPublisher) {
  MoqtSessionPeer::set_peer_role(&session_, MoqtRole::kPublisher);
  MoqtSubscribe request = {
      /*subscribe_id=*/1,
      /*track_alias=*/2,
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*start_group=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*start_object=*/MoqtSubscribeLocation(true, static_cast<uint64_t>(0)),
      /*end_group=*/std::nullopt,
      /*end_object=*/std::nullopt,
      /*authorization_info=*/std::nullopt,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
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
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> stream_input =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_stream);
  MoqtAnnounce announce = {
      /*track_namespace=*/"foo",
  };
  EXPECT_CALL(mock_session_,
              CloseSession(static_cast<uint64_t>(MoqtError::kProtocolViolation),
                           "Received ANNOUNCE from Subscriber"))
      .Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_)).Times(1);
  stream_input->OnAnnounceMessage(announce);
}

// TODO: Cover more error cases in the above

}  // namespace test

}  // namespace moqt
