// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <cstdint>
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
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
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
using ::testing::Return;
using ::testing::StrictMock;

constexpr webtransport::StreamId kControlStreamId = 4;
constexpr webtransport::StreamId kIncomingUniStreamId = 15;
constexpr webtransport::StreamId kOutgoingUniStreamId = 14;

constexpr MoqtSessionParameters default_parameters = {
    /*version=*/MoqtVersion::kDraft01,
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
      MoqtSession* session, webtransport::Stream* stream) {
    auto new_stream = std::make_unique<MoqtSession::Stream>(
        session, stream, /*is_control_stream=*/true);
    session->control_stream_ = kControlStreamId;
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

  static void CreateRemoteTrack(MoqtSession* session, FullTrackName& name,
                                RemoteTrack::Visitor* visitor) {
    session->remote_tracks_.try_emplace(name, name, visitor);
  }

  static void CreateRemoteTrackWithAlias(MoqtSession* session,
                                         FullTrackName& name,
                                         RemoteTrack::Visitor* visitor,
                                         uint64_t track_alias) {
    auto it = session->remote_tracks_.try_emplace(name, name, visitor);
    RemoteTrack& track = it.first->second;
    track.set_track_alias(track_alias);
    session->tracks_by_alias_.emplace(std::make_pair(track_alias, &track));
  }

  static LocalTrack& GetLocalTrack(MoqtSession* session, FullTrackName& name) {
    auto it = session->local_tracks_.find(name);
    EXPECT_NE(it, session->local_tracks_.end());
    return it->second;
  }
};

class MoqtSessionTest : public quic::test::QuicTest {
 public:
  MoqtSessionTest()
      : session_(&mock_session_, default_parameters,
                 session_callbacks_.AsSessionCallbacks()) {}

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
  bool correct_message = false;
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
      MoqtVersion::kDraft01,
      MoqtRole::kBoth,
  };
  EXPECT_CALL(session_callbacks_.session_established_callback, Call()).Times(1);
  stream_input->OnServerSetupMessage(setup);
}

TEST_F(MoqtSessionTest, OnClientSetup) {
  MoqtSessionParameters server_parameters = {
      /*version=*/MoqtVersion::kDraft01,
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
      /*supported_versions*/ {MoqtVersion::kDraft01},
      /*role=*/MoqtRole::kBoth,
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
  EXPECT_CALL(mock_session_, CloseSession(1, "foo")).Times(1);
  EXPECT_CALL(session_callbacks_.session_terminated_callback, Call(_))
      .WillOnce([&](absl::string_view error_message) {
        reported_error = (error_message == "foo");
      });
  session_.Error("foo");
  EXPECT_TRUE(reported_error);
}

TEST_F(MoqtSessionTest, AddLocalTrack) {
  MoqtSubscribeRequest request = {
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
  stream_input->OnSubscribeRequestMessage(request);
  EXPECT_TRUE(correct_message);

  // Add the track. Now Subscribe should succeed.
  MockLocalTrackVisitor local_track_visitor;
  session_.AddLocalTrack(FullTrackName("foo", "bar"), &local_track_visitor);
  correct_message = true;
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]), MoqtMessageType::kSubscribeOk);
        return absl::OkStatus();
      });
  stream_input->OnSubscribeRequestMessage(request);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithOk) {
  testing::MockFunction<void(absl::string_view track_namespace,
                             std::optional<absl::string_view> error_message)>
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
                    std::optional<absl::string_view> error_message) {
        correct_message = true;
        EXPECT_EQ(track_namespace, "foo");
        EXPECT_FALSE(error_message.has_value());
      });
  stream_input->OnAnnounceOkMessage(ok);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, AnnounceWithError) {
  testing::MockFunction<void(absl::string_view track_namespace,
                             std::optional<absl::string_view> error_message)>
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
  };
  correct_message = false;
  EXPECT_CALL(announce_resolved_callback, Call(_, _))
      .WillOnce([&](absl::string_view track_namespace,
                    std::optional<absl::string_view> error_message) {
        correct_message = true;
        EXPECT_EQ(track_namespace, "foo");
        EXPECT_TRUE(error_message.has_value());
      });
  stream_input->OnAnnounceErrorMessage(error);
  EXPECT_TRUE(correct_message);
}

TEST_F(MoqtSessionTest, HasSubscribers) {
  MockLocalTrackVisitor local_track_visitor;
  FullTrackName ftn("foo", "bar");
  EXPECT_FALSE(session_.HasSubscribers(ftn));
  session_.AddLocalTrack(ftn, &local_track_visitor);
  EXPECT_FALSE(session_.HasSubscribers(ftn));

  // Peer subscribes.
  MoqtSubscribeRequest request = {
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
  stream_input->OnSubscribeRequestMessage(request);
  EXPECT_TRUE(correct_message);
  EXPECT_TRUE(session_.HasSubscribers(ftn));
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
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeRequest);
        return absl::OkStatus();
      });
  session_.SubscribeCurrentGroup("foo", "bar", &remote_track_visitor, "");

  MoqtSubscribeOk ok = {
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*track_id=*/0,
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
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kSubscribeRequest);
        return absl::OkStatus();
      });
  session_.SubscribeCurrentGroup("foo", "bar", &remote_track_visitor, "");

  MoqtSubscribeError error = {
      /*track_namespace=*/"foo",
      /*track_name=*/"bar",
      /*error_code=*/1,
      /*reason_phrase=*/"deadbeef",
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
  MoqtSessionPeer::CreateRemoteTrackWithAlias(&session_, ftn, &visitor_, 0);
  MoqtObject object = {
      /*track_id=*/0,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
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
  MoqtSessionPeer::CreateRemoteTrackWithAlias(&session_, ftn, &visitor_, 0);
  MoqtObject object = {
      /*track_id=*/0,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
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
      /*version=*/MoqtVersion::kDraft01,
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
  MoqtSessionPeer::CreateRemoteTrackWithAlias(&session, ftn, &visitor_, 0);
  MoqtObject object = {
      /*track_id=*/0,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
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

TEST_F(MoqtSessionTest, IncomingObjectUnknownTrackId) {
  MockRemoteTrackVisitor visitor_;
  FullTrackName ftn("foo", "bar");
  std::string payload = "deadbeef";
  MoqtSessionPeer::CreateRemoteTrack(&session_, ftn, &visitor_);
  MoqtObject object = {
      /*track_id=*/0,
      /*group_sequence=*/0,
      /*object_sequence=*/0,
      /*object_send_order=*/0,
      /*payload_length=*/8,
  };
  StrictMock<webtransport::test::MockStream> mock_stream;
  std::unique_ptr<MoqtParserVisitor> object_stream =
      MoqtSessionPeer::CreateUniStream(&session_, &mock_stream);

  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(0);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kIncomingUniStreamId));
  object_stream->OnObjectMessage(object, payload, true);
  // Packet should be buffered.

  // SUBSCRIBE_OK arrives
  MoqtSubscribeOk ok = {
      /*track_namespace=*/ftn.track_namespace,
      /*track_name=*/ftn.track_name,
      /*track_id=*/0,
      /*expires=*/quic::QuicTimeDelta::FromMilliseconds(0),
  };
  StrictMock<webtransport::test::MockStream> mock_control_stream;
  std::unique_ptr<MoqtParserVisitor> control_stream =
      MoqtSessionPeer::CreateControlStream(&session_, &mock_control_stream);
  EXPECT_CALL(visitor_, OnReply(_, _)).Times(1);
  EXPECT_CALL(visitor_, OnObjectFragment(_, _, _, _, _, _, _)).Times(1);
  control_stream->OnSubscribeOkMessage(ok);
}

TEST_F(MoqtSessionTest, CreateUniStreamAndSend) {
  StrictMock<webtransport::test::MockStream> mock_stream;
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, SetVisitor(_)).Times(1);
  EXPECT_CALL(mock_stream, GetStreamId())
      .WillRepeatedly(Return(kOutgoingUniStreamId));
  std::optional<webtransport::StreamId> stream =
      session_.OpenUnidirectionalStream();
  EXPECT_TRUE(stream.has_value());
  EXPECT_EQ(stream.value(), kOutgoingUniStreamId);

  // Send on the stream
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillOnce(Return(&mock_stream));
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, &track_visitor);
  LocalTrack& track = MoqtSessionPeer::GetLocalTrack(&session_, ftn);
  FullSequence& next_seq = track.next_sequence_mutable();
  next_seq.group = 4;
  next_seq.object = 1;
  track.AddWindow(SubscribeWindow(5, 0));
  // No subscription; this is a no-op except for incrementing the sequence
  // number.
  EXPECT_CALL(mock_stream, Writev(_, _)).Times(0);
  session_.PublishObjectToStream(kOutgoingUniStreamId,
                                 FullTrackName("foo", "bar"),
                                 /*start_new_group=*/false, "deadbeef");
  EXPECT_EQ(next_seq, FullSequence(4, 2));
  bool correct_message = false;
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillOnce(Return(&mock_stream));
  EXPECT_CALL(mock_stream, Writev(_, _))
      .WillOnce([&](absl::Span<const absl::string_view> data,
                    const quiche::StreamWriteOptions& options) {
        correct_message = true;
        EXPECT_EQ(*ExtractMessageType(data[0]),
                  MoqtMessageType::kObjectWithPayloadLength);
        return absl::OkStatus();
      });
  session_.PublishObjectToStream(kOutgoingUniStreamId,
                                 FullTrackName("foo", "bar"),
                                 /*start_new_group=*/true, "deadbeef");
  EXPECT_TRUE(correct_message);
  EXPECT_EQ(next_seq, FullSequence(5, 1));
}

// Error cases

TEST_F(MoqtSessionTest, CannotOpenUniStream) {
  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(false));
  std::optional<webtransport::StreamId> stream =
      session_.OpenUnidirectionalStream();
  EXPECT_FALSE(stream.has_value());

  EXPECT_CALL(mock_session_, CanOpenNextOutgoingUnidirectionalStream())
      .WillOnce(Return(true));
  EXPECT_CALL(mock_session_, OpenOutgoingUnidirectionalStream())
      .WillOnce(Return(nullptr));
  stream = session_.OpenUnidirectionalStream();
  EXPECT_FALSE(stream.has_value());
}

TEST_F(MoqtSessionTest, CannotPublishToStream) {
  EXPECT_CALL(mock_session_, GetStreamById(kOutgoingUniStreamId))
      .WillOnce(Return(nullptr));
  FullTrackName ftn("foo", "bar");
  MockLocalTrackVisitor track_visitor;
  session_.AddLocalTrack(ftn, &track_visitor);
  LocalTrack& track = MoqtSessionPeer::GetLocalTrack(&session_, ftn);
  FullSequence& next_seq = track.next_sequence_mutable();
  next_seq.group = 4;
  next_seq.object = 1;
  session_.PublishObjectToStream(kOutgoingUniStreamId, ftn,
                                 /*start_new_group=*/false, "deadbeef");
  // Object not sent; no change in sequence number.
  EXPECT_EQ(next_seq.group, 4);
  EXPECT_EQ(next_seq.object, 1);
}

// TODO: Cover more error cases in the above

}  // namespace test

}  // namespace moqt
