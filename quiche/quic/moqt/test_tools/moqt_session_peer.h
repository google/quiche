// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_SESSION_PEER_H_
#define QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_SESSION_PEER_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/casts.h"
#include "absl/base/nullability.h"
#include "absl/container/flat_hash_set.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_subscription.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_data_reader.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {

class MoqtDataParserPeer {
 public:
  static void SetType(MoqtDataParser* parser, MoqtDataStreamType type) {
    parser->type_ = type;
    parser->next_input_ = MoqtDataParser::NextInput::kTrackAlias;
  }
  static void SetTrackAlias(MoqtDataParser* parser, uint64_t track_alias) {
    parser->metadata_.track_alias = track_alias;
    parser->next_input_ = MoqtDataParser::NextInput::kGroupId;
  }
};

// Helper class to interact with MOQT bidi streams in tests.
class MoqtBidiStreamTestWrapper {
 public:
  explicit MoqtBidiStreamTestWrapper(
      std::unique_ptr<MoqtBidiStreamBase> absl_nonnull stream)
      : stream_(std::move(stream)) {}

  MoqtBidiStreamBase& stream() { return *stream_; }

  // Simulates receiving the specified control message on the bidi stream.
  void ReceiveMessage(const AnyMoqtControlMessage& message) {
    std::string serialized = SerializeGenericMessage(message);
    quiche::QuicheDataReader reader(serialized);
    uint64_t raw_type;
    ASSERT_TRUE(reader.ReadVarInt62(&raw_type));
    ASSERT_TRUE(reader.Seek(2));
    absl::Status status = stream_->OnRawControlMessage(MoqtRawControlMessage{
        .type = static_cast<MoqtMessageType>(raw_type),
        .payload = std::string(reader.ReadRemainingPayload())});
    stream_->CheckStatus(status);
  }

 private:
  std::unique_ptr<MoqtBidiStreamBase> absl_nonnull stream_;
};

class OutgoingSubgroupStreamPeer {
 public:
  static quic::QuicAlarm* GetAlarm(OutgoingSubgroupStream* stream) {
    return stream->delivery_timeout_alarm_.get();
  }
};

class MoqtSessionPeer {
 public:
  static constexpr webtransport::StreamId kControlStreamId = 4;

  static std::unique_ptr<MoqtBidiStreamTestWrapper> CreateControlStream(
      MoqtSession* session, webtransport::test::MockStream* stream) {
    auto new_stream = std::make_unique<MoqtSession::ControlStream>(session);
    session->control_stream_ = new_stream->GetWeakPtr();
    new_stream->BindStream(stream);
    ON_CALL(*stream, visitor())
        .WillByDefault(::testing::Return(new_stream.get()));
    ON_CALL(*stream, CanWrite).WillByDefault(::testing::Return(true));
    return std::make_unique<MoqtBidiStreamTestWrapper>(std::move(new_stream));
  }

  static std::unique_ptr<MoqtDataParserVisitor> CreateIncomingDataStream(
      MoqtSession* session, webtransport::Stream* stream,
      MoqtDataStreamType type,
      std::optional<uint64_t> track_alias = std::nullopt,
      SubscribeVisitor* visitor = nullptr) {
    auto new_stream = std::make_unique<IncomingDataStream>(
        stream, session, session->callbacks_.clock);
    MoqtDataParserPeer::SetType(&new_stream->parser_, type);
    if (track_alias.has_value()) {
      MoqtDataParserPeer::SetTrackAlias(&new_stream->parser_, *track_alias);
      new_stream->visitor_ = visitor;
    }
    return new_stream;
  }

  static std::unique_ptr<webtransport::StreamVisitor>
  CreateIncomingStreamVisitor(MoqtSession* session,
                              webtransport::Stream* stream) {
    auto new_stream = std::make_unique<IncomingDataStream>(
        stream, session, session->callbacks_.clock);
    return new_stream;
  }

  static bool RequestIdIsSubscriptionPublisher(MoqtSession* session,
                                               uint64_t request_id) {
    return session->published_subscriptions_.contains(request_id);
  }

  // In the test OnSessionReady, the session creates a stream and then passes
  // its unique_ptr to the mock webtransport stream. This function casts
  // that unique_ptr into a MoqtSession::Stream*, which is a private class of
  // MoqtSession, and then casts again into MoqtParserVisitor so that the test
  // can inject packets into that stream.
  // This function is useful for any test that wants to inject packets on a
  // stream created by the MoqtSession.
  static std::unique_ptr<MoqtBidiStreamTestWrapper>
  FetchParserVisitorFromWebtransportStreamVisitor(
      std::unique_ptr<webtransport::StreamVisitor> visitor) {
    return std::make_unique<MoqtBidiStreamTestWrapper>(absl::WrapUnique(
        absl::down_cast<MoqtSession::ControlStream*>(visitor.release())));
  }

  static SubscribeRemoteTrack* remote_track(MoqtSession* session,
                                            uint64_t track_alias) {
    return session->RemoteTrackByAlias(track_alias);
  }

  static void set_next_request_id(MoqtSession* session, uint64_t id) {
    session->next_request_id_ = id;
  }

  static void set_peer_max_request_id(MoqtSession* session, uint64_t id) {
    session->peer_max_request_id_ = id;
  }

  static MoqtSession::PublishedFetch* GetFetch(MoqtSession* session,
                                               uint64_t fetch_id) {
    auto it = session->incoming_fetches_.find(fetch_id);
    if (it == session->incoming_fetches_.end()) {
      return nullptr;
    }
    return it->second.get();
  }

  static void ValidateRequestId(MoqtSession* session, uint64_t id) {
    session->ValidateRequestId(id);
  }

  // Adds an upstream fetch and a stream ready to receive data.
  static std::unique_ptr<MoqtFetchTask> CreateUpstreamFetch(
      MoqtSession* session, webtransport::Stream* stream) {
    MoqtFetch fetch_message = {
        0,
        StandaloneFetch(FullTrackName{"foo", "bar"}, Location{0, 0},
                        Location{4, kMaxObjectId}),
        MessageParameters(),
    };
    std::unique_ptr<MoqtFetchTask> task;
    auto [it, success] = session->upstream_by_id_.try_emplace(
        0, std::make_unique<UpstreamFetch>(
               fetch_message, std::get<StandaloneFetch>(fetch_message.fetch),
               [&](std::unique_ptr<MoqtFetchTask> fetch_task) {
                 task = std::move(fetch_task);
               },
               [session = session]() { session->upstream_by_id_.erase(0); }));
    QUICHE_DCHECK(success);
    UpstreamFetch* fetch = absl::down_cast<UpstreamFetch*>(it->second.get());
    // Initialize the fetch task
    fetch->OnFetchResult(
        Location{4, 10}, absl::OkStatus(),
        [=, session_ptr = session, request_id = fetch_message.request_id]() {
          session_ptr->CancelFetch(request_id);
        });
    ;
    auto mock_session =
        absl::down_cast<webtransport::test::MockSession*>(session->session());
    EXPECT_CALL(*mock_session, AcceptIncomingUnidirectionalStream())
        .WillOnce(testing::Return(stream))
        .WillOnce(testing::Return(nullptr));
    session->OnIncomingUnidirectionalStreamAvailable();
    return task;
  }

  static quic::QuicAlarmFactory* GetAlarmFactory(MoqtSession* session) {
    return session->alarm_factory_.get();
  }

  static quic::QuicTime Now(MoqtSession* session) {
    return session->callbacks_.clock->ApproximateNow();
  }

  static quic::QuicAlarm* GetPublishDoneAlarm(
      SubscribeRemoteTrack* subscription) {
    return subscription->publish_done_alarm_.get();
  }

  static quic::QuicAlarm* GetGoAwayTimeoutAlarm(MoqtSession* session) {
    return session->goaway_timeout_alarm_.get();
  }

  static quic::QuicTimeDelta GetDeliveryTimeout(MoqtSession* session,
                                                uint64_t request_id) {
    auto it = session->published_subscriptions_.find(request_id);
    if (it == session->published_subscriptions_.end()) {
      return quic::QuicTimeDelta::Zero();
    }
    return it->second->delivery_timeout();
  }

  static absl::string_view GetImplementationString(MoqtSession* session) {
    return session->parameters_.moqt_implementation;
  }

  static MoqtSession::ControlStream* GetControlStream(MoqtSession* session) {
    return session->control_stream_.GetIfAvailable();
  }

  static const MoqtSessionParameters& GetParameters(MoqtSession* session) {
    return session->parameters_;
  }

  static std::optional<uint64_t> NextQueuedRequestIdToServer(
      MoqtSession* session) {
    return session->subscriptions_with_queued_streams_.empty()
               ? std::optional<uint64_t>()
               : session->subscriptions_with_queued_streams_.begin()->second;
  }
};

}  // namespace moqt::test

#endif  // QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_SESSION_PEER_H_
