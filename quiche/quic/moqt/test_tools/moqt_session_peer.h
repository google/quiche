// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_SESSION_PEER_H_
#define QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_SESSION_PEER_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moqt_mock_visitor.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt::test {

class MoqtDataParserPeer {
 public:
  static void SetType(MoqtDataParser* parser, MoqtDataStreamType type) {
    parser->type_ = type;
  }
};

class MoqtSessionPeer {
 public:
  static constexpr webtransport::StreamId kControlStreamId = 4;

  static std::unique_ptr<MoqtControlParserVisitor> CreateControlStream(
      MoqtSession* session, webtransport::test::MockStream* stream) {
    auto new_stream =
        std::make_unique<MoqtSession::ControlStream>(session, stream);
    session->control_stream_ = kControlStreamId;
    ON_CALL(*stream, visitor())
        .WillByDefault(::testing::Return(new_stream.get()));
    webtransport::test::MockSession* mock_session =
        static_cast<webtransport::test::MockSession*>(session->session());
    EXPECT_CALL(*mock_session, GetStreamById(kControlStreamId))
        .Times(::testing::AnyNumber())
        .WillRepeatedly(::testing::Return(stream));
    return new_stream;
  }

  static std::unique_ptr<MoqtDataParserVisitor> CreateIncomingDataStream(
      MoqtSession* session, webtransport::Stream* stream,
      MoqtDataStreamType type) {
    auto new_stream =
        std::make_unique<MoqtSession::IncomingDataStream>(session, stream);
    MoqtDataParserPeer::SetType(&new_stream->parser_, type);
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

  static void CreateRemoteTrack(MoqtSession* session,
                                const MoqtSubscribe& subscribe,
                                SubscribeRemoteTrack::Visitor* visitor) {
    auto track = std::make_unique<SubscribeRemoteTrack>(subscribe, visitor);
    session->subscribe_by_alias_.try_emplace(subscribe.track_alias,
                                             track.get());
    session->subscribe_by_name_.try_emplace(subscribe.full_track_name,
                                            track.get());
    session->upstream_by_id_.try_emplace(subscribe.subscribe_id,
                                         std::move(track));
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

  static SubscribeRemoteTrack* remote_track(MoqtSession* session,
                                            uint64_t track_alias) {
    return session->RemoteTrackByAlias(track_alias);
  }

  static void set_next_subscribe_id(MoqtSession* session, uint64_t id) {
    session->next_subscribe_id_ = id;
  }

  static void set_peer_max_subscribe_id(MoqtSession* session, uint64_t id) {
    session->peer_max_subscribe_id_ = id;
  }

  static MockFetchTask* AddFetch(MoqtSession* session, uint64_t fetch_id) {
    auto fetch_task = std::make_unique<MockFetchTask>();
    MockFetchTask* return_ptr = fetch_task.get();
    auto published_fetch = std::make_unique<MoqtSession::PublishedFetch>(
        fetch_id, session, std::move(fetch_task));
    session->incoming_fetches_.emplace(fetch_id, std::move(published_fetch));
    // Add the fetch to the pending stream queue.
    session->UpdateQueuedSendOrder(fetch_id, std::nullopt, 0);
    return return_ptr;
  }

  static MoqtSession::PublishedFetch* GetFetch(MoqtSession* session,
                                               uint64_t fetch_id) {
    auto it = session->incoming_fetches_.find(fetch_id);
    if (it == session->incoming_fetches_.end()) {
      return nullptr;
    }
    return it->second.get();
  }

  static void ValidateSubscribeId(MoqtSession* session, uint64_t id) {
    session->ValidateSubscribeId(id);
  }

  static FullSequence LargestSentForSubscription(MoqtSession* session,
                                                 uint64_t subscribe_id) {
    return *session->published_subscriptions_[subscribe_id]->largest_sent();
  }
};

}  // namespace moqt::test

#endif  // QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_SESSION_PEER_H_