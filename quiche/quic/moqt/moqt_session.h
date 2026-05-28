// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_SESSION_H_
#define QUICHE_QUIC_MOQT_MOQT_SESSION_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/cleanup/cleanup.h"
#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_subscription.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/quic/moqt/session_namespace_tree.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_circular_deque.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {
class MoqtSessionPeer;
}

inline constexpr quic::QuicTimeDelta kDefaultGoAwayTimeout =
    quic::QuicTime::Delta::FromSeconds(10);

class QUICHE_EXPORT MoqtSession : public MoqtSessionInterface,
                                  public SessionToPublisherInterface,
                                  public SessionToUniStreamInterface,
                                  public webtransport::SessionVisitor {
 public:
  MoqtSession(webtransport::Session* session, MoqtSessionParameters parameters,
              std::unique_ptr<quic::QuicAlarmFactory> alarm_factory,
              MoqtSessionCallbacks callbacks = MoqtSessionCallbacks());
  ~MoqtSession() {
    CleanUpState();
    std::move(callbacks_.session_deleted_callback)();
  }

  // webtransport::SessionVisitor implementation.
  void OnSessionReady() override;
  void OnSessionClosed(webtransport::SessionErrorCode,
                       const std::string&) override;
  void OnIncomingBidirectionalStreamAvailable() override;
  void OnIncomingUnidirectionalStreamAvailable() override;
  void OnDatagramReceived(absl::string_view datagram) override;
  void OnCanCreateNewOutgoingBidirectionalStream() override;
  void OnCanCreateNewOutgoingUnidirectionalStream() override;

  quic::Perspective perspective() const { return parameters_.perspective; }

  // MoqtSessionInterface implementation.
  MoqtSessionCallbacks& callbacks() override { return callbacks_; }
  void Error(MoqtError code, absl::string_view error) override;
  // Returns false if the SUBSCRIBE isn't sent.
  bool Subscribe(const FullTrackName& name, SubscribeVisitor* visitor,
                 const MessageParameters& parameters) override;
  bool SubscribeUpdate(const FullTrackName& name,
                       const MessageParameters& parameters,
                       MoqtResponseCallback response_callback) override;
  void Unsubscribe(const FullTrackName& name) override;
  bool Fetch(const FullTrackName& name, FetchResponseCallback callback,
             Location start, uint64_t end_group,
             std::optional<uint64_t> end_object,
             MessageParameters parameters) override;
  bool RelativeJoiningFetch(const FullTrackName& name,
                            SubscribeVisitor* visitor,
                            uint64_t num_previous_groups,
                            MessageParameters parameters) override;
  bool RelativeJoiningFetch(const FullTrackName& name,
                            SubscribeVisitor* visitor,
                            FetchResponseCallback callback,
                            uint64_t num_previous_groups,
                            MessageParameters parameters) override;
  bool PublishNamespace(const TrackNamespace& track_namespace,
                        const MessageParameters& parameters,
                        MoqtResponseCallback response_callback,
                        quiche::SingleUseCallback<void(MoqtRequestErrorInfo)>
                            cancel_callback) override;
  bool PublishNamespaceUpdate(const TrackNamespace& track_namespace,
                              MessageParameters& parameters,
                              MoqtResponseCallback response_callback) override;
  bool PublishNamespaceDone(const TrackNamespace& track_namespace) override;
  bool PublishNamespaceCancel(const TrackNamespace& track_namespace,
                              RequestErrorCode error_code,
                              absl::string_view error_reason) override;
  // TODO(martinduke): Support PUBLISH. For now, PUBLISH-only requests will be
  // rejected with nullptr, and kBoth requests will change to kNamespace.
  // After receiving MoqtNamespaceTask, call
  // MoqtNamespaceTask::SetObjectsAvailableCallback() to actually retrieve
  // namespaces.
  std::unique_ptr<MoqtNamespaceTask> SubscribeNamespace(
      TrackNamespace& prefix, SubscribeNamespaceOption option,
      const MessageParameters& parameters,
      MoqtResponseCallback response_callback) override;
  quiche::QuicheWeakPtr<MoqtSessionInterface> GetWeakPtr() override {
    return weak_ptr_factory_.Create();
  }

  // SessionToPublisherInterface implementation.
  bool alternate_delivery_timeout() const override {
    return alternate_delivery_timeout_;
  }
  // If |old_priority| is nullopt, the subscription does not have any pending
  // streams. If it has a value, |old_priority| is the old value to be replaced
  // by |new_priority|.
  void UpdateTrackPriority(uint64_t request_id,
                           std::optional<MoqtTrackPriority> old_priority,
                           MoqtTrackPriority new_priority) override;
  quic::QuicAlarmFactory* alarm_factory() override {
    return alarm_factory_.get();
  }
  void PublishIsDone(uint64_t request_id) override;
  webtransport::Session* session() override {
    return is_closing_ ? nullptr : session_;
  }

  // SessionToUniStreamInterface implementation.
  bool deliver_partial_objects() const {
    return parameters_.deliver_partial_objects;
  }
  // Called when the incoming track is malformed per Section 2.5 of
  // draft-ietf-moqt-moq-transport-12. Unsubscribe and notify the application so
  // the error can be propagated downstream, if necessary.
  void OnMalformedTrack(RemoteTrack* track);
  quiche::QuicheWeakPtr<RemoteTrack> GetSubscribe(uint64_t track_alias) {
    auto it = subscribe_by_alias_.find(track_alias);
    if (it == subscribe_by_alias_.end()) {
      return quiche::QuicheWeakPtr<RemoteTrack>();
    }
    return it->second->weak_ptr();
  }
  quiche::QuicheWeakPtr<RemoteTrack> GetFetch(uint64_t request_id) {
    auto it = upstream_by_id_.find(request_id);
    if (it == upstream_by_id_.end()) {
      return quiche::QuicheWeakPtr<RemoteTrack>();
    }
    return it->second->weak_ptr();
  }
  // Error() defined in MoqtSessionInterface.

  // Send a GOAWAY message to the peer. |new_session_uri| must be empty if
  // called by the client.
  void GoAway(absl::string_view new_session_uri);

  MoqtPublisher* publisher() { return publisher_; }
  void set_publisher(MoqtPublisher* publisher) { publisher_ = publisher; }
  bool support_object_acks() const { return parameters_.support_object_acks; }
  void set_support_object_acks(bool value) {
    QUICHE_DCHECK(!control_stream_.IsValid())
        << "support_object_acks needs to be set before handshake";
    parameters_.support_object_acks = value;
  }

  // Assigns a monitoring interface for a specific track subscription that is
  // expected to happen in the future.  `interface` will be only used for a
  // single subscription, and it must outlive the session.
  void SetMonitoringInterfaceForTrack(
      FullTrackName track, MoqtPublishingMonitorInterface* interface) {
    monitoring_interfaces_for_published_tracks_.emplace(std::move(track),
                                                        interface);
  }

  void Close() {
    session_->CloseSession(0, "Application closed");
    CleanUpState();
  }

  void GrantMoreRequests(uint64_t num_requests);

  void UseAlternateDeliveryTimeout() { alternate_delivery_timeout_ = true; }

  MoqtTraceRecorder& trace_recorder() { return trace_recorder_; }

 private:
  friend class test::MoqtSessionPeer;

  struct Empty {};

  // A stream is open, but we don't know the type until we receive a message.
  class QUICHE_EXPORT UnknownBidiStream : public webtransport::StreamVisitor {
   public:
    // Constructor for a stream initiated by the remote peer. The caller is
    // responsible for calling stream->SetVisitor().
    UnknownBidiStream(MoqtSession* session,
                      webtransport::Stream* absl_nonnull stream)
        : session_(session),
          stream_(stream),
          parser_(std::make_unique<MoqtControlStreamParser>(stream)) {}
    ~UnknownBidiStream() {}

    // webtransport::StreamVisitor overrides.
    void OnResetStreamReceived(webtransport::StreamErrorCode error) override {}
    void OnStopSendingReceived(webtransport::StreamErrorCode error) override {}
    void OnWriteSideInDataRecvdState() override {}
    void OnCanRead() override;
    void OnCanWrite() override {}

   private:
    MoqtSession* session_;
    webtransport::Stream* stream_;
    std::unique_ptr<MoqtControlStreamParser> parser_;
  };

  class QUICHE_EXPORT ControlStream : public MoqtBidiStreamBase {
   public:
    explicit ControlStream(MoqtSession* session)
        : MoqtBidiStreamBase(
              &session->framer_, session->ControlMessageParser(),
              // Do nothing on deletion. It threw an error on RESET_STREAM or
              // FIN, and we're here because the session is being destroyed.
              []() {},
              [session](MoqtError code, absl::string_view reason) {
                session->control_stream_ =
                    quiche::QuicheWeakPtr<ControlStream>();
                if (!session->is_closing_) {
                  session->Error(code, reason);
                }
              }),
          session_(session),
          weak_ptr_factory_(this) {}

    void OnStreamBound() override;
    absl::Status OnRawControlMessage(
        const MoqtRawControlMessage& message) override;

    // MoqtControlParserVisitor implementation.
    absl::Status OnControlMessage(const MoqtClientSetup& message);
    absl::Status OnControlMessage(const MoqtServerSetup& message);
    absl::Status OnControlMessage(const MoqtRequestOk& message);
    absl::Status OnControlMessage(const MoqtRequestError& message);
    absl::Status OnControlMessage(const MoqtSubscribe& message);
    absl::Status OnControlMessage(const MoqtSubscribeOk& message);
    absl::Status OnControlMessage(const MoqtUnsubscribe& message);
    absl::Status OnControlMessage(const MoqtPublishDone& /*message*/);
    absl::Status OnControlMessage(const MoqtRequestUpdate& message);
    absl::Status OnControlMessage(const MoqtPublishNamespace& message);
    absl::Status OnControlMessage(const MoqtPublishNamespaceDone& /*message*/);
    absl::Status OnControlMessage(const MoqtPublishNamespaceCancel& message);
    absl::Status OnControlMessage(const MoqtTrackStatus& message);
    absl::Status OnControlMessage(const MoqtGoAway& /*message*/);
    absl::Status OnControlMessage(const MoqtMaxRequestId& message);
    absl::Status OnControlMessage(const MoqtFetch& message);
    absl::Status OnControlMessage(const MoqtFetchCancel& /*message*/) {
      return absl::OkStatus();
    }
    absl::Status OnControlMessage(const MoqtFetchOk& message);
    absl::Status OnControlMessage(const MoqtRequestsBlocked& message);
    absl::Status OnControlMessage(const MoqtPublish& message);
    absl::Status OnControlMessage(const MoqtObjectAck& message) {
      auto subscription_it =
          session_->published_subscriptions_.find(message.subscribe_id);
      if (subscription_it == session_->published_subscriptions_.end()) {
        return absl::OkStatus();
      }
      subscription_it->second->ProcessObjectAck(message);
      return absl::OkStatus();
    }

    // webtransport::StreamVisitor overrides
    void OnResetStreamReceived(webtransport::StreamErrorCode error) override {
      session_->Error(MoqtError::kProtocolViolation,
                      "Control stream reset received");
    }
    void OnStopSendingReceived(webtransport::StreamErrorCode error) override {
      session_->Error(MoqtError::kProtocolViolation,
                      "Control stream stop sending received");
    }

    quic::Perspective perspective() const {
      return session_->parameters_.perspective;
    }
    quiche::QuicheWeakPtr<ControlStream> GetWeakPtr() {
      return weak_ptr_factory_.Create();
    }

   private:
    friend class test::MoqtSessionPeer;

    MoqtSession* session_;
    // Must be last.
    quiche::QuicheWeakPtrFactory<ControlStream> weak_ptr_factory_;
  };

  class QUICHE_EXPORT PublishedFetch {
   public:
    PublishedFetch(uint64_t request_id, std::unique_ptr<MoqtFetchTask> fetch)
        : request_id_(request_id), fetch_(std::move(fetch)) {}

    MoqtFetchTask* fetch_task_ptr() { return fetch_.get(); }
    // Can only be called once.
    std::unique_ptr<MoqtFetchTask> release_fetch_task() {
      auto on_return = absl::MakeCleanup([this] { fetch_ = nullptr; });
      return std::move(fetch_);
    }
    uint64_t request_id() const { return request_id_; }
    void SetStreamId(webtransport::StreamId id) { stream_id_ = id; }

   private:
    uint64_t request_id_;
    // Store the stream ID in case a FETCH_CANCEL requires a reset.
    std::optional<webtransport::StreamId> stream_id_;
    // Temporary storage until the stream is created.
    std::unique_ptr<MoqtFetchTask> fetch_;
  };

  class QUICHE_EXPORT DownstreamTrackStatus : public MoqtObjectListener {
   public:
    DownstreamTrackStatus(uint64_t request_id,
                          MoqtSession* absl_nonnull session,
                          MoqtTrackPublisher* absl_nonnull publisher)
        : request_id_(request_id), session_(session), publisher_(publisher) {}
    ~DownstreamTrackStatus() {
      if (publisher_ != nullptr) {
        publisher_->RemoveObjectListener(this);
      }
    }
    DownstreamTrackStatus(const DownstreamTrackStatus&) = delete;
    DownstreamTrackStatus(DownstreamTrackStatus&&) = delete;

    void OnSubscribeAccepted() override {
      if (publisher_ == nullptr) {
        QUICHE_NOTREACHED();
        return;
      }
      MessageParameters parameters;
      parameters.expires = publisher_->expiration();
      parameters.largest_object = publisher_->largest_location();
      MoqtBidiStreamBase* control_stream = session_->GetControlStream();
      if (control_stream != nullptr) {
        control_stream->CheckStatus(
            control_stream->SendRequestOk(request_id_, parameters));
      }
      session_->incoming_track_status_.erase(request_id_);
      // No class access below this line!
    }

    void OnSubscribeRejected(MoqtRequestErrorInfo info) override {
      MoqtBidiStreamBase* control_stream = session_->GetControlStream();
      if (control_stream != nullptr) {
        control_stream->CheckStatus(control_stream->SendRequestError(
            request_id_, info.error_code, info.retry_interval,
            info.reason_phrase));
      }
      session_->incoming_track_status_.erase(request_id_);
      // No class access below this line!
    }

    void OnNewObjectAvailable(Location, std::optional<uint64_t> /*subgroup*/,
                              MoqtPriority) override {}
    void OnNewFinAvailable(Location /*location*/,
                           uint64_t /*subgroup*/) override {}
    void OnSubgroupAbandoned(
        uint64_t /*group*/, uint64_t /*subgroup*/,
        webtransport::StreamErrorCode /*error_code*/) override {}
    void OnGroupAbandoned(uint64_t /*group_id*/) override {}
    void OnTrackPublisherGone() override {
      publisher_ = nullptr;
      OnSubscribeRejected(MoqtRequestErrorInfo(RequestErrorCode::kDoesNotExist,
                                               std::nullopt,
                                               "Track publisher gone"));
    }

   private:
    uint64_t request_id_;
    MoqtSession* session_;
    MoqtTrackPublisher* publisher_;
  };

  class GoAwayTimeoutDelegate : public quic::QuicAlarm::DelegateWithoutContext {
   public:
    explicit GoAwayTimeoutDelegate(MoqtSession* session) : session_(session) {}
    void OnAlarm() override;

   private:
    MoqtSession* session_;
  };

  // Returns the pointer to the control stream, or nullptr if none is present.
  ControlStream* GetControlStream() { return control_stream_.GetIfAvailable(); }
  // Sends a message on the control stream; QUICHE_DCHECKs if no control stream
  // is present.
  void SendControlMessage(quiche::QuicheBuffer message);

  // Returns false if creation failed.
  [[nodiscard]] bool OpenDataStream(PublishedFetch* fetch,
                                    webtransport::SendOrder send_order);

  SubscribeRemoteTrack* RemoteTrackByAlias(uint64_t track_alias);
  RemoteTrack* RemoteTrackById(uint64_t request_id);
  SubscribeRemoteTrack* RemoteTrackByName(const FullTrackName& name);

  // Checks that a subscribe ID from a SUBSCRIBE or FETCH is valid, and throws
  // a session error if is not.
  bool ValidateRequestId(uint64_t request_id);

  void CancelFetch(uint64_t request_id);

  // Sends an OBJECT_ACK message for a specific subscribe ID.
  void SendObjectAck(uint64_t subscribe_id, uint64_t group_id,
                     uint64_t object_id,
                     quic::QuicTimeDelta delta_from_deadline) {
    if (!SupportsObjectAck()) {
      return;
    }
    MoqtObjectAck ack;
    ack.subscribe_id = subscribe_id;
    ack.group_id = group_id;
    ack.object_id = object_id;
    ack.delta_from_deadline = delta_from_deadline;
    SendControlMessage(framer_.SerializeObjectAck(ack));
  }

  // Indicates if OBJECT_ACK is supported by both sides.
  bool SupportsObjectAck() const {
    return parameters_.support_object_acks && peer_supports_object_ack_;
  }

  // When the session is closing, clean up state without waiting for the
  // underlying WebTransport session to be destroyed.
  void CleanUpState();

  MoqtControlMessageParser ControlMessageParser() const {
    return MoqtControlMessageParser(parameters_.version,
                                    parameters_.using_webtrans);
  }

  bool is_closing_ = false;
  webtransport::Session* session_;
  MoqtSessionParameters parameters_;
  MoqtSessionCallbacks callbacks_;
  MoqtFramer framer_;

  quiche::QuicheWeakPtr<ControlStream> control_stream_ =
      quiche::QuicheWeakPtr<ControlStream>();
  quiche::QuicheCircularDeque<std::unique_ptr<MoqtBidiStreamBase>>
      pending_bidi_streams_;
  bool peer_supports_object_ack_ = false;
  std::string error_;

  bool sent_goaway_ = false;
  bool received_goaway_ = false;

  MoqtTraceRecorder trace_recorder_;

  // Upstream SUBSCRIBE state.
  // Upstream SUBSCRIBEs and FETCHes, indexed by subscribe_id. Do not erase
  // directly, call RemoteTrack::Destroy(), except in deletion callbacks passed
  // to RemoteTrack.
  absl::flat_hash_map<uint64_t, std::unique_ptr<RemoteTrack>> upstream_by_id_;
  // All SUBSCRIBEs, indexed by track_alias.
  absl::flat_hash_map<uint64_t, SubscribeRemoteTrack*> subscribe_by_alias_;
  // All SUBSCRIBEs, indexed by track name.
  absl::flat_hash_map<FullTrackName, SubscribeRemoteTrack*> subscribe_by_name_;
  struct SubscribeUpdateStatus {
    FullTrackName name;
    MessageParameters parameters;
    MoqtResponseCallback response_callback;
  };
  // Outgoing Subscribe Updates. We should not update parameters until a
  // REQUEST_OK arrives.
  absl::flat_hash_map<uint64_t, SubscribeUpdateStatus>
      pending_subscribe_updates_;

  // The next subscribe ID that the local endpoint can send.
  uint64_t next_request_id_ = 0;
  // The local endpoint can send subscribe IDs less than this value.
  uint64_t peer_max_request_id_ = 0;
  std::optional<uint64_t> last_requests_blocked_sent_;

  // All open incoming subscriptions, indexed by track name, used to check for
  // duplicates.
  absl::flat_hash_set<FullTrackName> subscribed_track_names_;
  // Application object representing the publisher for all of the tracks that
  // can be subscribed to via this connection.  Must outlive this object.
  MoqtPublisher* publisher_;
  // Subscriptions for local tracks by the remote peer, indexed by subscribe ID.
  absl::flat_hash_map<uint64_t, std::unique_ptr<SubscriptionPublisher>>
      published_subscriptions_;
  // Keeps track of all request IDs that have queued outgoing data streams. The
  // first element is the highest priority (lowest integer).
  absl::btree_multimap<MoqtTrackPriority, uint64_t>
      subscriptions_with_queued_streams_;
  // This is only used to check for track_alias collisions.
  absl::flat_hash_set<uint64_t> used_track_aliases_;
  uint64_t next_local_track_alias_ = 0;

  // Incoming FETCHes, indexed by fetch ID.
  absl::flat_hash_map<uint64_t, std::unique_ptr<PublishedFetch>>
      incoming_fetches_;

  absl::flat_hash_map<uint64_t, std::unique_ptr<DownstreamTrackStatus>>
      incoming_track_status_;

  // Monitoring interfaces for expected incoming subscriptions.
  absl::flat_hash_map<FullTrackName, MoqtPublishingMonitorInterface*>
      monitoring_interfaces_for_published_tracks_;

  // PUBLISH_NAMESPACE state.
  struct PublishNamespaceState {
    TrackNamespace track_namespace;
    MoqtResponseCallback response_callback;
    quiche::SingleUseCallback<void(MoqtRequestErrorInfo)> cancel_callback;
  };
  absl::flat_hash_map<uint64_t, PublishNamespaceState> publish_namespace_by_id_;
  absl::flat_hash_map<TrackNamespace, uint64_t> publish_namespace_by_namespace_;
  absl::flat_hash_map<uint64_t, MoqtResponseCallback>
      publish_namespace_updates_;
  absl::flat_hash_map<TrackNamespace, uint64_t>
      incoming_publish_namespaces_by_namespace_;
  absl::flat_hash_map<uint64_t, TrackNamespace>
      incoming_publish_namespaces_by_id_;

  // It's an error if the namespaces overlap, so keep track of them.
  SessionNamespaceTree incoming_subscribe_namespace_;
  SessionNamespaceTree outgoing_subscribe_namespace_;

  // The maximum request ID sent to the peer. Peer-generated IDs must be less
  // than this value.
  uint64_t local_max_request_id_ = 0;

  std::unique_ptr<quic::QuicAlarmFactory> alarm_factory_;
  // Kill the session if the peer doesn't promptly close out the session after
  // a GOAWAY.
  std::unique_ptr<quic::QuicAlarm> goaway_timeout_alarm_;

  // If true, use a non-standard design where a timer starts for group n when
  // the first object of group n+1 arrives.
  bool alternate_delivery_timeout_ = false;

  quiche::QuicheWeakPtrFactory<MoqtSessionInterface> weak_ptr_factory_;

  // Must be last.  Token used to make sure that the streams do not call into
  // the session when the session has already been destroyed.

  std::shared_ptr<Empty> liveness_token_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_SESSION_H_
