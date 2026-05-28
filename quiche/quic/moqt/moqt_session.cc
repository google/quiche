// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/base/casts.h"
#include "absl/base/nullability.h"
#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"
#include "absl/functional/bind_front.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
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
#include "quiche/quic/moqt/moqt_namespace_stream.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_subscription.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_status_utils.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/web_transport.h"

#define ENDPOINT \
  (perspective() == Perspective::IS_SERVER ? "MoQT Server: " : "MoQT Client: ")

namespace moqt {

namespace {

using ::quic::Perspective;

class DefaultPublisher : public MoqtPublisher {
 public:
  static DefaultPublisher* GetInstance() {
    static DefaultPublisher* instance = new DefaultPublisher();
    return instance;
  }

  // MoqtPublisher implementation.
  absl_nullable std::shared_ptr<MoqtTrackPublisher> GetTrack(
      const FullTrackName& track_name) override {
    QUICHE_DCHECK(track_name.IsValid());
    return nullptr;
  }
};
}  // namespace

MoqtSession::MoqtSession(webtransport::Session* session,
                         MoqtSessionParameters parameters,
                         std::unique_ptr<quic::QuicAlarmFactory> alarm_factory,
                         MoqtSessionCallbacks callbacks)
    : session_(session),
      parameters_(parameters),
      callbacks_(std::move(callbacks)),
      framer_(parameters.using_webtrans),
      publisher_(DefaultPublisher::GetInstance()),
      local_max_request_id_(parameters.max_request_id),
      alarm_factory_(std::move(alarm_factory)),
      weak_ptr_factory_(this),
      liveness_token_(std::make_shared<Empty>()) {
  if (parameters_.using_webtrans) {
    session_->SetOnDraining([this]() {
      QUICHE_DLOG(INFO) << "WebTransport session is draining";
      received_goaway_ = true;
      if (callbacks_.goaway_received_callback != nullptr) {
        std::move(callbacks_.goaway_received_callback)(absl::string_view());
      }
    });
  }
  if (parameters_.perspective == Perspective::IS_SERVER) {
    next_request_id_ = 1;
  }
  QUICHE_DCHECK(parameters_.moqt_implementation.empty());
  parameters_.moqt_implementation = kImplementationName;
}

void MoqtSession::SendControlMessage(quiche::QuicheBuffer message) {
  ControlStream* control_stream = GetControlStream();
  if (control_stream == nullptr) {
    QUICHE_LOG(DFATAL) << "Trying to send a message on the control stream "
                          "while it does not exist";
    return;
  }
  control_stream->SendOrBufferMessageOrFatal(std::move(message));
}

void MoqtSession::OnSessionReady() {
  QUICHE_DLOG(INFO) << ENDPOINT << "Underlying session ready";
  std::optional<std::string> version = session_->GetNegotiatedSubprotocol();
  if (version != parameters_.version) {
    Error(MoqtError::kVersionNegotiationFailed,
          "MOQT peer chose wrong subprotocol");
    return;
  }
  if (parameters_.perspective == Perspective::IS_SERVER) {
    return;
  }
  auto control_stream = std::make_unique<ControlStream>(this);
  if (!session_->CanOpenNextOutgoingBidirectionalStream()) {
    Error(MoqtError::kControlMessageTimeout, "Unable to open a control stream");
    return;
  }
  webtransport::Stream* stream = session_->OpenOutgoingBidirectionalStream();
  if (stream == nullptr) {
    Error(MoqtError::kInternalError, "Unable to open a control stream");
    return;
  }
  control_stream_ = control_stream->GetWeakPtr();
  control_stream->BindStream(stream);
  trace_recorder_.RecordControlStreamCreated(stream->GetStreamId());
  stream->SetVisitor(std::move(control_stream));
  MoqtClientSetup setup;
  parameters_.ToSetupParameters(setup.parameters);
  SendControlMessage(framer_.SerializeClientSetup(setup));
  QUIC_DLOG(INFO) << ENDPOINT << "Send CLIENT_SETUP";
}

void MoqtSession::OnSessionClosed(webtransport::SessionErrorCode,
                                  const std::string& error_message) {
  if (!error_.empty()) {
    // Avoid erroring out twice.
    return;
  }
  QUICHE_DLOG(INFO) << ENDPOINT << "Underlying session closed with message: "
                    << error_message;
  error_ = error_message;
  CleanUpState();
  std::move(callbacks_.session_terminated_callback)(error_message);
}

void MoqtSession::OnIncomingBidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingBidirectionalStream()) {
    auto bidi_stream = std::make_unique<UnknownBidiStream>(this, stream);
    stream->SetVisitor(std::move(bidi_stream));
    stream->visitor()->OnCanRead();
  }
}

void MoqtSession::OnIncomingUnidirectionalStreamAvailable() {
  while (webtransport::Stream* stream =
             session_->AcceptIncomingUnidirectionalStream()) {
    stream->SetVisitor(
        std::make_unique<IncomingDataStream>(stream, this, callbacks_.clock));
    stream->visitor()->OnCanRead();
  }
}

void MoqtSession::OnDatagramReceived(absl::string_view datagram) {
  MoqtObject message;
  bool use_default_priority;
  std::optional<absl::string_view> payload =
      ParseDatagram(datagram, message, use_default_priority);
  if (!payload.has_value()) {
    Error(MoqtError::kProtocolViolation, "Malformed datagram received");
    return;
  }
  QUICHE_DLOG(INFO) << ENDPOINT
                    << "Received OBJECT message in datagram for request_id "
                    << " for track alias " << message.track_alias
                    << " with sequence " << message.group_id << ":"
                    << message.object_id << " priority "
                    << message.publisher_priority << " length "
                    << payload->size();
  SubscribeRemoteTrack* track = RemoteTrackByAlias(message.track_alias);
  if (track == nullptr) {
    return;
  }
  track->OnObjectOrOk();
  if (use_default_priority) {
    message.publisher_priority = track->default_publisher_priority();
  }
  if (!track->InWindow(Location(message.group_id, message.object_id))) {
    // TODO(martinduke): a recent REQUEST_UPDATE could put us here, and it's
    // not an error.
    return;
  }
  QUICHE_CHECK(!track->is_fetch());
  SubscribeVisitor* visitor = track->visitor();
  if (visitor != nullptr) {
    // TODO(martinduke): Handle extension headers.
    PublishedObjectMetadata metadata;
    metadata.location = Location(message.group_id, message.object_id);
    metadata.subgroup = std::nullopt;
    metadata.status = message.object_status;
    metadata.publisher_priority = message.publisher_priority;
    metadata.payload_length = payload->size();
    metadata.arrival_time = callbacks_.clock->Now();
    visitor->OnObjectFragment(track->full_track_name(), metadata, *payload,
                              /*offset=*/0);
  }
}

void MoqtSession::OnCanCreateNewOutgoingBidirectionalStream() {
  while (!pending_bidi_streams_.empty() &&
         session_->CanOpenNextOutgoingBidirectionalStream()) {
    webtransport::Stream* stream = session_->OpenOutgoingBidirectionalStream();
    pending_bidi_streams_.front()->BindStream(stream);
    // TODO(vasilvv): Distinguish between control and and non-control bidi
    // streams in trace_recorder_.
    trace_recorder_.RecordControlStreamCreated(stream->GetStreamId());
    stream->SetVisitor(std::move(pending_bidi_streams_.front()));
    pending_bidi_streams_.pop_front();
    stream->visitor()->OnCanWrite();
  }
}

void MoqtSession::Error(MoqtError code, absl::string_view error) {
  if (!error_.empty() || is_closing_) {
    // Avoid erroring out twice.
    return;
  }
  QUICHE_DLOG(INFO) << ENDPOINT << "MOQT session closed with code: "
                    << static_cast<int>(code) << " and message: " << error;
  error_ = std::string(error);
  session_->CloseSession(static_cast<uint64_t>(code), error);
  std::move(callbacks_.session_terminated_callback)(error);
  CleanUpState();
}

std::unique_ptr<MoqtNamespaceTask> MoqtSession::SubscribeNamespace(
    TrackNamespace& prefix, SubscribeNamespaceOption option,
    const MessageParameters& parameters,
    MoqtResponseCallback response_callback) {
  if (received_goaway_ || sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Tried to send SUBSCRIBE_NAMESPACE after GOAWAY";
    return nullptr;
  }
  if (next_request_id_ >= peer_max_request_id_) {
    if (!last_requests_blocked_sent_.has_value() ||
        peer_max_request_id_ > *last_requests_blocked_sent_) {
      MoqtRequestsBlocked requests_blocked;
      requests_blocked.max_request_id = peer_max_request_id_;
      SendControlMessage(framer_.SerializeRequestsBlocked(requests_blocked));
      last_requests_blocked_sent_ = peer_max_request_id_;
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE_NAMESPACE with ID "
                    << next_request_id_
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return nullptr;
  }
  // Sanitize the option.
  switch (option) {
    case SubscribeNamespaceOption::kNamespace:
      break;
    case SubscribeNamespaceOption::kPublish:
      // TODO(martinduke): Support PUBLISH.
      return nullptr;
    case SubscribeNamespaceOption::kBoth:
      option = SubscribeNamespaceOption::kNamespace;
      break;
  }
  QUICHE_DCHECK(option == SubscribeNamespaceOption::kNamespace);
  if (!outgoing_subscribe_namespace_.SubscribeNamespace(prefix)) {
    std::move(response_callback)(MoqtRequestErrorInfo{
        RequestErrorCode::kInternalError, std::nullopt,
        "SUBSCRIBE_NAMESPACE already outstanding for namespace"});
    return nullptr;
  }
  std::unique_ptr<MoqtNamespaceSubscriberStream> state =
      std::make_unique<MoqtNamespaceSubscriberStream>(
          &framer_, ControlMessageParser(), next_request_id_,
          [session_weak_ptr = GetWeakPtr(), this, pref = prefix]() {
            if (!session_weak_ptr.IsValid() || is_closing_) {
              return;
            }
            outgoing_subscribe_namespace_.UnsubscribeNamespace(pref);
          },
          [session_weak_ptr = GetWeakPtr(), this](MoqtError error,
                                                  absl::string_view reason) {
            if (!session_weak_ptr.IsValid() || is_closing_) {
              return;
            }
            Error(error, reason);
          },
          std::move(response_callback));
  MoqtNamespaceSubscriberStream* state_ptr = state.get();
  if (session_->CanOpenNextOutgoingBidirectionalStream()) {
    webtransport::Stream* stream = session_->OpenOutgoingBidirectionalStream();
    state->BindStream(stream);
    stream->SetVisitor(std::move(state));
  } else {
    pending_bidi_streams_.push_back(std::move(state));
  }
  MoqtSubscribeNamespace message;
  message.request_id = next_request_id_;
  message.track_namespace_prefix = prefix;
  message.subscribe_options = SubscribeNamespaceOption::kNamespace;
  message.parameters = parameters;
  state_ptr->SendOrBufferMessageOrFatal(
      framer_.SerializeSubscribeNamespace(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent SUBSCRIBE_NAMESPACE message for "
                  << message.track_namespace_prefix;
  return state_ptr->CreateTask(prefix);
}

bool MoqtSession::PublishNamespace(
    const TrackNamespace& track_namespace, const MessageParameters& parameters,
    MoqtResponseCallback response_callback,
    quiche::SingleUseCallback<void(MoqtRequestErrorInfo)> cancel_callback) {
  if (is_closing_) {
    return false;
  }
  if (publish_namespace_by_namespace_.contains(track_namespace)) {
    return false;
  }
  if (next_request_id_ >= peer_max_request_id_) {
    if (!last_requests_blocked_sent_.has_value() ||
        peer_max_request_id_ > *last_requests_blocked_sent_) {
      MoqtRequestsBlocked requests_blocked;
      requests_blocked.max_request_id = peer_max_request_id_;
      SendControlMessage(framer_.SerializeRequestsBlocked(requests_blocked));
      last_requests_blocked_sent_ = peer_max_request_id_;
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send PUBLISH_NAMESPACE with ID "
                    << next_request_id_
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return false;
  }
  if (received_goaway_ || sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Tried to send PUBLISH_NAMESPACE after GOAWAY";
    return false;
  }
  publish_namespace_by_namespace_[track_namespace] = next_request_id_;
  publish_namespace_by_id_[next_request_id_] =
      PublishNamespaceState{track_namespace, std::move(response_callback),
                            std::move(cancel_callback)};
  MoqtPublishNamespace message;
  message.request_id = next_request_id_;
  next_request_id_ += 2;
  message.track_namespace = track_namespace;
  message.parameters = parameters;
  SendControlMessage(framer_.SerializePublishNamespace(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent PUBLISH_NAMESPACE message for "
                  << message.track_namespace;
  return true;
}

bool MoqtSession::PublishNamespaceUpdate(
    const TrackNamespace& track_namespace, MessageParameters& parameters,
    MoqtResponseCallback response_callback) {
  if (is_closing_) {
    return false;
  }
  auto it = publish_namespace_by_namespace_.find(track_namespace);
  if (it == publish_namespace_by_namespace_.end()) {
    return false;  // Could have been destroyed by PUBLISH_NAMESPACE_CANCEL.
  }
  if (next_request_id_ >= peer_max_request_id_) {
    if (!last_requests_blocked_sent_.has_value() ||
        peer_max_request_id_ > *last_requests_blocked_sent_) {
      MoqtRequestsBlocked requests_blocked;
      requests_blocked.max_request_id = peer_max_request_id_;
      SendControlMessage(framer_.SerializeRequestsBlocked(requests_blocked));
      last_requests_blocked_sent_ = peer_max_request_id_;
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send PUBLISH_NAMESPACE with ID "
                    << next_request_id_
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return false;
  }
  MoqtRequestUpdate message;
  message.request_id = next_request_id_;
  message.existing_request_id = it->second;
  message.parameters = parameters;
  publish_namespace_updates_[next_request_id_] = std::move(response_callback);
  next_request_id_ += 2;
  SendControlMessage(framer_.SerializeRequestUpdate(message));
  return true;
}

bool MoqtSession::PublishNamespaceDone(const TrackNamespace& track_namespace) {
  if (is_closing_) {
    return false;
  }
  auto it = publish_namespace_by_namespace_.find(track_namespace);
  if (it == publish_namespace_by_namespace_.end()) {
    return false;  // Could have been destroyed by PUBLISH_NAMESPACE_CANCEL.
  }
  MoqtPublishNamespaceDone message;
  message.request_id = it->second;
  SendControlMessage(framer_.SerializePublishNamespaceDone(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent PUBLISH_NAMESPACE_DONE message for "
                  << track_namespace;
  publish_namespace_by_id_.erase(it->second);
  publish_namespace_by_namespace_.erase(it);
  return true;
}

bool MoqtSession::PublishNamespaceCancel(const TrackNamespace& track_namespace,
                                         RequestErrorCode code,
                                         absl::string_view reason) {
  auto it = incoming_publish_namespaces_by_namespace_.find(track_namespace);
  if (it == incoming_publish_namespaces_by_namespace_.end()) {
    return false;  // Could have been destroyed by PUBLISH_NAMESPACE_DONE.
  }
  MoqtPublishNamespaceCancel message{it->second, code, std::string(reason)};
  incoming_publish_namespaces_by_id_.erase(it->second);
  incoming_publish_namespaces_by_namespace_.erase(it);
  SendControlMessage(framer_.SerializePublishNamespaceCancel(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent PUBLISH_NAMESPACE_CANCEL message for "
                  << track_namespace << " with reason " << reason;
  return true;
}

bool MoqtSession::Subscribe(const FullTrackName& name,
                            SubscribeVisitor* visitor,
                            const MessageParameters& parameters) {
  QUICHE_DCHECK(name.IsValid());

  if (next_request_id_ >= peer_max_request_id_) {
    if (!last_requests_blocked_sent_.has_value() ||
        peer_max_request_id_ > *last_requests_blocked_sent_) {
      MoqtRequestsBlocked requests_blocked;
      requests_blocked.max_request_id = peer_max_request_id_;
      SendControlMessage(framer_.SerializeRequestsBlocked(requests_blocked));
      last_requests_blocked_sent_ = peer_max_request_id_;
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE with ID "
                    << next_request_id_
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return false;
  }
  if (subscribe_by_name_.contains(name)) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE for track " << name
                    << " which is already subscribed";
    return false;
  }
  if (received_goaway_ || sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE after GOAWAY";
    return false;
  }
  MoqtSubscribe message(next_request_id_, name, parameters);
  next_request_id_ += 2;
  if (SupportsObjectAck() && visitor != nullptr) {
    // Since we do not expose subscribe IDs directly in the API, instead wrap
    // the session and subscribe ID in a callback.
    visitor->OnCanAckObjects(absl::bind_front(&MoqtSession::SendObjectAck, this,
                                              message.request_id));
  } else {
    QUICHE_DLOG_IF(WARNING, message.parameters.oack_window_size.has_value())
        << "Attempting to set object_ack_window on a connection that does not "
           "support it.";
    message.parameters.oack_window_size = std::nullopt;
  }
  SendControlMessage(framer_.SerializeSubscribe(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent SUBSCRIBE message for "
                  << message.full_track_name;
  auto track = std::make_unique<SubscribeRemoteTrack>(
      message, visitor,
      [this, request_id = message.request_id, ftn = name]() {
        // Deletion callback
        subscribe_by_name_.erase(ftn);
        upstream_by_id_.erase(request_id);
      },
      [this](uint64_t alias, SubscribeRemoteTrack* track) {
        // Track alias registry callback.
        if (is_closing_) {
          return true;
        }
        if (track == nullptr) {
          subscribe_by_alias_.erase(alias);
          return true;
        }
        auto [it, success] = subscribe_by_alias_.try_emplace(alias, track);
        if (!success) {
          Error(MoqtError::kDuplicateTrackAlias, "");
        }
        return success;
      });
  subscribe_by_name_.emplace(message.full_track_name, track.get());
  upstream_by_id_.emplace(message.request_id, std::move(track));
  return true;
}

bool MoqtSession::SubscribeUpdate(const FullTrackName& name,
                                  const MessageParameters& parameters,
                                  MoqtResponseCallback response_callback) {
  QUICHE_DCHECK(name.IsValid());
  if (next_request_id_ >= peer_max_request_id_) {
    if (!last_requests_blocked_sent_.has_value() ||
        peer_max_request_id_ > *last_requests_blocked_sent_) {
      MoqtRequestsBlocked requests_blocked;
      requests_blocked.max_request_id = peer_max_request_id_;
      SendControlMessage(framer_.SerializeRequestsBlocked(requests_blocked));
      last_requests_blocked_sent_ = peer_max_request_id_;
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send SUBSCRIBE with ID "
                    << next_request_id_
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return false;
  }
  auto it = subscribe_by_name_.find(name);
  if (it == subscribe_by_name_.end()) {
    return false;
  }
  pending_subscribe_updates_[next_request_id_] = {name, parameters,
                                                  std::move(response_callback)};
  MoqtRequestUpdate update{next_request_id_, it->second->request_id(),
                           parameters};
  next_request_id_ += 2;
  SendControlMessage(framer_.SerializeRequestUpdate(update));
  return true;
}

void MoqtSession::Unsubscribe(const FullTrackName& name) {
  if (is_closing_) {
    return;
  }
  QUICHE_DCHECK(name.IsValid());
  SubscribeRemoteTrack* track = RemoteTrackByName(name);
  if (track == nullptr) {
    return;
  }
  QUICHE_DCHECK(name.IsValid());
  QUIC_DLOG(INFO) << ENDPOINT << "Sent UNSUBSCRIBE message for " << name;
  MoqtUnsubscribe message;
  message.request_id = track->request_id();
  SendControlMessage(framer_.SerializeUnsubscribe(message));
  track->Destroy();
}

bool MoqtSession::Fetch(const FullTrackName& name,
                        FetchResponseCallback callback, Location start,
                        uint64_t end_group, std::optional<uint64_t> end_object,
                        MessageParameters parameters) {
  QUICHE_DCHECK(name.IsValid());
  if (next_request_id_ >= peer_max_request_id_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send FETCH with ID "
                    << next_request_id_
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return false;
  }
  if (received_goaway_ || sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send FETCH after GOAWAY";
    return false;
  }
  MoqtFetch message;
  Location end_location = end_object.has_value()
                              ? Location(end_group, *end_object)
                              : Location(end_group, kMaxObjectId);
  message.fetch = StandaloneFetch(name, start, end_location);
  message.request_id = next_request_id_;
  next_request_id_ += 2;
  message.parameters = parameters;
  SendControlMessage(framer_.SerializeFetch(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent FETCH message for " << name;
  auto fetch = std::make_unique<UpstreamFetch>(
      message, std::get<StandaloneFetch>(message.fetch), std::move(callback),
      [this, id = message.request_id]() {  // Deletion callback
        upstream_by_id_.erase(id);
      });
  upstream_by_id_.emplace(message.request_id, std::move(fetch));
  return true;
}

bool MoqtSession::RelativeJoiningFetch(const FullTrackName& name,
                                       SubscribeVisitor* visitor,
                                       uint64_t num_previous_groups,
                                       MessageParameters parameters) {
  QUICHE_DCHECK(name.IsValid());
  return RelativeJoiningFetch(
      name, visitor,
      [this, id = next_request_id_](std::unique_ptr<MoqtFetchTask> fetch_task) {
        // Move the fetch_task to the subscribe to plumb into its visitor.
        RemoteTrack* track = RemoteTrackById(id);
        if (track == nullptr || track->is_fetch()) {
          fetch_task.release();
          return;
        }
        auto* subscribe = absl::down_cast<SubscribeRemoteTrack*>(track);
        RemoteTrackByName(track->full_track_name());
        subscribe->OnJoiningFetchReady(std::move(fetch_task));
      },
      num_previous_groups, parameters);
}

bool MoqtSession::RelativeJoiningFetch(const FullTrackName& name,
                                       SubscribeVisitor* visitor,
                                       FetchResponseCallback callback,
                                       uint64_t num_previous_groups,
                                       MessageParameters parameters) {
  QUICHE_DCHECK(name.IsValid());
  if ((next_request_id_ + 2) >= peer_max_request_id_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send JOINING_FETCH with ID "
                    << (next_request_id_ + 2)
                    << " which is greater than the maximum ID "
                    << peer_max_request_id_;
    return false;
  }
  MessageParameters subscribe_parameters = parameters;
  subscribe_parameters.subscription_filter.emplace(
      MoqtFilterType::kLargestObject);
  if (!Subscribe(name, visitor, subscribe_parameters)) {
    return false;
  }

  MoqtFetch fetch;
  fetch.request_id = next_request_id_;
  next_request_id_ += 2;
  fetch.fetch = JoiningFetchRelative{fetch.request_id - 2, num_previous_groups};
  fetch.parameters = parameters;
  SendControlMessage(framer_.SerializeFetch(fetch));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent Joining FETCH message for " << name;
  auto upstream_fetch = std::make_unique<UpstreamFetch>(
      fetch, name, std::move(callback),
      /*Deletion callback=*/[this, id = fetch.request_id]() {
        upstream_by_id_.erase(id);
      });
  upstream_by_id_.emplace(fetch.request_id, std::move(upstream_fetch));
  return true;
}

void MoqtSession::GoAway(absl::string_view new_session_uri) {
  if (sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Tried to send multiple GOAWAY";
    return;
  }
  if (!new_session_uri.empty() && !new_session_uri.empty()) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Client tried to send GOAWAY with new session URI";
    return;
  }
  MoqtGoAway message;
  message.new_session_uri = std::string(new_session_uri);
  SendControlMessage(framer_.SerializeGoAway(message));
  sent_goaway_ = true;
  goaway_timeout_alarm_ = absl::WrapUnique(
      alarm_factory_->CreateAlarm(new GoAwayTimeoutDelegate(this)));
  goaway_timeout_alarm_->Set(callbacks_.clock->ApproximateNow() +
                             kDefaultGoAwayTimeout);
}

void MoqtSession::GoAwayTimeoutDelegate::OnAlarm() {
  session_->Error(MoqtError::kGoawayTimeout,
                  "Peer did not close session after GOAWAY");
}

void MoqtSession::PublishIsDone(uint64_t request_id) {
  if (is_closing_) {
    return;
  }
  auto it = published_subscriptions_.find(request_id);
  if (it == published_subscriptions_.end()) {
    return;
  }
  subscribed_track_names_.erase(it->second->publisher().GetTrackName());
  published_subscriptions_.erase(it);
}

void MoqtSession::UpdateTrackPriority(
    uint64_t request_id, std::optional<MoqtTrackPriority> old_priority,
    MoqtTrackPriority new_priority) {
  if (old_priority.has_value()) {
    auto [start, end] =
        subscriptions_with_queued_streams_.equal_range(*old_priority);
    for (auto it = start; it != end; ++it) {
      if (it->second == request_id) {
        subscriptions_with_queued_streams_.erase(it);
        break;
      }
    }
  }
  subscriptions_with_queued_streams_.emplace(new_priority, request_id);
}

bool MoqtSession::OpenDataStream(PublishedFetch* fetch,
                                 webtransport::SendOrder send_order) {
  webtransport::Stream* new_stream =
      session_->OpenOutgoingUnidirectionalStream();
  if (new_stream == nullptr) {
    QUICHE_BUG(MoqtSession_OpenDataStream_blocked)
        << "OpenDataStream called when creation of new streams is blocked.";
    return false;
  }
  fetch->SetStreamId(new_stream->GetStreamId());
  // The line below will lead to updating ObjectsAvailableCallback in the
  // FetchTask to call OnCanWrite() on the stream. If there is an object
  // available, the callback will be invoked synchronously (i.e. before
  // SetVisitor() returns).
  new_stream->SetVisitor(std::make_unique<OutgoingFetchStream>(
      framer_, new_stream, fetch->request_id(),
      webtransport::StreamPriority{/*send_group_id=*/kMoqtSendGroupId,
                                   send_order},
      fetch->release_fetch_task(),
      // use weakptr to avoid use-after-free for this.
      [weakptr = GetWeakPtr(), request_id = fetch->request_id()]() {
        if (weakptr.IsValid()) {
          auto session =
              absl::down_cast<MoqtSession*>(weakptr.GetIfAvailable());
          session->incoming_fetches_.erase(request_id);
        }
      },
      &trace_recorder_));
  return true;
}

SubscribeRemoteTrack* MoqtSession::RemoteTrackByAlias(uint64_t track_alias) {
  auto it = subscribe_by_alias_.find(track_alias);
  if (it == subscribe_by_alias_.end()) {
    return nullptr;
  }
  return it->second;
}

RemoteTrack* MoqtSession::RemoteTrackById(uint64_t request_id) {
  auto it = upstream_by_id_.find(request_id);
  if (it == upstream_by_id_.end()) {
    return nullptr;
  }
  return it->second.get();
}

SubscribeRemoteTrack* MoqtSession::RemoteTrackByName(
    const FullTrackName& name) {
  QUICHE_DCHECK(name.IsValid());
  auto it = subscribe_by_name_.find(name);
  if (it == subscribe_by_name_.end()) {
    return nullptr;
  }
  return it->second;
}

void MoqtSession::OnCanCreateNewOutgoingUnidirectionalStream() {
  while (!subscriptions_with_queued_streams_.empty() &&
         session_->CanOpenNextOutgoingUnidirectionalStream()) {
    auto next = subscriptions_with_queued_streams_.begin();
    auto subscription = published_subscriptions_.find(next->second);
    if (subscription == published_subscriptions_.end()) {
      auto fetch = incoming_fetches_.find(next->second);
      // Create the stream if the fetch still exists.
      if (fetch != incoming_fetches_.end() &&
          !OpenDataStream(fetch->second.get(),
                          SendOrderForFetch(next->first.subscriber_priority))) {
        return;  // A QUIC_BUG has fired because this shouldn't happen.
      }
      // FETCH needs only one stream, and can be deleted from the queue. Or,
      // there is no subscribe and no fetch; the entry in the queue is invalid.
      subscriptions_with_queued_streams_.erase(next);
      continue;
    }
    subscriptions_with_queued_streams_.erase(next);
    // Pop the item from the subscription's queue, which might update
    // subscriptions_with_queued_streams_ with a second pending stream.
    subscription->second->OnCanCreateNewUniStream();
  }
}

void MoqtSession::GrantMoreRequests(uint64_t num_requests) {
  local_max_request_id_ += (num_requests * 2);
  MoqtMaxRequestId message;
  message.max_request_id = local_max_request_id_;
  SendControlMessage(framer_.SerializeMaxRequestId(message));
}

bool MoqtSession::ValidateRequestId(uint64_t request_id) {
  if (request_id >= local_max_request_id_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received request with too large ID";
    Error(MoqtError::kTooManyRequests, "Received request with too large ID");
    return false;
  }
  if ((request_id % 2 == 0) !=
      (parameters_.perspective == Perspective::IS_SERVER)) {
    QUICHE_DLOG(INFO) << ENDPOINT << "Request ID evenness incorrect";
    Error(MoqtError::kInvalidRequestId, "Request ID evenness incorrect");
    return false;
  }
  if (published_subscriptions_.contains(request_id) ||
      incoming_fetches_.contains(request_id) ||
      incoming_track_status_.contains(request_id) ||
      incoming_publish_namespaces_by_id_.contains(request_id)) {
    QUICHE_DLOG(INFO) << ENDPOINT << "Duplicate request ID";
    Error(MoqtError::kInvalidRequestId, "Duplicate request ID");
    return false;
  }
  return true;
}

void MoqtSession::UnknownBidiStream::OnCanRead() {
  absl::StatusOr<MoqtMessageType> message_type =
      parser_->ReadFirstMessageType();
  if (absl::IsUnavailable(message_type.status())) {
    return;
  }
  if (absl::IsInvalidArgument(message_type.status())) {
    // Received a FIN before any type has been available, which is malformed.
    session_->Error(MoqtError::kProtocolViolation,
                    message_type.status().message());
    return;
  }
  if (!message_type.ok()) {
    // The result is neither of "OK", "no type available", or "parse error".
    // This is unexpected; treat it as an internal error, and reset the stream.
    stream_->ResetWithUserCode(kResetCodeInternalError);
    return;
  }
  switch (*message_type) {
    case MoqtMessageType::kClientSetup: {
      if (session_->control_stream_.GetIfAvailable() != nullptr) {
        session_->Error(MoqtError::kProtocolViolation,
                        "Multiple control streams");
        return;
      }
      auto control_stream = std::make_unique<ControlStream>(session_);
      control_stream->BindStream(std::move(parser_));
      // Store a reference to the stream context when the current context is
      // destroyed below.
      ControlStream* temp_stream = control_stream.get();
      session_->control_stream_ = temp_stream->GetWeakPtr();
      // Deletes the UnknownBidiStream object; no class access after this
      // point.
      stream_->SetVisitor(std::move(control_stream));
      temp_stream->OnCanRead();
      break;
    }
    case MoqtMessageType::kSubscribeNamespace: {
      auto namespace_stream = std::make_unique<MoqtNamespacePublisherStream>(
          &session_->framer_, session_->ControlMessageParser(),
          [session = session_](MoqtError code, absl::string_view reason) {
            session->Error(code, reason);
          },
          &session_->incoming_subscribe_namespace_,
          session_->callbacks_.incoming_subscribe_namespace_callback);
      namespace_stream->BindStream(std::move(parser_));
      MoqtNamespacePublisherStream* temp_stream = namespace_stream.get();
      stream_->SetVisitor(std::move(namespace_stream));
      // The UnknownBidiStream object is deleted; no class access after this
      // point.
      temp_stream->OnCanRead();
      break;
    }
    default:
      session_->Error(MoqtError::kProtocolViolation,
                      "Unexpected message type received to start bidi stream");
      return;
  }
}

void MoqtSession::ControlStream::OnStreamBound() {
  stream()->SetPriority(
      webtransport::StreamPriority{/*send_group_id=*/kMoqtSendGroupId,
                                   /*send_order=*/kMoqtControlStreamSendOrder});
}

absl::Status MoqtSession::ControlStream::OnRawControlMessage(
    const MoqtRawControlMessage& message) {
  return DispatchControlMessage<ControlStream>(message, "control");
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtClientSetup& message) {
  if (session_->perspective() == Perspective::IS_CLIENT) {
    return absl::InvalidArgumentError("Received CLIENT_SETUP from server");
  }
  session_->peer_supports_object_ack_ =
      message.parameters.support_object_acks.value_or(
          kDefaultSupportObjectAcks);
  session_->peer_max_request_id_ =
      message.parameters.max_request_id.value_or(kDefaultMaxRequestId);
  QUICHE_DLOG(INFO) << "Received CLIENT_SETUP";
  MoqtServerSetup response;
  session_->parameters_.ToSetupParameters(response.parameters);
  QUICHE_RETURN_IF_ERROR(
      SendOrBufferMessage(session_->framer_.SerializeServerSetup(response)));
  QUICHE_DLOG(INFO) << "Sent SERVER_SETUP";
  // TODO: handle path.
  std::move(session_->callbacks_.session_established_callback)();
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtServerSetup& message) {
  if (perspective() == Perspective::IS_SERVER) {
    return absl::InvalidArgumentError("Received SERVER_SETUP from client");
  }
  session_->peer_supports_object_ack_ =
      message.parameters.support_object_acks.value_or(
          kDefaultSupportObjectAcks);
  QUIC_DLOG(INFO) << ENDPOINT << "Received the SETUP message";
  // TODO: handle path.
  session_->peer_max_request_id_ =
      message.parameters.max_request_id.value_or(kDefaultMaxRequestId);
  std::move(session_->callbacks_.session_established_callback)();
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtSubscribe& message) {
  if (!session_->ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received a SUBSCRIBE for "
                  << message.full_track_name;
  if (session_->sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received a SUBSCRIBE after GOAWAY";
    return SendRequestError(message.request_id, RequestErrorCode::kUnauthorized,
                            std::nullopt, "SUBSCRIBE after GOAWAY");
  }
  if (session_->subscribed_track_names_.contains(message.full_track_name)) {
    return SendRequestError(message.request_id,
                            RequestErrorCode::kDuplicateSubscription,
                            std::nullopt, "");
  }
  const FullTrackName& track_name = message.full_track_name;
  std::shared_ptr<MoqtTrackPublisher> track_publisher =
      session_->publisher_->GetTrack(track_name);
  if (track_publisher == nullptr) {
    QUIC_DLOG(INFO) << ENDPOINT << "SUBSCRIBE for " << track_name
                    << " rejected by the application: does not exist";
    return SendRequestError(message.request_id, RequestErrorCode::kDoesNotExist,
                            std::nullopt, "not found");
  }

  MoqtPublishingMonitorInterface* monitoring = nullptr;
  auto monitoring_it =
      session_->monitoring_interfaces_for_published_tracks_.find(track_name);
  if (monitoring_it !=
      session_->monitoring_interfaces_for_published_tracks_.end()) {
    monitoring = monitoring_it->second;
    session_->monitoring_interfaces_for_published_tracks_.erase(monitoring_it);
  }

  MoqtTrackPublisher* track_publisher_ptr = track_publisher.get();
  auto subscription = std::make_unique<SubscriptionPublisher>(
      session_->framer_, track_publisher, this, message.request_id,
      session_->next_local_track_alias_++, message.parameters, session_,
      monitoring, session_->callbacks_.clock, session_->trace_recorder_);
  SubscriptionPublisher* subscription_ptr = subscription.get();
  auto [it, success] = session_->published_subscriptions_.emplace(
      message.request_id, std::move(subscription));
  if (!success) {
    QUICHE_NOTREACHED();  // ValidateRequestId() should have caught this.
  }
  session_->subscribed_track_names_.insert(message.full_track_name);
  track_publisher_ptr->AddObjectListener(subscription_ptr);
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtSubscribeOk& message) {
  RemoteTrack* track = session_->RemoteTrackById(message.request_id);
  if (track == nullptr) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received the SUBSCRIBE_OK for "
                    << "request_id = " << message.request_id
                    << " but no track exists";
    // Subscription state might have been destroyed for internal reasons.
    return absl::OkStatus();
  }
  if (track->is_fetch()) {
    return absl::InvalidArgumentError("Received SUBSCRIBE_OK for a FETCH");
  }
  if (message.parameters.largest_object.has_value()) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received the SUBSCRIBE_OK for "
                    << "request_id = " << message.request_id << " "
                    << track->full_track_name()
                    << " largest_id = " << *message.parameters.largest_object;
  } else {
    QUIC_DLOG(INFO) << ENDPOINT << "Received the SUBSCRIBE_OK for "
                    << "request_id = " << message.request_id << " "
                    << track->full_track_name();
  }
  SubscribeRemoteTrack* subscribe =
      absl::down_cast<SubscribeRemoteTrack*>(track);
  subscribe->OnObjectOrOk();
  if (!subscribe->set_track_alias(message.track_alias)) {
    // A duplicate track alias could destroy the session.
    return absl::OkStatus();
  }
  std::optional<SubscriptionFilter> filter =
      subscribe->parameters().subscription_filter;
  if (filter.has_value()) {
    filter->OnLargestObject(message.parameters.largest_object);
  }
  subscribe->set_publisher_delivery_timeout(
      message.extensions.delivery_timeout());
  // TODO(martinduke): Is there anything to do with EXPIRES?
  subscribe->set_default_publisher_priority(
      message.extensions.default_publisher_priority());
  if (!subscribe->parameters().group_order.has_value()) {
    // Use publisher default because the subscriber didn't care.
    subscribe->parameters().group_order =
        message.extensions.default_publisher_group_order();
  }
  subscribe->set_dynamic_groups(message.extensions.dynamic_groups());
  if (subscribe->visitor() != nullptr) {
    subscribe->visitor()->OnReply(
        track->full_track_name(),
        SubscribeOkData{message.parameters, message.extensions});
  }
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtRequestOk& message) {
  if (session_->upstream_by_id_.contains(message.request_id)) {
    return absl::InvalidArgumentError(
        "Received REQUEST_OK for SUBSCRIBE, FETCH, or PUBLISH");
  }
  // Response to REQUEST_UPDATE for a subscribe.
  auto ru_it = session_->pending_subscribe_updates_.find(message.request_id);
  if (ru_it != session_->pending_subscribe_updates_.end()) {
    auto sub_it = session_->subscribe_by_name_.find(ru_it->second.name);
    if (sub_it == session_->subscribe_by_name_.end()) {
      std::move(ru_it->second.response_callback)(
          MoqtRequestErrorInfo{RequestErrorCode::kDoesNotExist, std::nullopt,
                               "subscription does not exist anymore"});
      session_->pending_subscribe_updates_.erase(ru_it);
      return absl::OkStatus();
    }
    sub_it->second->parameters().Update(ru_it->second.parameters);
    std::move(ru_it->second.response_callback)(std::nullopt);
    session_->pending_subscribe_updates_.erase(ru_it);
    return absl::OkStatus();
  }
  // Response to PUBLISH_NAMESPACE.
  auto pn_it = session_->publish_namespace_by_id_.find(message.request_id);
  if (pn_it != session_->publish_namespace_by_id_.end()) {
    if (pn_it->second.response_callback == nullptr) {
      return absl::InvalidArgumentError(
          "Multiple responses for PUBLISH_NAMESPACE");
    }
    std::move(pn_it->second.response_callback)(std::nullopt);
    return absl::OkStatus();
  }
  // Response to SUBSCRIBE_NAMESPACE is handled in the NamespaceStream.
  // TRACK_STATUS response would go here, but we don't support upstream
  // TRACK_STATUS.
  // If it doesn't match any state, it might be because the local application
  // cancelled the request. Do nothing.
  // TODO(martinduke): Do something with parameters.
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtRequestError& message) {
  MoqtRequestErrorInfo error_info{message.error_code, message.retry_interval,
                                  message.reason_phrase};
  // TODO(martinduke): Do something with retry_interval.
  RemoteTrack* track = session_->RemoteTrackById(message.request_id);
  if (track != nullptr) {
    // It's in response to SUBSCRIBE or FETCH.
    if (!track->ErrorIsAllowed()) {
      return absl::InvalidArgumentError(
          "Received REQUEST_ERROR after REQUEST_OK or objects");
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Received the REQUEST_ERROR for "
                    << "request_id = " << message.request_id << " ("
                    << track->full_track_name() << ")"
                    << ", error = " << static_cast<uint64_t>(message.error_code)
                    << " (" << message.reason_phrase << ")";
    if (track->is_fetch()) {
      UpstreamFetch* fetch = absl::down_cast<UpstreamFetch*>(track);
      absl::Status status =
          RequestErrorCodeToStatus(message.error_code, message.reason_phrase);
      fetch->OnFetchResult(Location(0, 0), status, nullptr);
    } else {
      SubscribeRemoteTrack* subscribe =
          absl::down_cast<SubscribeRemoteTrack*>(track);
      if (subscribe->visitor() != nullptr) {
        subscribe->visitor()->OnReply(subscribe->full_track_name(), error_info);
      }
    }
    if (!session_->is_closing_) {
      // The visitor might have closed the session.
      track->Destroy();
    }
    return absl::OkStatus();
  }
  // Response to REQUEST_UPDATE for a subscribe.
  auto ru_it = session_->pending_subscribe_updates_.find(message.request_id);
  if (ru_it != session_->pending_subscribe_updates_.end()) {
    std::move(ru_it->second.response_callback)(error_info);
    session_->pending_subscribe_updates_.erase(ru_it);
    return absl::OkStatus();
  }
  // Response to PUBLISH_NAMESPACE.
  auto pn_it = session_->publish_namespace_by_id_.find(message.request_id);
  if (pn_it != session_->publish_namespace_by_id_.end()) {
    if (pn_it->second.response_callback == nullptr) {
      return absl::InvalidArgumentError(
          "Multiple responses for PUBLISH_NAMESPACE");
    }
    std::move(pn_it->second.response_callback)(error_info);
    session_->publish_namespace_by_namespace_.erase(
        pn_it->second.track_namespace);
    session_->publish_namespace_by_id_.erase(pn_it);
    return absl::OkStatus();
  }
  // Response to SUBSCRIBE_NAMESPACE is handled in the NamespaceStream.
  // TRACK_STATUS response would go here, but we don't support upstream
  // TRACK_STATUS.
  // If it doesn't match any state, it might be because the local application
  // cancelled the request. Do nothing.
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtUnsubscribe& message) {
  auto it = session_->published_subscriptions_.find(message.request_id);
  if (it == session_->published_subscriptions_.end()) {
    return absl::OkStatus();
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received an UNSUBSCRIBE for "
                  << it->second->publisher().GetTrackName();
  session_->PublishIsDone(message.request_id);
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtPublishDone& message) {
  auto it = session_->upstream_by_id_.find(message.request_id);
  if (it == session_->upstream_by_id_.end()) {
    return absl::OkStatus();
  }
  auto* subscribe = absl::down_cast<SubscribeRemoteTrack*>(it->second.get());
  QUIC_DLOG(INFO) << ENDPOINT << "Received a PUBLISH_DONE for "
                  << it->second->full_track_name();
  subscribe->OnPublishDone(message.stream_count, session_->callbacks_.clock,
                           session_->alarm_factory_.get());
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtRequestUpdate& message) {
  auto it =
      session_->published_subscriptions_.find(message.existing_request_id);
  if (it != session_->published_subscriptions_.end()) {
    // It's updating SUBSCRIBE.
    it->second->Update(message.parameters);
    return SendRequestOk(message.request_id, MessageParameters());
  }
  auto pn_it =
      session_->publish_namespace_by_id_.find(message.existing_request_id);
  if (pn_it != session_->publish_namespace_by_id_.end()) {
    // It's updating PUBLISH_NAMESPACE.
    quiche::QuicheWeakPtr<MoqtSessionInterface> session_weakptr =
        session_->GetWeakPtr();
    TrackNamespace track_namespace = pn_it->second.track_namespace;
    session_->callbacks().incoming_publish_namespace_callback(
        pn_it->second.track_namespace, message.parameters,
        [&](std::optional<MoqtRequestErrorInfo> error) {
          MoqtSession* session =
              absl::down_cast<MoqtSession*>(session_weakptr.GetIfAvailable());
          if (session == nullptr) {
            return;
          }
          if (error.has_value()) {
            CheckStatus(SendRequestError(message.request_id, *error));
            session->incoming_publish_namespaces_by_id_.erase(
                message.request_id);
            session->incoming_publish_namespaces_by_namespace_.erase(
                track_namespace);
          } else {
            CheckStatus(SendRequestOk(message.request_id, MessageParameters()));
          }
        });
    return absl::OkStatus();
  }
  // TODO(martinduke): Check all the request types.
  // Does not match any known request.
  return SendRequestError(message.request_id, RequestErrorCode::kNotSupported,
                          std::nullopt, "No support for update of this type");
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtPublishNamespace& message) {
  if (!session_->ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  if (session_->sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received a PUBLISH_NAMESPACE after GOAWAY";
    return SendRequestError(message.request_id, RequestErrorCode::kUnauthorized,
                            std::nullopt, "PUBLISH_NAMESPACE after GOAWAY");
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received a PUBLISH_NAMESPACE for "
                  << message.track_namespace;
  auto [it, inserted] =
      session_->incoming_publish_namespaces_by_namespace_.emplace(
          message.track_namespace, message.request_id);
  if (!inserted) {
    return SendRequestError(message.request_id,
                            RequestErrorCode::kDuplicateSubscription,
                            std::nullopt, "Duplicate PUBLISH_NAMESPACE");
  }
  quiche::QuicheWeakPtr<MoqtSessionInterface> session_weakptr =
      session_->GetWeakPtr();
  session_->incoming_publish_namespaces_by_id_[message.request_id] =
      message.track_namespace;
  session_->callbacks_.incoming_publish_namespace_callback(
      message.track_namespace, message.parameters,
      [&](std::optional<MoqtRequestErrorInfo> error) {
        MoqtSession* session =
            absl::down_cast<MoqtSession*>(session_weakptr.GetIfAvailable());
        if (session == nullptr) {
          return;
        }
        if (error.has_value()) {
          CheckStatus(SendRequestError(message.request_id, *error));
          session->incoming_publish_namespaces_by_id_.erase(message.request_id);
          session->incoming_publish_namespaces_by_namespace_.erase(
              message.track_namespace);
        } else {
          CheckStatus(SendRequestOk(message.request_id, MessageParameters()));
        }
      });
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtPublishNamespaceDone& message) {
  auto it =
      session_->incoming_publish_namespaces_by_id_.find(message.request_id);
  if (it == session_->incoming_publish_namespaces_by_id_.end()) {
    return absl::OkStatus();
  }
  session_->callbacks_.incoming_publish_namespace_callback(
      it->second, std::nullopt, nullptr);
  session_->incoming_publish_namespaces_by_namespace_.erase(it->second);
  session_->incoming_publish_namespaces_by_id_.erase(it);
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtPublishNamespaceCancel& message) {
  auto it = session_->publish_namespace_by_id_.find(message.request_id);
  if (it == session_->publish_namespace_by_id_.end()) {
    return absl::OkStatus();  // State might have been destroyed due to
                              // PUBLISH_NAMESPACE_DONE.
  }
  std::move(it->second.cancel_callback)(MoqtRequestErrorInfo{
      message.error_code, std::nullopt, std::string(message.error_reason)});
  session_->publish_namespace_by_namespace_.erase(it->second.track_namespace);
  session_->publish_namespace_by_id_.erase(it);
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtTrackStatus& message) {
  if (!session_->ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  if (session_->sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Received a TRACK_STATUS_REQUEST after GOAWAY";
    return SendRequestError(message.request_id, RequestErrorCode::kUnauthorized,
                            std::nullopt, "TRACK_STATUS_REQUEST after GOAWAY");
  }
  // TODO(martinduke): Handle authentication.
  std::shared_ptr<MoqtTrackPublisher> track =
      session_->publisher_->GetTrack(message.full_track_name);
  if (track == nullptr) {
    return SendRequestError(message.request_id, RequestErrorCode::kDoesNotExist,
                            std::nullopt, "Track does not exist");
  }
  auto [it, inserted] = session_->incoming_track_status_.emplace(
      message.request_id, std::make_unique<DownstreamTrackStatus>(
                              message.request_id, session_, track.get()));
  track->AddObjectListener(it->second.get());
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtGoAway& message) {
  if (!message.new_session_uri.empty() &&
      perspective() == quic::Perspective::IS_SERVER) {
    return absl::InvalidArgumentError(
        "Received GOAWAY with new_session_uri on the server");
  }
  if (session_->received_goaway_) {
    return absl::InvalidArgumentError("Received multiple GOAWAY messages");
  }
  session_->received_goaway_ = true;
  if (session_->callbacks_.goaway_received_callback != nullptr) {
    std::move(session_->callbacks_.goaway_received_callback)(
        message.new_session_uri);
  }
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtMaxRequestId& message) {
  if (message.max_request_id < session_->peer_max_request_id_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Peer sent MAX_REQUEST_ID message with "
                       "lower value than previous";
    return absl::InvalidArgumentError(
        "MAX_REQUEST_ID has lower value than previous");
  }
  session_->peer_max_request_id_ = message.max_request_id;
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtFetch& message) {
  if (!session_->ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  if (session_->sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received a FETCH after GOAWAY";
    return SendRequestError(message.request_id, RequestErrorCode::kUnauthorized,
                            std::nullopt, "FETCH after GOAWAY");
  }
  std::unique_ptr<MoqtFetchTask> fetch;
  FullTrackName track_name;
  if (std::holds_alternative<StandaloneFetch>(message.fetch)) {
    const StandaloneFetch& standalone_fetch =
        std::get<StandaloneFetch>(message.fetch);
    track_name = standalone_fetch.full_track_name;
    std::shared_ptr<MoqtTrackPublisher> track_publisher =
        session_->publisher_->GetTrack(track_name);
    if (track_publisher == nullptr) {
      QUIC_DLOG(INFO) << ENDPOINT << "FETCH for " << track_name
                      << " rejected by the application: not found";
      return SendRequestError(message.request_id,
                              RequestErrorCode::kDoesNotExist, std::nullopt,
                              "not found");
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Received a StandaloneFETCH for "
                    << track_name;
    // The check for end_object < start_object is done in
    // MoqtTrackPublisher::Fetch().
    fetch = track_publisher->StandaloneFetch(
        standalone_fetch.start_location, standalone_fetch.end_location,
        message.parameters.group_order.value_or(MoqtDeliveryOrder::kAscending));
  } else {
    // Joining Fetch processing.
    uint64_t joining_request_id =
        std::holds_alternative<JoiningFetchRelative>(message.fetch)
            ? std::get<struct JoiningFetchRelative>(message.fetch)
                  .joining_request_id
            : std::get<JoiningFetchAbsolute>(message.fetch).joining_request_id;
    auto it = session_->published_subscriptions_.find(joining_request_id);
    if (it == session_->published_subscriptions_.end()) {
      QUIC_DLOG(INFO) << ENDPOINT << "Received a JOINING_FETCH for "
                      << "request_id " << joining_request_id
                      << " that does not exist";
      return SendRequestError(
          message.request_id, RequestErrorCode::kInvalidJoiningRequestId,
          std::nullopt, "Joining Fetch for non-existent request");
    }
    if (!it->second->can_have_joining_fetch()) {
      QUIC_DLOG(INFO) << ENDPOINT << "Received a JOINING_FETCH for "
                      << "joining_request_id " << joining_request_id
                      << " that is not forwarding";
      return absl::InvalidArgumentError(
          "Joining Fetch for non-forwarding subscribe");
    }
    track_name = it->second->publisher().GetTrackName();
    if (it->second->established()) {
      if (!it->second->parameters().largest_object.has_value()) {
        // Nothing to Fetch.
        return SendRequestError(message.request_id,
                                RequestErrorCode::kDoesNotExist, std::nullopt,
                                "not found");
      }
      const Location largest_location =
          *it->second->parameters().largest_object;
      uint64_t start_group;
      if (std::holds_alternative<JoiningFetchRelative>(message.fetch)) {
        const JoiningFetchRelative& relative_fetch =
            std::get<JoiningFetchRelative>(message.fetch);
        start_group =
            (relative_fetch.joining_start > largest_location.group)
                ? 0
                : (largest_location.group - relative_fetch.joining_start);
      } else {
        const JoiningFetchAbsolute& absolute_fetch =
            std::get<JoiningFetchAbsolute>(message.fetch);
        start_group = absolute_fetch.joining_start;
        if (start_group > largest_location.group) {
          return SendRequestError(message.request_id,
                                  RequestErrorCode::kInvalidRange, std::nullopt,
                                  "invalid range");
        }
      }
      fetch = it->second->publisher().StandaloneFetch(
          Location{start_group, 0}, largest_location,
          message.parameters.group_order.value_or(
              MoqtDeliveryOrder::kAscending));
    } else {
      // Subscription is in PENDING state.
      if (std::holds_alternative<JoiningFetchRelative>(message.fetch)) {
        fetch = it->second->publisher().RelativeFetch(
            std::get<JoiningFetchRelative>(message.fetch).joining_start,
            message.parameters.group_order.value_or(
                MoqtDeliveryOrder::kAscending));
      } else {
        fetch = it->second->publisher().AbsoluteFetch(
            std::get<JoiningFetchAbsolute>(message.fetch).joining_start,
            message.parameters.group_order.value_or(
                MoqtDeliveryOrder::kAscending));
      }
    }
  }
  if (!fetch->GetStatus().ok()) {
    QUIC_DLOG(INFO) << ENDPOINT << "FETCH for " << track_name
                    << " could not initialize the task";
    return SendRequestError(message.request_id, RequestErrorCode::kInvalidRange,
                            std::nullopt, fetch->GetStatus().message());
  }
  auto published_fetch =
      std::make_unique<PublishedFetch>(message.request_id, std::move(fetch));
  auto result = session_->incoming_fetches_.emplace(message.request_id,
                                                    std::move(published_fetch));
  if (!result.second) {  // Emplace failed.
    QUIC_DLOG(INFO) << ENDPOINT << "FETCH for " << track_name
                    << " could not be added to the session";
    return SendRequestError(message.request_id,
                            RequestErrorCode::kInternalError, std::nullopt,
                            "Could not initialize FETCH state");
  }
  MoqtFetchTask* fetch_task = result.first->second->fetch_task_ptr();
  fetch_task->SetFetchResponseCallback(
      [this, request_id = message.request_id](
          std::variant<MoqtFetchOk, MoqtRequestError> message) {
        if (!session_->incoming_fetches_.contains(request_id)) {
          return;  // FETCH was cancelled.
        }
        if (std::holds_alternative<MoqtFetchOk>(message)) {
          MoqtFetchOk& fetch_ok = std::get<MoqtFetchOk>(message);
          fetch_ok.request_id = request_id;
          CheckStatus(SendOrBufferMessage(
              session_->framer_.SerializeFetchOk(fetch_ok)));
          return;
        }
        CheckStatus(SendRequestError(
            request_id, std::get<MoqtRequestError>(message).error_code,
            std::get<MoqtRequestError>(message).retry_interval,
            std::get<MoqtRequestError>(message).reason_phrase));
      });
  // Set a temporary new-object callback that creates a data stream. When
  // created, the stream visitor will replace this callback.
  fetch_task->SetObjectAvailableCallback(
      [this,
       subscriber_priority = message.parameters.subscriber_priority.value_or(
           kDefaultSubscriberPriority),
       request_id = message.request_id]() {
        auto it = session_->incoming_fetches_.find(request_id);
        if (it == session_->incoming_fetches_.end()) {
          return;
        }
        if (!session_->session()->CanOpenNextOutgoingUnidirectionalStream() ||
            !session_->OpenDataStream(it->second.get(),
                                      SendOrderForFetch(subscriber_priority))) {
          session_->UpdateTrackPriority(
              request_id, std::nullopt,
              MoqtTrackPriority(subscriber_priority,
                                kDefaultPublisherPriority));
        }
      });
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtFetchOk& message) {
  RemoteTrack* track = session_->RemoteTrackById(message.request_id);
  if (track == nullptr) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received the FETCH_OK for "
                    << "request_id = " << message.request_id
                    << " but no track exists";
    // Subscription state might have been destroyed for internal reasons.
    return absl::OkStatus();
  }
  if (!track->is_fetch()) {
    return absl::InvalidArgumentError("Received FETCH_OK for a SUBSCRIBE");
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received the FETCH_OK for request_id = "
                  << message.request_id << " " << track->full_track_name();
  UpstreamFetch* fetch = absl::down_cast<UpstreamFetch*>(track);
  fetch->OnFetchResult(
      message.end_location, absl::OkStatus(),
      [=, session = session_]() { session->CancelFetch(message.request_id); });
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtRequestsBlocked& message) {
  // TODO(martinduke): Derive logic for granting more subscribes.
  return absl::OkStatus();
}

absl::Status MoqtSession::ControlStream::OnControlMessage(
    const MoqtPublish& message) {
  if (!session_->ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  RequestErrorCode error_code = session_->sent_goaway_
                                    ? RequestErrorCode::kUnauthorized
                                    : RequestErrorCode::kNotSupported;
  absl::string_view error_reason = session_->sent_goaway_
                                       ? "Received a PUBLISH after GOAWAY"
                                       : "PUBLISH is not supported";
  return SendRequestError(message.request_id, error_code, std::nullopt,
                          error_reason);
}

void MoqtSession::OnMalformedTrack(RemoteTrack* track) {
  if (!track->is_fetch()) {
    absl::down_cast<SubscribeRemoteTrack*>(track)->visitor()->OnMalformedTrack(
        track->full_track_name());
    Unsubscribe(track->full_track_name());
    return;
  }
  UpstreamFetch::UpstreamFetchTask* task =
      absl::down_cast<UpstreamFetch*>(track)->task();
  if (task != nullptr) {
    task->OnStreamAndFetchClosed(kResetCodeMalformedTrack,
                                 "Malformed track received");
  }
  CancelFetch(track->request_id());
}

void MoqtSession::CleanUpState() {
  if (is_closing_) {
    return;
  }
  is_closing_ = true;
  if (goaway_timeout_alarm_ != nullptr) {
    goaway_timeout_alarm_->PermanentCancel();
  }
  // Incoming SUBSCRIBE_NAMESPACE is automatically cleaned up; the destroyed
  // session owns the webtransport stream, which owns the StreamVisitor, which
  // owns the task. Destroying the task notifies the application.
  published_subscriptions_.clear();
  for (auto& it : incoming_publish_namespaces_by_namespace_) {
    callbacks_.incoming_publish_namespace_callback(it.first, std::nullopt,
                                                   nullptr);
  }
  for (auto& it : publish_namespace_by_id_) {
    std::move(it.second.cancel_callback)(MoqtRequestErrorInfo{
        RequestErrorCode::kUninterested, std::nullopt, "Session closed"});
  }
  while (!upstream_by_id_.empty()) {
    upstream_by_id_.begin()->second->Destroy();
  }
}

void MoqtSession::CancelFetch(uint64_t request_id) {
  if (is_closing_) {
    return;
  }
  auto it = upstream_by_id_.find(request_id);
  if (it == upstream_by_id_.end()) {
    return;
  }
  it->second->Destroy();
  // This is only called from the callback where UpstreamFetchTask has been
  // destroyed, so there is no need to notify the application.
  ControlStream* stream = GetControlStream();
  if (stream == nullptr) {
    return;
  }
  MoqtFetchCancel message;
  message.request_id = request_id;
  stream->SendOrBufferMessageOrFatal(framer_.SerializeFetchCancel(message));
  // The FETCH_CANCEL will cause a RESET_STREAM to return, which would be the
  // same as a STOP_SENDING. However, a FETCH_CANCEL works even if the stream
  // hasn't opened yet.
}

void MoqtSessionParameters::ToSetupParameters(SetupParameters& out) const {
  if (perspective == quic::Perspective::IS_CLIENT && !using_webtrans) {
    out.path = path;
    out.authority = authority;
  }
  if (max_request_id != kDefaultMaxRequestId) {
    out.max_request_id = max_request_id;
  }
  if (max_auth_token_cache_size != kDefaultMaxAuthTokenCacheSize) {
    out.max_auth_token_cache_size = max_auth_token_cache_size;
  }
  if (support_object_acks != kDefaultSupportObjectAcks) {
    out.support_object_acks = support_object_acks;
  }
  if (!moqt_implementation.empty()) {
    out.moqt_implementation = moqt_implementation;
  }
  for (const AuthToken& token : authorization_token) {
    out.authorization_tokens.push_back(token);
  }
}

}  // namespace moqt
