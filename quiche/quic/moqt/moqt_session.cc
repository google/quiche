// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_session.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>

#include "absl/base/casts.h"
#include "absl/base/nullability.h"
#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/container/node_hash_map.h"
#include "absl/functional/bind_front.h"
#include "absl/functional/overload.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_live_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_namespace_stream.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_object_subscriber.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publish_stream.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_subscribe_stream.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"
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
      framer_(parameters.using_webtrans, parameters.perspective),
      publisher_(DefaultPublisher::GetInstance()),
      local_max_request_id_(parameters.max_request_id),
      alarm_factory_(std::move(alarm_factory)),
      weak_ptr_factory_(this),
      weak_ptr_factory_for_publishers_(this),
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
  MoqtSetup setup;
  parameters_.ToSetupParameters(setup.parameters);
  SendControlMessage(framer_.SerializeSetup(setup));
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
    if (sent_goaway_) {
      // Immediately reject new requests with REQUEST_ERROR. If the stream
      // cannot be written, just reset it.
      if (!stream->CanWrite()) {
        stream->ResetWithUserCode(kResetCodeSessionClosed);
        continue;
      }
      webtransport::StreamWriteOptions options;
      options.set_send_fin(true);
      std::array write_vector = {
          quiche::QuicheMemSlice(framer_.SerializeRequestError(MoqtRequestError{
              0, RequestErrorCode::kGoingAway, std::nullopt, ""}))};
      if (!stream->Writev(absl::MakeSpan(write_vector), options).ok()) {
        stream->ResetWithUserCode(kResetCodeSessionClosed);
      };
      continue;
    }
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
  LiveSubscriber* track = SubscribeByAlias(message.track_alias);
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
    TrackNamespace& prefix, const MessageParameters& parameters,
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
  if (!outgoing_subscribe_namespace_.SubscribeNamespace(prefix)) {
    std::move(response_callback)(MoqtRequestErrorInfo{
        RequestErrorCode::kInternalError, std::nullopt,
        "SUBSCRIBE_NAMESPACE already outstanding for namespace"});
    return nullptr;
  }
  std::unique_ptr<MoqtSubscribeNamespaceRequestStream> state =
      std::make_unique<MoqtSubscribeNamespaceRequestStream>(
          &framer_, ControlMessageParser(), next_request_id_,
          [weakptr = GetWeakPtr()](const TrackNamespace& prefix) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session != nullptr) {
              session->outgoing_subscribe_namespace_.UnsubscribeNamespace(
                  prefix);
            }
          },
          [weakptr = GetWeakPtr()](MoqtError error, absl::string_view reason) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session != nullptr) {
              session->Error(error, reason);
            }
          },
          std::move(response_callback));
  MoqtSubscribeNamespaceRequestStream* state_ptr = state.get();
  if (session_->CanOpenNextOutgoingBidirectionalStream()) {
    webtransport::Stream* stream = session_->OpenOutgoingBidirectionalStream();
    state->BindStream(stream);
    stream->SetVisitor(std::move(state));
  } else {
    pending_bidi_streams_.push_back(std::move(state));
  }
  MoqtSubscribeNamespace message;
  message.request_id = NextRequestId();
  message.track_namespace_prefix = prefix;
  message.parameters = parameters;
  state_ptr->SendOrBufferMessageOrFatal(
      framer_.SerializeSubscribeNamespace(message));
  QUIC_DLOG(INFO) << ENDPOINT << "Sent SUBSCRIBE_NAMESPACE message for "
                  << message.track_namespace_prefix;
  return state_ptr->CreateTask(prefix);
}

bool MoqtSession::SubscribeTracks(TrackNamespace& prefix,
                                  const MessageParameters& parameters,
                                  MoqtResponseCallback response_callback) {
  return false;
}

void MoqtSession::UnsubscribeTracks(TrackNamespace& prefix) {
  // Do nothing.
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
                            SubscribeVisitor* absl_nonnull visitor,
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
  if (!session_->CanOpenNextOutgoingBidirectionalStream()) {
    return false;  // Do not retry opening a SUBSCRIBE stream.
  }
  auto stream_visitor = std::make_unique<MoqtSubscribeRequestStream>(
      &framer_, ControlMessageParser(), NextRequestId(),
      [weak_session = GetWeakPtr()](MoqtError code, absl::string_view reason) {
        MoqtSessionInterface* session = weak_session.GetIfAvailable();
        if (session == nullptr) {
          return;
        }
        session->Error(code, reason);
      },
      name, visitor, parameters,
      [weakptr = GetWeakPtr()](LiveSubscriber* track) {
        MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
        if (session == nullptr || !track->track_alias().has_value()) {
          return false;
        }
        auto [it, success] = session->subscribe_by_alias_.try_emplace(
            *track->track_alias(), track);
        return success;
      },
      [weakptr = GetWeakPtr()](LiveSubscriber* track) {
        MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
        if (session == nullptr) {
          return;
        }
        session->subscribe_by_name_.erase(track->full_track_name());
        if (track->track_alias().has_value()) {
          session->subscribe_by_alias_.erase(*track->track_alias());
        }
      },
      callbacks_.clock, alarm_factory_.get());
  webtransport::Stream* stream = session_->OpenOutgoingBidirectionalStream();
  QUICHE_CHECK(stream != nullptr);
  MoqtSubscribeRequestStream* stream_visitor_ptr = stream_visitor.get();
  stream->SetVisitor(std::move(stream_visitor));
  stream_visitor_ptr->BindStream(stream);
  subscribe_by_name_[name] = stream_visitor_ptr->track();
  if (SupportsObjectAck()) {
    visitor->OnCanAckObjects(
        absl::bind_front(&MoqtSession::SendObjectAck, this, name));
  }
  return true;
}

bool MoqtSession::SubscribeUpdate(const FullTrackName& name,
                                  const MessageParameters& parameters,
                                  MoqtResponseCallback response_callback) {
  QUICHE_DCHECK(name.IsValid());
  auto it = subscribe_by_name_.find(name);
  if (it == subscribe_by_name_.end()) {
    return false;
  }
  // sending zero because related request ID is ignored for SUBSCRIBE.
  return it->second->request_stream()
      ->SendRequestUpdate(NextRequestId(), 0, parameters,
                          std::move(response_callback))
      .ok();
}

bool MoqtSession::PublishUpdate(const FullTrackName& name,
                                const MessageParameters& parameters,
                                MoqtResponseCallback response_callback) {
  // TODO(martinduke): Implement this.
  return false;
}

void MoqtSession::Unsubscribe(const FullTrackName& name) {
  if (is_closing_) {
    return;
  }
  QUICHE_DCHECK(name.IsValid());
  auto it = subscribe_by_name_.find(name);
  if (it == subscribe_by_name_.end()) {
    return;
  }
  it->second->request_stream()->Reset(kResetCodeCancelled);
}

bool MoqtSession::Publish(
    std::shared_ptr<MoqtTrackPublisher> absl_nonnull publisher,
    const MessageParameters& parameters, const TrackExtensions& extensions,
    MoqtResponseCallback response_callback) {
  if (received_goaway_ || sent_goaway_) {
    QUICHE_DLOG(INFO) << ENDPOINT << "Tried to send PUBLISH after GOAWAY";
    return false;
  }
  const FullTrackName& name = publisher->GetTrackName();
  QUICHE_DCHECK(name.IsValid());
  if (!session_->CanOpenNextOutgoingBidirectionalStream()) {
    return false;  // Do not retry opening a PUBLISH stream.
  }
  auto it = subscribed_track_names_.find(name);
  if (it != subscribed_track_names_.end()) {
    if (it->second->established()) {
      QUICHE_DLOG(INFO) << ENDPOINT << "Tried to send PUBLISH for track "
                        << name << " which is already published";
      return false;
    }
    it->second->OnSubscribeRejected(
        MoqtRequestErrorInfo{RequestErrorCode::kDuplicateSubscription,
                             std::nullopt, "PUBLISH is coming"});
  }
  auto stream_visitor = std::make_unique<MoqtPublishRequestStream>(
      &framer_, ControlMessageParser(),
      [weak_session = GetWeakPtr()](LivePublisher* publisher) {
        MoqtSession* session = MoqtSessionFromWeakPtr(weak_session);
        if (session == nullptr) {
          return;
        }
        session->subscribed_track_names_.erase(
            publisher->publisher().GetTrackName());
        session->published_subscriptions_.erase(publisher->request_id());
      },
      [weak_session = GetWeakPtr()](MoqtError code, absl::string_view reason) {
        MoqtSessionInterface* session = weak_session.GetIfAvailable();
        if (session == nullptr) {
          return;
        }
        session->Error(code, reason);
      },
      std::move(response_callback));
  auto publish_state = std::make_unique<LivePublisher>(
      framer_, publisher, stream_visitor.get(), next_request_id_,
      next_local_track_alias_, parameters,
      weak_ptr_factory_for_publishers_.Create(), true);
  LivePublisher* publisher_ptr = publish_state.get();
  stream_visitor->SetPublisher(std::move(publish_state));
  webtransport::Stream* stream = session_->OpenOutgoingBidirectionalStream();
  MoqtPublishRequestStream* stream_visitor_ptr = stream_visitor.get();
  stream->SetVisitor(std::move(stream_visitor));
  stream_visitor_ptr->BindStream(stream);
  next_request_id_ += 2;
  ++next_local_track_alias_;
  publisher->AddObjectListener(publisher_ptr);
  return true;
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
      [this, id = message.request_id]() {
        fetch_by_id_.erase(id);  // Deletion callback
      });
  fetch_by_id_.emplace(message.request_id, std::move(fetch));
  return true;
}

bool MoqtSession::RelativeJoiningFetch(const FullTrackName& name,
                                       SubscribeVisitor* visitor,
                                       uint64_t num_previous_groups,
                                       MessageParameters parameters) {
  QUICHE_DCHECK(name.IsValid());
  return RelativeJoiningFetch(
      name, visitor,
      [this, track_name = name](std::unique_ptr<MoqtFetchTask> fetch_task) {
        // Move the fetch_task to the subscribe to plumb into its visitor.
        LiveSubscriber* subscribe = SubscribeByName(track_name);
        if (subscribe == nullptr || subscribe->is_fetch()) {
          fetch_task.release();
          return;
        }
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
        fetch_by_id_.erase(id);
      });
  fetch_by_id_.emplace(fetch.request_id, std::move(upstream_fetch));
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

std::shared_ptr<MoqtTrackPublisher> MoqtSession::GetTrackPublisher(
    const FullTrackName& name) {
  if (publisher_ == nullptr) {
    return nullptr;
  }
  return publisher_->GetTrack(name);
}

MoqtPublishingMonitorInterface* MoqtSession::ReleaseMonitoringInterface(
    const FullTrackName& name) {
  auto it = monitoring_interfaces_for_published_tracks_.find(name);
  if (it == monitoring_interfaces_for_published_tracks_.end()) {
    return nullptr;
  }
  MoqtPublishingMonitorInterface* interface = it->second;
  monitoring_interfaces_for_published_tracks_.erase(it);
  return interface;
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

LiveSubscriber* MoqtSession::SubscribeByAlias(uint64_t track_alias) {
  auto it = subscribe_by_alias_.find(track_alias);
  if (it == subscribe_by_alias_.end()) {
    return nullptr;
  }
  return it->second;
}

LiveSubscriber* MoqtSession::SubscribeByName(const FullTrackName& track_name) {
  auto it = subscribe_by_name_.find(track_name);
  if (it == subscribe_by_name_.end()) {
    return nullptr;
  }
  return it->second;
}

UpstreamFetch* MoqtSession::FetchById(uint64_t request_id) {
  auto it = fetch_by_id_.find(request_id);
  if (it == fetch_by_id_.end()) {
    return nullptr;
  }
  return it->second.get();
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
  // TODO(martinduke): Write new checks for duplicate request IDs. It's
  // probably best to track the largest observed plus a set of holes.
  if (incoming_fetches_.contains(request_id) ||
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
    case MoqtMessageType::kSetup: {
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
      auto namespace_stream =
          std::make_unique<MoqtSubscribeNamespaceResponseStream>(
              &session_->framer_, session_->ControlMessageParser(),
              [weakptr = session_->GetWeakPtr()](const TrackNamespace& prefix) {
                MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
                if (session != nullptr) {
                  return session->incoming_subscribe_namespace_
                      .SubscribeNamespace(prefix);
                }
                return true;
              },
              [weakptr = session_->GetWeakPtr()](const TrackNamespace& prefix) {
                MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
                if (session != nullptr) {
                  session->incoming_subscribe_namespace_.UnsubscribeNamespace(
                      prefix);
                }
              },
              [weakptr = session_->GetWeakPtr()](MoqtError code,
                                                 absl::string_view reason) {
                MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
                if (session != nullptr) {
                  session->Error(code, reason);
                }
              },
              session_->callbacks_.incoming_subscribe_namespace_callback);
      namespace_stream->BindStream(std::move(parser_));
      MoqtSubscribeNamespaceResponseStream* temp_stream =
          namespace_stream.get();
      stream_->SetVisitor(std::move(namespace_stream));
      // The UnknownBidiStream object is deleted; no class access after this
      // point.
      temp_stream->OnCanRead();
      break;
    }
    case MoqtMessageType::kSubscribeTracks: {
      // TODO(martinduke): Implement this.
      MoqtControlMessageQueue queue(stream_);
      if (!queue
               .SendOrBufferMessage(
                   session_->framer_.SerializeRequestError(MoqtRequestError{
                       /*request_id=*/0, RequestErrorCode::kNotSupported,
                       std::nullopt, "SUBSCRIBE_TRACKS is not supported"}),
                   /*fin=*/true)
               .ok()) {
        session_->Error(MoqtError::kInternalError, "Internal write error");
        return;
      }
      break;
    }
    case MoqtMessageType::kPublish: {
      auto publish_stream = std::make_unique<MoqtPublishResponseStream>(
          &session_->framer_, session_->ControlMessageParser(),
          session_->callbacks_.clock, session_->alarm_factory(),
          [weakptr = session_->GetWeakPtr()](MoqtError code,
                                             absl::string_view reason) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session != nullptr) {
              session->Error(code, reason);
            }
          },
          &session_->callbacks_.incoming_publish_callback,
          [weakptr = session_->GetWeakPtr()](LiveSubscriber* track) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session == nullptr) {
              return false;
            }
            QUICHE_BUG_IF(quiche_bug_publish_no_track_alias,
                          !track->track_alias().has_value())
                << "PUBLISH with no track alias";
            if (!track->track_alias().has_value()) {
              return false;
            }
            auto [alias_it, alias_inserted] =
                session->subscribe_by_alias_.try_emplace(*track->track_alias(),
                                                         track);
            if (!alias_inserted) {
              // Already a PUBLISH or an established SUBSCRIBE.
              return false;
            }
            auto it =
                session->subscribe_by_name_.find(track->full_track_name());
            if (it != session->subscribe_by_name_.end()) {
              // It's a pending SUBSCRIBE; kill it, but use the parameters and
              // visitor from the SUBSCRIBE.
              track->Update(it->second->const_parameters());
              track->set_visitor(it->second->ReleaseVisitor());
              session->Unsubscribe(it->second->full_track_name());
            }
            auto [name_it, name_inserted] =
                session->subscribe_by_name_.try_emplace(
                    track->full_track_name(), track);
            QUICHE_DCHECK(name_inserted);
            return true;
          },
          [weakptr = session_->GetWeakPtr()](LiveSubscriber* track) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session != nullptr) {
              session->subscribe_by_name_.erase(track->full_track_name());
              if (track->track_alias().has_value()) {
                session->subscribe_by_alias_.erase(*track->track_alias());
              }
            }
          });
      publish_stream->BindStream(std::move(parser_));
      MoqtPublishResponseStream* temp_stream = publish_stream.get();
      stream_->SetVisitor(std::move(publish_stream));
      // The UnknownBidiStream object is deleted; no class access after this
      // point.
      temp_stream->OnCanRead();
      break;
    }
    case MoqtMessageType::kSubscribe: {
      auto subscribe_stream = std::make_unique<MoqtSubscribeResponseStream>(
          &session_->framer_, session_->ControlMessageParser(),
          session_->next_local_track_alias_++,
          [weakptr = session_->GetWeakPtr()](LivePublisher* subscription) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session == nullptr) {
              return true;
            }
            auto [it, success] = session->published_subscriptions_.try_emplace(
                subscription->request_id(), subscription);
            if (!success) {
              return false;
            }
            auto [it2, success2] = session->subscribed_track_names_.try_emplace(
                subscription->publisher().GetTrackName(), subscription);
            return success2;
          },
          [weakptr = session_->GetWeakPtr()](LivePublisher* subscription) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session == nullptr) {
              return;
            }
            session->published_subscriptions_.erase(subscription->request_id());
            session->subscribed_track_names_.erase(
                subscription->publisher().GetTrackName());
          },
          [weakptr = session_->GetWeakPtr()](MoqtError code,
                                             absl::string_view reason) {
            MoqtSession* session = MoqtSessionFromWeakPtr(weakptr);
            if (session != nullptr) {
              session->Error(code, reason);
            }
          },
          session_->weak_ptr_factory_for_publishers_.Create());
      subscribe_stream->BindStream(std::move(parser_));
      MoqtSubscribeResponseStream* temp_stream = subscribe_stream.get();
      stream_->SetVisitor(std::move(subscribe_stream));
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
  return ControlMessageDispatcher::DispatchControlMessage(
      *session_, message_parser(), message, "control");
}

absl::Status MoqtSession::OnControlMessage(const MoqtSetup& message) {
  if (parameters_.perspective == Perspective::IS_SERVER) {
    peer_supports_object_ack_ = message.parameters.support_object_acks.value_or(
        kDefaultSupportObjectAcks);
    peer_max_request_id_ =
        message.parameters.max_request_id.value_or(kDefaultMaxRequestId);
    QUICHE_DLOG(INFO) << "Received CLIENT_SETUP";
    MoqtSetup response;
    parameters_.ToSetupParameters(response.parameters);
    SendControlMessage(framer_.SerializeSetup(response));
    QUICHE_DLOG(INFO) << "Sent SERVER_SETUP";
    // TODO: handle path.
    std::move(callbacks_.session_established_callback)();
    return absl::OkStatus();
  } else {
    peer_supports_object_ack_ = message.parameters.support_object_acks.value_or(
        kDefaultSupportObjectAcks);
    QUIC_DLOG(INFO) << ENDPOINT << "Received the SETUP message";
    // TODO: handle path.
    peer_max_request_id_ =
        message.parameters.max_request_id.value_or(kDefaultMaxRequestId);
    std::move(callbacks_.session_established_callback)();
    return absl::OkStatus();
  }
}

absl::Status MoqtSession::OnControlMessage(const MoqtRequestOk& message) {
  if (fetch_by_id_.contains(message.request_id)) {
    return absl::InvalidArgumentError("Received REQUEST_OK for FETCH");
  }
  // Response to PUBLISH_NAMESPACE.
  auto pn_it = publish_namespace_by_id_.find(message.request_id);
  if (pn_it != publish_namespace_by_id_.end()) {
    if (pn_it->second.response_callback == nullptr) {
      return absl::InvalidArgumentError(
          "Multiple responses for PUBLISH_NAMESPACE");
    }
    std::move(pn_it->second.response_callback)(MessageParameters());
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

absl::Status MoqtSession::OnControlMessage(const MoqtRequestError& message) {
  MoqtRequestErrorInfo error_info{message.error_code, message.retry_interval,
                                  message.reason_phrase};
  // TODO(martinduke): Do something with retry_interval.
  UpstreamFetch* fetch = FetchById(message.request_id);
  if (fetch != nullptr) {
    // It's in response to FETCH.
    if (!fetch->ErrorIsAllowed()) {
      return absl::InvalidArgumentError(
          "Received REQUEST_ERROR after REQUEST_OK or objects");
    }
    QUIC_DLOG(INFO) << ENDPOINT << "Received the REQUEST_ERROR for "
                    << "request_id = " << message.request_id << " ("
                    << fetch->full_track_name() << ")"
                    << ", error = " << static_cast<uint64_t>(message.error_code)
                    << " (" << message.reason_phrase << ")";
    absl::Status status =
        RequestErrorCodeToStatus(message.error_code, message.reason_phrase);
    fetch->OnFetchResult(Location(0, 0), status, nullptr);
    if (!is_closing_) {
      // The visitor might have closed the session.
      fetch->Destroy();
    }
    return absl::OkStatus();
  }
  // Response to PUBLISH_NAMESPACE.
  auto pn_it = publish_namespace_by_id_.find(message.request_id);
  if (pn_it != publish_namespace_by_id_.end()) {
    if (pn_it->second.response_callback == nullptr) {
      return absl::InvalidArgumentError(
          "Multiple responses for PUBLISH_NAMESPACE");
    }
    std::move(pn_it->second.response_callback)(error_info);
    publish_namespace_by_namespace_.erase(pn_it->second.track_namespace);
    publish_namespace_by_id_.erase(pn_it);
    return absl::OkStatus();
  }
  // Response to SUBSCRIBE_NAMESPACE is handled in the NamespaceStream.
  // TRACK_STATUS response would go here, but we don't support upstream
  // TRACK_STATUS.
  // If it doesn't match any state, it might be because the local application
  // cancelled the request. Do nothing.
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtRequestUpdate& message) {
  auto pn_it = publish_namespace_by_id_.find(message.existing_request_id);
  if (pn_it != publish_namespace_by_id_.end()) {
    // It's updating PUBLISH_NAMESPACE.
    quiche::QuicheWeakPtr<MoqtSessionInterface> session_weakptr = GetWeakPtr();
    TrackNamespace track_namespace = pn_it->second.track_namespace;
    callbacks().incoming_publish_namespace_callback(
        track_namespace, message.parameters,
        [&](std::variant<MessageParameters, MoqtRequestErrorInfo> response) {
          MoqtSession* session =
              absl::down_cast<MoqtSession*>(session_weakptr.GetIfAvailable());
          if (session == nullptr) {
            return;
          }
          std::visit(
              absl::Overload{
                  [this, request_id = message.request_id](
                      const MessageParameters& parameters) {
                    // In draft-18, there are no useful parameters in
                    // PUBLISH_NAMESPACE_OK, but Issue #1639 would change that.
                    SendControlMessage(framer_.SerializeRequestOk(MoqtRequestOk{
                        .request_id = request_id, .parameters = parameters}));
                  },
                  [this, id = message.request_id, track_ns = track_namespace](
                      const MoqtRequestErrorInfo& error_info) {
                    SendRequestErrorOnControlStream(id, error_info.error_code,
                                                    error_info.retry_interval,
                                                    error_info.reason_phrase);
                    incoming_publish_namespaces_by_id_.erase(id);
                    incoming_publish_namespaces_by_namespace_.erase(track_ns);
                  }},
              response);
        });
    return absl::OkStatus();
  }
  // TODO(martinduke): Check all the request types.
  // Does not match any known request.
  SendRequestErrorOnControlStream(message.request_id,
                                  RequestErrorCode::kNotSupported, std::nullopt,
                                  "No support for update of this type");
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(
    const MoqtPublishNamespace& message) {
  if (!ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  if (sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received a PUBLISH_NAMESPACE after GOAWAY";
    SendRequestErrorOnControlStream(
        message.request_id, RequestErrorCode::kUnauthorized, std::nullopt,
        "PUBLISH_NAMESPACE after GOAWAY");
    return absl::OkStatus();
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received a PUBLISH_NAMESPACE for "
                  << message.track_namespace;
  auto [it, inserted] = incoming_publish_namespaces_by_namespace_.emplace(
      message.track_namespace, message.request_id);
  if (!inserted) {
    SendRequestErrorOnControlStream(
        message.request_id, RequestErrorCode::kDuplicateSubscription,
        std::nullopt, "Duplicate PUBLISH_NAMESPACE");
    return absl::OkStatus();
  }
  quiche::QuicheWeakPtr<MoqtSessionInterface> session_weakptr = GetWeakPtr();
  incoming_publish_namespaces_by_id_[message.request_id] =
      message.track_namespace;
  callbacks_.incoming_publish_namespace_callback(
      message.track_namespace, message.parameters,
      [&](std::variant<MessageParameters, MoqtRequestErrorInfo> response) {
        MoqtSession* session =
            absl::down_cast<MoqtSession*>(session_weakptr.GetIfAvailable());
        if (session == nullptr) {
          return;
        }
        std::visit(
            absl::Overload{
                [this, request_id = message.request_id](
                    const MessageParameters& parameters) {
                  // In draft-18, there are no useful parameters in
                  // PUBLISH_NAMESPACE_OK, but Issue #1639 would change that.
                  SendControlMessage(framer_.SerializeRequestOk(MoqtRequestOk{
                      .request_id = request_id, .parameters = parameters}));
                },
                [this, id = message.request_id,
                 track_ns = message.track_namespace](
                    const MoqtRequestErrorInfo& error_info) {
                  SendRequestErrorOnControlStream(id, error_info.error_code,
                                                  error_info.retry_interval,
                                                  error_info.reason_phrase);
                  incoming_publish_namespaces_by_id_.erase(id);
                  incoming_publish_namespaces_by_namespace_.erase(track_ns);
                }},
            response);
      });
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(
    const MoqtPublishNamespaceDone& message) {
  auto it = incoming_publish_namespaces_by_id_.find(message.request_id);
  if (it == incoming_publish_namespaces_by_id_.end()) {
    return absl::OkStatus();
  }
  callbacks_.incoming_publish_namespace_callback(it->second, std::nullopt,
                                                 nullptr);
  incoming_publish_namespaces_by_namespace_.erase(it->second);
  incoming_publish_namespaces_by_id_.erase(it);
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(
    const MoqtPublishNamespaceCancel& message) {
  auto it = publish_namespace_by_id_.find(message.request_id);
  if (it == publish_namespace_by_id_.end()) {
    return absl::OkStatus();  // State might have been destroyed due to
                              // PUBLISH_NAMESPACE_DONE.
  }
  std::move(it->second.cancel_callback)(MoqtRequestErrorInfo{
      message.error_code, std::nullopt, std::string(message.error_reason)});
  publish_namespace_by_namespace_.erase(it->second.track_namespace);
  publish_namespace_by_id_.erase(it);
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtTrackStatus& message) {
  if (!ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  if (sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Received a TRACK_STATUS_REQUEST after GOAWAY";
    SendRequestErrorOnControlStream(
        message.request_id, RequestErrorCode::kUnauthorized, std::nullopt,
        "TRACK_STATUS_REQUEST after GOAWAY");
    return absl::OkStatus();
  }
  // TODO(martinduke): Handle authentication.
  std::shared_ptr<MoqtTrackPublisher> track =
      publisher_->GetTrack(message.full_track_name);
  if (track == nullptr) {
    SendRequestErrorOnControlStream(message.request_id,
                                    RequestErrorCode::kDoesNotExist,
                                    std::nullopt, "Track does not exist");
    return absl::OkStatus();
  }
  auto [it, inserted] = incoming_track_status_.emplace(
      message.request_id, std::make_unique<DownstreamTrackStatus>(
                              message.request_id, this, track.get()));
  track->AddObjectListener(it->second.get());
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtGoAway& message) {
  if (!message.new_session_uri.empty() &&
      perspective() == quic::Perspective::IS_SERVER) {
    return absl::InvalidArgumentError(
        "Received GOAWAY with new_session_uri on the server");
  }
  if (received_goaway_) {
    return absl::InvalidArgumentError("Received multiple GOAWAY messages");
  }
  received_goaway_ = true;
  if (callbacks_.goaway_received_callback != nullptr) {
    std::move(callbacks_.goaway_received_callback)(message.new_session_uri);
  }
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtMaxRequestId& message) {
  if (message.max_request_id < peer_max_request_id_) {
    QUIC_DLOG(INFO) << ENDPOINT
                    << "Peer sent MAX_REQUEST_ID message with "
                       "lower value than previous";
    return absl::InvalidArgumentError(
        "MAX_REQUEST_ID has lower value than previous");
  }
  peer_max_request_id_ = message.max_request_id;
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtFetch& message) {
  if (!ValidateRequestId(message.request_id)) {
    return absl::OkStatus();
  }
  if (sent_goaway_) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received a FETCH after GOAWAY";
    SendRequestErrorOnControlStream(message.request_id,
                                    RequestErrorCode::kUnauthorized,
                                    std::nullopt, "FETCH after GOAWAY");
    return absl::OkStatus();
  }
  std::unique_ptr<MoqtFetchTask> fetch;
  FullTrackName track_name;
  if (std::holds_alternative<StandaloneFetch>(message.fetch)) {
    const StandaloneFetch& standalone_fetch =
        std::get<StandaloneFetch>(message.fetch);
    track_name = standalone_fetch.full_track_name;
    std::shared_ptr<MoqtTrackPublisher> track_publisher =
        publisher_->GetTrack(track_name);
    if (track_publisher == nullptr) {
      QUIC_DLOG(INFO) << ENDPOINT << "FETCH for " << track_name
                      << " rejected by the application: not found";
      SendRequestErrorOnControlStream(message.request_id,
                                      RequestErrorCode::kDoesNotExist,
                                      std::nullopt, "not found");
      return absl::OkStatus();
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
    auto it = published_subscriptions_.find(joining_request_id);
    if (it == published_subscriptions_.end()) {
      QUIC_DLOG(INFO) << ENDPOINT << "Received a JOINING_FETCH for "
                      << "request_id " << joining_request_id
                      << " that does not exist";
      SendRequestErrorOnControlStream(
          message.request_id, RequestErrorCode::kInvalidJoiningRequestId,
          std::nullopt, "Joining Fetch for non-existent request");
      return absl::OkStatus();
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
        SendRequestErrorOnControlStream(message.request_id,
                                        RequestErrorCode::kDoesNotExist,
                                        std::nullopt, "not found");
        return absl::OkStatus();
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
          SendRequestErrorOnControlStream(message.request_id,
                                          RequestErrorCode::kInvalidRange,
                                          std::nullopt, "invalid range");
          return absl::OkStatus();
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
    SendRequestErrorOnControlStream(message.request_id,
                                    RequestErrorCode::kInvalidRange,
                                    std::nullopt, fetch->GetStatus().message());
    return absl::OkStatus();
  }
  auto published_fetch =
      std::make_unique<PublishedFetch>(message.request_id, std::move(fetch));
  auto result =
      incoming_fetches_.emplace(message.request_id, std::move(published_fetch));
  if (!result.second) {  // Emplace failed.
    QUIC_DLOG(INFO) << ENDPOINT << "FETCH for " << track_name
                    << " could not be added to the session";
    SendRequestErrorOnControlStream(
        message.request_id, RequestErrorCode::kInternalError, std::nullopt,
        "Could not initialize FETCH state");
    return absl::OkStatus();
  }
  MoqtFetchTask* fetch_task = result.first->second->fetch_task_ptr();
  fetch_task->SetFetchResponseCallback(
      [this, request_id = message.request_id](
          std::variant<MoqtFetchOk, MoqtRequestError> message) {
        if (!incoming_fetches_.contains(request_id)) {
          return;  // FETCH was cancelled.
        }
        if (std::holds_alternative<MoqtFetchOk>(message)) {
          MoqtFetchOk& fetch_ok = std::get<MoqtFetchOk>(message);
          fetch_ok.request_id = request_id;
          SendControlMessage(framer_.SerializeFetchOk(fetch_ok));
          return;
        }
        SendRequestErrorOnControlStream(
            request_id, std::get<MoqtRequestError>(message).error_code,
            std::get<MoqtRequestError>(message).retry_interval,
            std::get<MoqtRequestError>(message).reason_phrase);
      });
  // Set a temporary new-object callback that creates a data stream. When
  // created, the stream visitor will replace this callback.
  fetch_task->SetObjectAvailableCallback(
      [this,
       subscriber_priority = message.parameters.subscriber_priority.value_or(
           kDefaultSubscriberPriority),
       request_id = message.request_id]() {
        auto it = incoming_fetches_.find(request_id);
        if (it == incoming_fetches_.end()) {
          return;
        }
        if (!session()->CanOpenNextOutgoingUnidirectionalStream() ||
            !OpenDataStream(it->second.get(),
                            SendOrderForFetch(subscriber_priority))) {
          UpdateTrackPriority(request_id, std::nullopt,
                              MoqtTrackPriority(subscriber_priority,
                                                kDefaultPublisherPriority));
        }
      });
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtFetchOk& message) {
  UpstreamFetch* track = FetchById(message.request_id);
  if (track == nullptr) {
    QUIC_DLOG(INFO) << ENDPOINT << "Received the FETCH_OK for "
                    << "request_id = " << message.request_id
                    << " but no track exists";
    // Subscription state might have been destroyed for internal reasons.
    return absl::OkStatus();
  }
  QUIC_DLOG(INFO) << ENDPOINT << "Received the FETCH_OK for request_id = "
                  << message.request_id << " " << track->full_track_name();
  UpstreamFetch* fetch = absl::down_cast<UpstreamFetch*>(track);
  fetch->OnFetchResult(message.end_location, absl::OkStatus(),
                       [=, this]() { CancelFetch(message.request_id); });
  return absl::OkStatus();
}

absl::Status MoqtSession::OnControlMessage(const MoqtRequestsBlocked& message) {
  // TODO(martinduke): Derive logic for granting more subscribes.
  return absl::OkStatus();
}

void MoqtSession::OnMalformedTrack(ObjectSubscriber* track) {
  if (!track->is_fetch()) {
    auto* subscribe = absl::down_cast<LiveSubscriber*>(track);
    if (subscribe->visitor() != nullptr) {
      subscribe->visitor()->OnMalformedTrack(track->full_track_name());
    }
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
  for (auto& it : incoming_publish_namespaces_by_namespace_) {
    callbacks_.incoming_publish_namespace_callback(it.first, std::nullopt,
                                                   nullptr);
  }
  for (auto& it : publish_namespace_by_id_) {
    std::move(it.second.cancel_callback)(MoqtRequestErrorInfo{
        RequestErrorCode::kUninterested, std::nullopt, "Session closed"});
  }
  while (!fetch_by_id_.empty()) {
    fetch_by_id_.begin()->second->Destroy();
  }
  for (auto& [track_name, subscriber] : subscribe_by_name_) {
    // It's possible the application is going to destroy its visitor as early
    // as session_deleted_callback is called. So call OnPublishDone() now and
    // clear the visitor.
    if (subscriber->visitor() != nullptr) {
      subscriber->visitor()->OnPublishDone(subscriber->full_track_name());
      subscriber->ReleaseVisitor();
    }
  }
}

void MoqtSession::CancelFetch(uint64_t request_id) {
  if (is_closing_) {
    return;
  }
  auto it = fetch_by_id_.find(request_id);
  if (it == fetch_by_id_.end()) {
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
