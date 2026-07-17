// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_subscribe_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <variant>

#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_subscription.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

MoqtSubscribeRequestStream::MoqtSubscribeRequestStream(
    MoqtFramer* absl_nonnull framer,
    const MoqtControlMessageParser& message_parser, uint64_t request_id,
    SessionErrorCallback session_error_callback, const FullTrackName& name,
    SubscribeVisitor* absl_nonnull visitor, const MessageParameters& parameters,
    SubscribeRemoteTrack::AddCallback add_callback,
    SubscribeRemoteTrack::RemoveCallback remove_callback,
    const quic::QuicClock* absl_nonnull clock,
    quic::QuicAlarmFactory* absl_nonnull alarm_factory)
    : MoqtBidiStreamBase(framer, message_parser,
                         std::move(session_error_callback)),
      track_(std::make_unique<SubscribeRemoteTrack>(
          MoqtSubscribe{request_id, name, parameters}, visitor, this)),
      add_callback_(std::move(add_callback)),
      remove_callback_(std::move(remove_callback)),
      clock_(clock),
      alarm_factory_(alarm_factory) {}

void MoqtSubscribeRequestStream::OnStreamBound() {
  stream_parser()->set_allow_fin(true);
  SendOrBufferMessageOrFatal(framer()->SerializeSubscribe(
      MoqtSubscribe{track_->request_id(), track_->full_track_name(),
                    track_->const_parameters()}));
}

absl::Status MoqtSubscribeRequestStream::OnRawControlMessage(
    const MoqtRawControlMessage& message) {
  return ControlMessageDispatcher::DispatchControlMessage(
      *this, message_parser(), message, "subscribe request");
}

absl::Status MoqtSubscribeRequestStream::OnControlMessage(
    const MoqtSubscribeOk& message) {
  if (message.request_id != track_->request_id()) {
    return absl::InvalidArgumentError("SUBSCRIBE_OK request ID mismatch");
  }
  if (add_callback_ == nullptr) {
    return absl::InvalidArgumentError(
        "Multiple SUBSCRIBE_OK on the same stream");
  }
  track_->set_track_alias(message.track_alias);
  if (!std::move(add_callback_)(track_.get())) {
    add_callback_ = nullptr;
    OnFatalError(absl::AlreadyExistsError("Track alias already exists"));
    return absl::OkStatus();
  }
  add_callback_ = nullptr;

  track_->OnObjectOrOk(SubscribeOkData(message.parameters, message.extensions));
  return absl::OkStatus();
}

absl::Status MoqtSubscribeRequestStream::OnControlMessage(
    const MoqtRequestOk& message) {
  if (!track_->track_alias().has_value()) {
    // Not yet established.
    OnFatalError(
        absl::InvalidArgumentError("REQUEST_OK received before SUBSCRIBE_OK"));
    return absl::OkStatus();
  }
  auto status_or_params = PopParameters();
  if (status_or_params.ok()) {
    MessageParameters parameters = status_or_params.value();
    // EXPIRES or LARGEST_OBJECT could be present in REQUEST_OK.
    if (message.parameters.largest_object.has_value()) {
      parameters.largest_object = message.parameters.largest_object;
    }
    if (message.parameters.expires.has_value()) {
      parameters.expires = message.parameters.expires;
    }
    track_->Update(parameters);
  }
  return MoqtBidiStreamBase::OnControlMessage(message);
}

absl::Status MoqtSubscribeRequestStream::OnControlMessage(
    const MoqtRequestError& message) {
  MoqtRequestErrorInfo error_info{message.error_code, message.retry_interval,
                                  message.reason_phrase};
  if (track_->ErrorIsAllowed()) {
    if (track_->visitor() != nullptr) {
      track_->visitor()->OnReply(track_->full_track_name(), error_info);
    }
    Fin();
    return absl::OkStatus();
  }
  // In response to REQUEST_UPDATE, utilize the ResponseCallback and do not
  // update parameters.
  return MoqtBidiStreamBase::OnControlMessage(message);
}

absl::Status MoqtSubscribeRequestStream::OnControlMessage(
    const MoqtPublishDone& message) {
  if (track_ == nullptr) {
    // PUBLISH_DONE can be sent before the subscriber rejects the track.
    return absl::OkStatus();
  }
  track_->OnPublishDone(message.stream_count, clock_, alarm_factory_);
  return absl::OkStatus();
}

void MoqtSubscribeRequestStream::Detach() {
  if (remove_callback_ != nullptr) {
    SubscribeRemoteTrack::RemoveCallback remove_callback =
        std::move(remove_callback_);
    remove_callback_ = nullptr;
    std::move(remove_callback)(track_.get());
  }
  track_ = nullptr;
}

MoqtSubscribeResponseStream::MoqtSubscribeResponseStream(
    MoqtFramer* absl_nonnull framer,
    const MoqtControlMessageParser& message_parser, uint64_t track_alias,
    SubscriptionPublisher::AddCallback add_callback,
    SubscriptionPublisher::RemoveCallback remove_callback,
    SessionErrorCallback session_error_callback,
    quiche::QuicheWeakPtr<SessionToPublisherInterface> session)
    : MoqtBidiStreamBase(framer, message_parser,
                         std::move(session_error_callback)),
      track_alias_(track_alias),
      add_callback_(std::move(add_callback)),
      remove_callback_(std::move(remove_callback)),
      session_(std::move(session)) {}

absl::Status MoqtSubscribeResponseStream::OnRawControlMessage(
    const MoqtRawControlMessage& message) {
  return ControlMessageDispatcher::DispatchControlMessage(
      *this, message_parser(), message, "subscribe response");
}

absl::Status MoqtSubscribeResponseStream::OnControlMessage(
    const MoqtSubscribe& message) {
  if (subscription_ != nullptr) {
    return absl::InvalidArgumentError(
        "SUBSCRIBE received on stream that already has a subscription");
  }
  QUIC_DLOG(INFO) << "Received a SUBSCRIBE for " << message.full_track_name;
  if (session() == nullptr) {
    return absl::OkStatus();
  }
  std::shared_ptr<MoqtTrackPublisher> track_publisher =
      session()->GetTrackPublisher(message.full_track_name);
  if (track_publisher == nullptr) {
    QUIC_DLOG(INFO) << "SUBSCRIBE for " << message.full_track_name
                    << " rejected by the application: does not exist";
    return SendRequestError(message.request_id, RequestErrorCode::kDoesNotExist,
                            std::nullopt, "not found", /*fin=*/true);
  }
  subscription_ = std::make_unique<SubscriptionPublisher>(
      *framer(), track_publisher, this, message.request_id, track_alias_,
      message.parameters, session_, false);
  if (add_callback_ != nullptr) {
    bool result = std::move(add_callback_)(subscription_.get());
    add_callback_ = nullptr;
    if (!result) {
      return SendRequestError(message.request_id,
                              RequestErrorCode::kDuplicateSubscription,
                              std::nullopt, "duplicate subscription",
                              /*fin=*/true);
    }
  }
  // Don't add the publisher until we know it's successful.
  track_publisher->AddObjectListener(subscription_.get());
  return absl::OkStatus();
}

absl::Status MoqtSubscribeResponseStream::OnControlMessage(
    const MoqtRequestUpdate& message) {
  if (subscription_ == nullptr) {
    QUICHE_BUG(INFO) << "Received REQUEST_UPDATE, no subscription state";
    return SendRequestError(message.request_id,
                            RequestErrorCode::kInternalError, std::nullopt,
                            "no subscription", /*fin=*/true);
  }
  subscription_->Update(message.parameters);
  return SendRequestOk(message.request_id, MessageParameters());
}

void MoqtSubscribeResponseStream::Detach() {
  if (remove_callback_ != nullptr && subscription_ != nullptr) {
    SubscriptionPublisher::RemoveCallback remove_callback =
        std::move(remove_callback_);
    remove_callback_ = nullptr;
    std::move(remove_callback)(subscription_.get());
  }
  if (subscription_ != nullptr) {
    subscription_->ResetAllStreams();
    subscription_ = nullptr;
  }
}

}  // namespace moqt
