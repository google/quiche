// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_PUBLISH_STREAM_H_
#define QUICHE_QUIC_MOQT_MOQT_PUBLISH_STREAM_H_

#include <cstdint>
#include <memory>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_subscription.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

class MoqtPublishPublisherStream : public MoqtBidiStreamBase {
 public:
  // Order of operations:
  // 1. Call this constructor
  // 2. Call SetPublisher()
  // 3. Call Webtransport::Stream::SetVisitor()
  // 4. Call this::BindStream()
  MoqtPublishPublisherStream(
      MoqtFramer* absl_nonnull framer,
      const MoqtControlMessageParser& message_parser,
      SubscriptionPublisher::RemoveCallback stream_deleted_callback,
      SessionErrorCallback session_error_callback,
      MoqtResponseCallback response_callback);
  ~MoqtPublishPublisherStream();

  // MoqtBidiStreamBase overrides.
  void OnStreamBound() override;
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override;
  absl::Status OnControlMessage(const MoqtRequestOk& message);
  absl::Status OnControlMessage(const MoqtRequestError& message);
  absl::Status OnControlMessage(const MoqtRequestUpdate& message);
  absl::Status OnControlMessage(const MoqtObjectAck& message) {
    publisher_->ProcessObjectAck(message);
    return absl::OkStatus();
  }

  void SetPublisher(std::unique_ptr<SubscriptionPublisher> publisher) {
    publisher_ = std::move(publisher);
  }

  void Detach() override {
    if (stream_deleted_callback_ == nullptr) {
      return;
    }
    SubscriptionPublisher::RemoveCallback callback =
        std::move(stream_deleted_callback_);
    stream_deleted_callback_ = nullptr;
    std::move(callback)(publisher_.get());
    publisher_->ResetAllStreams();
    publisher_ = nullptr;
  }

 private:
  MoqtResponseCallback response_callback_;
  std::unique_ptr<SubscriptionPublisher> publisher_;
  absl::flat_hash_map<uint64_t, MoqtResponseCallback> pending_updates_;
  SubscriptionPublisher::RemoveCallback stream_deleted_callback_;
};

class MoqtPublishSubscriberStream : public MoqtBidiStreamBase {
 public:
  MoqtPublishSubscriberStream(
      MoqtFramer* absl_nonnull framer,
      const MoqtControlMessageParser& message_parser,
      const quic::QuicClock* absl_nonnull clock,
      quic::QuicAlarmFactory* absl_nonnull alarm_factory,
      SessionErrorCallback session_error_callback,
      const MoqtIncomingPublishCallback* absl_nonnull incoming_publish_callback,
      SubscribeRemoteTrack::AddCallback add_callback,
      SubscribeRemoteTrack::RemoveCallback remove_callback);
  ~MoqtPublishSubscriberStream() { Detach(); }

  // MoqtBidiStreamBase overrides.
  void OnStreamBound() override {
    stream_parser()->set_allow_fin(true);
    // TODO(martinduke): Set the priority for this stream.
  }
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override;
  absl::Status OnControlMessage(const MoqtPublish& message);
  absl::Status OnControlMessage(const MoqtRequestUpdate& message);
  absl::Status OnControlMessage(const MoqtRequestOk& message);
  absl::Status OnControlMessage(const MoqtRequestError& message);
  absl::Status OnControlMessage(const MoqtPublishDone& message);

  SubscribeRemoteTrack* track() { return subscriber_.get(); }

  void Detach() override {
    if (remove_callback_ != nullptr) {
      SubscribeRemoteTrack::RemoveCallback callback =
          std::move(remove_callback_);
      remove_callback_ = nullptr;
      std::move(callback)(subscriber_.get());
    }
    subscriber_ = nullptr;
  }

 private:
  uint64_t request_id_;
  SubscribeVisitor* absl_nullable subscribe_visitor_ = nullptr;
  bool in_destructor_ = false;
  std::unique_ptr<SubscribeRemoteTrack> subscriber_;
  absl::flat_hash_map<uint64_t, MoqtResponseCallback> pending_updates_;
  const quic::QuicClock* clock_;
  quic::QuicAlarmFactory* alarm_factory_;
  const MoqtIncomingPublishCallback* incoming_publish_callback_;
  SubscribeRemoteTrack::AddCallback add_callback_;
  SubscribeRemoteTrack::RemoveCallback remove_callback_;
  quiche::QuicheWeakPtrFactory<MoqtPublishSubscriberStream> weak_ptr_factory_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_PUBLISH_STREAM_H_
