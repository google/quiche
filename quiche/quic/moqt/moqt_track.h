// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_SUBSCRIPTION_H_
#define QUICHE_QUIC_MOQT_MOQT_SUBSCRIPTION_H_

#include <cstdint>
#include <memory>
#include <optional>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_subscribe_windows.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

using MoqtObjectAckFunction =
    quiche::MultiUseCallback<void(uint64_t group_id, uint64_t object_id,
                                  quic::QuicTimeDelta delta_from_deadline)>;

// State common to both SUBSCRIBE and FETCH upstream.
class RemoteTrack {
 public:
  RemoteTrack(const FullTrackName& full_track_name, uint64_t id,
              SubscribeWindow window)
      : full_track_name_(full_track_name),
        subscribe_id_(id),
        window_(window),
        weak_ptr_factory_(this) {}
  virtual ~RemoteTrack() = default;

  FullTrackName full_track_name() const { return full_track_name_; }
  // If FETCH_ERROR or SUBSCRIBE_ERROR arrives after OK or an object, it is a
  // protocol violation.
  virtual void OnObjectOrOk() { error_is_allowed_ = false; }
  bool ErrorIsAllowed() const { return error_is_allowed_; }

  // When called while processing the first object in the track, sets the
  // data stream type to the value indicated by the incoming encoding.
  // Otherwise, returns true if the incoming object does not violate the rule
  // that the type is consistent.
  bool CheckDataStreamType(MoqtDataStreamType type);

  bool is_fetch() const {
    return data_stream_type_.has_value() &&
           *data_stream_type_ == MoqtDataStreamType::kStreamHeaderFetch;
  }

  uint64_t subscribe_id() const { return subscribe_id_; }

  // Is the object one that was requested?
  bool InWindow(FullSequence sequence) const {
    return window_.InWindow(sequence);
  }

  void ChangeWindow(SubscribeWindow& window) { window_ = window; }

  quiche::QuicheWeakPtr<RemoteTrack> weak_ptr() {
    return weak_ptr_factory_.Create();
  }

 private:
  const FullTrackName full_track_name_;
  const uint64_t subscribe_id_;
  SubscribeWindow window_;
  std::optional<MoqtDataStreamType> data_stream_type_;
  // If false, an object or OK message has been received, so any ERROR message
  // is a protocol violation.
  bool error_is_allowed_ = true;

  // Must be last.
  quiche::QuicheWeakPtrFactory<RemoteTrack> weak_ptr_factory_;
};

// A track on the peer to which the session has subscribed.
class SubscribeRemoteTrack : public RemoteTrack {
 public:
  // TODO: Separate this out (as it's used by the application) and give it a
  // name like MoqtTrackSubscriber,
  class Visitor {
   public:
    virtual ~Visitor() = default;
    // Called when the session receives a response to the SUBSCRIBE, unless it's
    // a SUBSCRIBE_ERROR with a new track_alias. In that case, the session will
    // automatically retry.
    virtual void OnReply(
        const FullTrackName& full_track_name,
        std::optional<FullSequence> largest_id,
        std::optional<absl::string_view> error_reason_phrase) = 0;
    // Called when the subscription process is far enough that it is possible to
    // send OBJECT_ACK messages; provides a callback to do so. The callback is
    // valid for as long as the session is valid.
    virtual void OnCanAckObjects(MoqtObjectAckFunction ack_function) = 0;
    // Called when an object fragment (or an entire object) is received.
    virtual void OnObjectFragment(
        const FullTrackName& full_track_name, FullSequence sequence,
        MoqtPriority publisher_priority, MoqtObjectStatus object_status,
        absl::string_view object, bool end_of_message) = 0;
    // TODO(martinduke): Add final sequence numbers
  };
  SubscribeRemoteTrack(const MoqtSubscribe& subscribe, Visitor* visitor)
      : RemoteTrack(subscribe.full_track_name, subscribe.subscribe_id,
                    SubscribeWindow(subscribe.start_group.value_or(0),
                                    subscribe.start_object.value_or(0),
                                    subscribe.end_group.value_or(UINT64_MAX),
                                    subscribe.end_object.value_or(UINT64_MAX))),
        track_alias_(subscribe.track_alias),
        visitor_(visitor),
        subscribe_(std::make_unique<MoqtSubscribe>(subscribe)) {}

  void OnObjectOrOk() override {
    subscribe_.reset();  // No SUBSCRIBE_ERROR, no need to store this anymore.
    RemoteTrack::OnObjectOrOk();
  }
  uint64_t track_alias() const { return track_alias_; }
  Visitor* visitor() { return visitor_; }
  MoqtSubscribe& GetSubscribe() {
    return *subscribe_;
    // This class will soon be destroyed, so there's no need to null the
    // unique_ptr;
  }

 private:
  const uint64_t track_alias_;
  Visitor* visitor_;
  // For convenience, store the subscribe message if it has to be re-sent with
  // a new track alias.
  std::unique_ptr<MoqtSubscribe> subscribe_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_SUBSCRIPTION_H_
