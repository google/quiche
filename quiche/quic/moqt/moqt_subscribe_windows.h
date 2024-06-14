// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_SUBSCRIBE_WINDOWS_H
#define QUICHE_QUIC_MOQT_SUBSCRIBE_WINDOWS_H

#include <cstdint>
#include <optional>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/container/node_hash_map.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

// Classes to track subscriptions to local tracks: the sequence numbers
// subscribed, the streams involved, and the subscribe IDs.
class QUICHE_EXPORT SubscribeWindow {
 public:
  // Creates a half-open window. |next_object| is the expected sequence number
  // of the next published object on the track.
  SubscribeWindow(uint64_t subscribe_id,
                  MoqtForwardingPreference forwarding_preference,
                  FullSequence next_object, uint64_t start_group,
                  uint64_t start_object)
      : SubscribeWindow(subscribe_id, forwarding_preference, next_object,
                        FullSequence(start_group, start_object), std::nullopt) {
  }

  // Creates a closed window.
  SubscribeWindow(uint64_t subscribe_id,
                  MoqtForwardingPreference forwarding_preference,
                  FullSequence next_object, uint64_t start_group,
                  uint64_t start_object, uint64_t end_group,
                  uint64_t end_object)
      : SubscribeWindow(subscribe_id, forwarding_preference, next_object,
                        FullSequence(start_group, start_object),
                        FullSequence(end_group, end_object)) {}

  SubscribeWindow(uint64_t subscribe_id,
                  MoqtForwardingPreference forwarding_preference,
                  FullSequence next_object, FullSequence start,
                  std::optional<FullSequence> end)
      : subscribe_id_(subscribe_id),
        start_(start),
        end_(end),
        original_next_object_(next_object),
        forwarding_preference_(forwarding_preference) {
    next_to_backfill_ =
        (start < next_object) ? start : std::optional<FullSequence>();
  }

  uint64_t subscribe_id() const { return subscribe_id_; }

  bool InWindow(const FullSequence& seq) const;

  // Returns the stream to send |sequence| on, if already opened.
  std::optional<webtransport::StreamId> GetStreamForSequence(
      FullSequence sequence) const;

  // Records what stream is being used for a track, group, or object depending
  // on |forwarding_preference|. Triggers QUIC_BUG if already assigned.
  void AddStream(uint64_t group_id, uint64_t object_id,
                 webtransport::StreamId stream_id);

  void RemoveStream(uint64_t group_id, uint64_t object_id);

  bool HasEnd() const { return end_.has_value(); }
  MoqtForwardingPreference forwarding_preference() const {
    return forwarding_preference_;
  }

  // Returns true if the object delivery completed the subscription
  bool OnObjectSent(FullSequence sequence);

  std::optional<FullSequence>& largest_delivered() {
    return largest_delivered_;
  }

  // Returns true if the updated values are valid.
  bool UpdateStartEnd(FullSequence start, std::optional<FullSequence> end);

 private:
  // Converts an object sequence number into one that matches the way that
  // stream IDs are being mapped. (See the comment for send_streams_ below.)
  FullSequence SequenceToIndex(FullSequence sequence) const;

  const uint64_t subscribe_id_;
  FullSequence start_;
  std::optional<FullSequence> end_;
  std::optional<FullSequence> largest_delivered_;
  // The next sequence number to be redelivered, because it was published prior
  // to the subscription. Is nullopt if no redeliveries are needed.
  std::optional<FullSequence> next_to_backfill_;
  // The first unpublished sequence number when the subscribe arrived.
  const FullSequence original_next_object_;
  // Store open streams for this subscription. If the forwarding preference is
  // kTrack, there is one entry under sequence (0, 0). If kGroup, each entry is
  // under (group, 0). If kObject, it's tracked under the full sequence. If
  // kDatagram, the map is empty.
  absl::flat_hash_map<FullSequence, webtransport::StreamId> send_streams_;
  // The forwarding preference for this track; informs how the streams are
  // mapped.
  const MoqtForwardingPreference forwarding_preference_;
};

// Class to keep track of the sequence number blocks to which a peer is
// subscribed.
class QUICHE_EXPORT MoqtSubscribeWindows {
 public:
  MoqtSubscribeWindows(MoqtForwardingPreference forwarding_preference)
      : forwarding_preference_(forwarding_preference) {}

  // Returns a vector of subscribe IDs that apply to the object. They will be in
  // reverse order of the AddWindow calls.
  std::vector<SubscribeWindow*> SequenceIsSubscribed(FullSequence sequence);

  // |start_group| and |start_object| must be absolute sequence numbers. An
  // optimization could consolidate overlapping subscribe windows.
  void AddWindow(uint64_t subscribe_id, FullSequence next_object,
                 uint64_t start_group, uint64_t start_object) {
    windows_.emplace(subscribe_id,
                     SubscribeWindow(subscribe_id, forwarding_preference_,
                                     next_object, start_group, start_object));
  }
  void AddWindow(uint64_t subscribe_id, FullSequence next_object,
                 uint64_t start_group, uint64_t start_object,
                 uint64_t end_group, uint64_t end_object) {
    windows_.emplace(
        subscribe_id,
        SubscribeWindow(subscribe_id, forwarding_preference_, next_object,
                        start_group, start_object, end_group, end_object));
  }
  void RemoveWindow(uint64_t subscribe_id) { windows_.erase(subscribe_id); }

  bool IsEmpty() const { return windows_.empty(); }

  SubscribeWindow* GetWindow(uint64_t subscribe_id) {
    auto it = windows_.find(subscribe_id);
    if (it == windows_.end()) {
      return nullptr;
    }
    return &it->second;
  }

 private:
  // Indexed by Subscribe ID.
  absl::node_hash_map<uint64_t, SubscribeWindow> windows_;
  const MoqtForwardingPreference forwarding_preference_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_SUBSCRIBE_WINDOWS_H
