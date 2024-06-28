// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file

#include "quiche/quic/moqt/moqt_track.h"

#include <cstdint>

#include "quiche/quic/moqt/moqt_messages.h"

namespace moqt {

void LocalTrack::AddWindow(uint64_t subscribe_id, uint64_t start_group,
                           uint64_t start_object) {
  QUIC_BUG_IF(quic_bug_subscribe_to_canceled_track, announce_canceled_)
      << "Canceled track got subscription";
  windows_.AddWindow(subscribe_id, next_sequence_, start_group, start_object);
}

void LocalTrack::AddWindow(uint64_t subscribe_id, uint64_t start_group,
                           uint64_t start_object, uint64_t end_group) {
  QUIC_BUG_IF(quic_bug_subscribe_to_canceled_track, announce_canceled_)
      << "Canceled track got subscription";
  // The end object might be unknown.
  auto it = max_object_ids_.find(end_group);
  if (end_group >= next_sequence_.group) {
    // Group is not fully published yet, so end object is unknown.
    windows_.AddWindow(subscribe_id, next_sequence_, start_group, start_object,
                       end_group, UINT64_MAX);
    return;
  }
  windows_.AddWindow(subscribe_id, next_sequence_, start_group, start_object,
                     end_group, it->second);
}

void LocalTrack::AddWindow(uint64_t subscribe_id, uint64_t start_group,
                           uint64_t start_object, uint64_t end_group,
                           uint64_t end_object) {
  QUIC_BUG_IF(quic_bug_subscribe_to_canceled_track, announce_canceled_)
      << "Canceled track got subscription";
  windows_.AddWindow(subscribe_id, next_sequence_, start_group, start_object,
                     end_group, end_object);
}

void LocalTrack::SentSequence(FullSequence sequence, MoqtObjectStatus status) {
  QUICHE_DCHECK(max_object_ids_.find(sequence.group) == max_object_ids_.end() ||
                max_object_ids_[sequence.group] < sequence.object);
  switch (status) {
    case MoqtObjectStatus::kNormal:
    case MoqtObjectStatus::kObjectDoesNotExist:
      if (next_sequence_ <= sequence) {
        next_sequence_ = sequence.next();
      }
      break;
    case MoqtObjectStatus::kGroupDoesNotExist:
      max_object_ids_[sequence.group] = 0;
      break;
    case MoqtObjectStatus::kEndOfGroup:
      max_object_ids_[sequence.group] = sequence.object;
      if (next_sequence_ <= sequence) {
        next_sequence_ = FullSequence(sequence.group + 1, 0);
      }
      break;
    case MoqtObjectStatus::kEndOfTrack:
      max_object_ids_[sequence.group] = sequence.object;
      break;
    default:
      QUICHE_DCHECK(false);
      return;
  }
}

bool RemoteTrack::CheckForwardingPreference(
    MoqtForwardingPreference preference) {
  if (forwarding_preference_.has_value()) {
    return forwarding_preference_.value() == preference;
  }
  forwarding_preference_ = preference;
  return true;
}

}  // namespace moqt
