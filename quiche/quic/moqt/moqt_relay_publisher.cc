// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_relay_publisher.h"

#include <memory>

#include "absl/base/nullability.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_relay_track_publisher.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"

namespace moqt {

absl_nullable std::shared_ptr<MoqtTrackPublisher> MoqtRelayPublisher::GetTrack(
    const FullTrackName& track_name) {
  auto it = tracks_.find(track_name);
  if (it == tracks_.end()) {
    return nullptr;
  }
  return it->second;
}

void MoqtRelayPublisher::Add(
    std::shared_ptr<MoqtRelayTrackPublisher> track_publisher) {
  const FullTrackName& track_name = track_publisher->GetTrackName();
  auto [it, success] = tracks_.emplace(track_name, track_publisher);
  QUICHE_BUG_IF(MoqtRelayPublisher_duplicate, !success)
      << "Trying to add a duplicate track into a RelayPublisher";
}

void MoqtRelayPublisher::Delete(const FullTrackName& track_name) {
  tracks_.erase(track_name);
}

}  // namespace moqt
