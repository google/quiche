// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_relay_publisher.h"

#include <memory>

#include "absl/base/nullability.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_relay_track_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

using quiche::QuicheWeakPtr;

absl_nullable std::shared_ptr<MoqtTrackPublisher> MoqtRelayPublisher::GetTrack(
    const FullTrackName& track_name) {
  auto it = tracks_.find(track_name);
  if (it == tracks_.end()) {
    return nullptr;
  }
  return it->second;
}

void MoqtRelayPublisher::SetDefaultUpstreamSession(
    MoqtSessionInterface* default_upstream_session) {
  MoqtSessionInterface* old_session =
      default_upstream_session_.GetIfAvailable();
  if (old_session != nullptr) {
    // The Publisher no longer cares if the old session is terminated.
    old_session->callbacks().session_terminated_callback =
        [](absl::string_view) {};
  }
  // Update callbacks.
  // goaway_received_callback has already been set by MoqtClient. It will
  // handle connecting to new URI and calling AddDefaultUpstreamSession() again
  // when that session is ready.
  default_upstream_session->callbacks().session_terminated_callback =
      [this](absl::string_view error_message) {
        QUICHE_LOG(INFO) << "Default upstream session terminated, error = "
                         << error_message;
        default_upstream_session_ = QuicheWeakPtr<MoqtSessionInterface>();
      };
  AddNamespaceCallbacks(default_upstream_session);
  default_upstream_session_ = default_upstream_session->GetWeakPtr();
}

void MoqtRelayPublisher::AddNamespaceCallbacks(
    MoqtSessionInterface* /*session*/) {
  // TODO(martinduke): Implement this.
}

void MoqtRelayPublisher::AddTrack(
    std::shared_ptr<MoqtRelayTrackPublisher> track_publisher) {
  const FullTrackName& track_name = track_publisher->GetTrackName();
  auto [it, success] = tracks_.emplace(track_name, track_publisher);
  QUICHE_BUG_IF(MoqtRelayPublisher_duplicate, !success)
      << "Trying to add a duplicate track into a RelayPublisher";
}

void MoqtRelayPublisher::DeleteTrack(const FullTrackName& track_name) {
  tracks_.erase(track_name);
}

}  // namespace moqt
