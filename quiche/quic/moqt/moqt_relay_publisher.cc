// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_relay_publisher.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_relay_track_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

using quiche::QuicheWeakPtr;

absl_nullable std::shared_ptr<MoqtTrackPublisher> MoqtRelayPublisher::GetTrack(
    const FullTrackName& track_name) {
  auto it = tracks_.find(track_name);
  if (it != tracks_.end()) {
    return it->second;
  }
  QuicheWeakPtr<MoqtSessionInterface> upstream =
      GetUpstream(track_name.track_namespace());
  if (!upstream.IsValid()) {
    return nullptr;
  }
  auto track_publisher = std::make_shared<MoqtRelayTrackPublisher>(
      track_name, std::move(upstream),
      [this, track_name] { tracks_.erase(track_name); }, std::nullopt,
      std::nullopt);
  tracks_[track_name] = track_publisher;
  return track_publisher;
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

QuicheWeakPtr<MoqtSessionInterface> MoqtRelayPublisher::GetUpstream(
    const TrackNamespace& /*track_namespace*/) {
  // TODO(martinduke): Find a published namespace that contains
  // |track_namespace|.
  if (default_upstream_session_.IsValid()) {
    return default_upstream_session_.GetIfAvailable()->GetWeakPtr();
  }
  return QuicheWeakPtr<MoqtSessionInterface>();
}

}  // namespace moqt
