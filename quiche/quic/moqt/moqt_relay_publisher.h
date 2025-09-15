// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_RELAY_PUBLISHER_H_
#define QUICHE_QUIC_MOQT_MOQT_RELAY_PUBLISHER_H_

#include <memory>

#include "absl/base/nullability.h"
#include "absl/container/flat_hash_map.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_relay_track_publisher.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

// MoqtRelayPublisher is a publisher that connects sessions that request objects
// and namespaces with upstream sessions that can deliver those things.
class MoqtRelayPublisher : public MoqtPublisher {
 public:
  explicit MoqtRelayPublisher(bool broadcast_mode)
      : broadcast_mode_(broadcast_mode) {}
  MoqtRelayPublisher(const MoqtRelayPublisher&) = delete;
  MoqtRelayPublisher(MoqtRelayPublisher&&) = delete;
  MoqtRelayPublisher& operator=(const MoqtRelayPublisher&) = delete;
  MoqtRelayPublisher& operator=(MoqtRelayPublisher&&) = delete;

  // MoqtPublisher implementation.
  absl_nullable std::shared_ptr<MoqtTrackPublisher> GetTrack(
      const FullTrackName& track_name) override;
  // TODO(martinduke): Implement namespace support.
  void AddNamespaceListener(NamespaceListener* /*listener*/) override {}
  void RemoveNamespaceListener(NamespaceListener* /*listener*/) override {}

  // There is a new default upstream session. When there is no other namespace
  // information, requests will route here.
  void SetDefaultUpstreamSession(
      MoqtSessionInterface* default_upstream_session);
  // There is a new incoming session. MoqtRelayPublisher will set the callbacks
  // for this session, but need not keep any state at this time.
  virtual void AddNamespaceCallbacks(MoqtSessionInterface* session);

  // Returns the default upstream session.
  quiche::QuicheWeakPtr<MoqtSessionInterface>& GetDefaultUpstreamSession() {
    return default_upstream_session_;
  }

 private:
  quiche::QuicheWeakPtr<MoqtSessionInterface> GetUpstream(
      const TrackNamespace& track_namespace);

  absl::flat_hash_map<FullTrackName, std::shared_ptr<MoqtRelayTrackPublisher>>
      tracks_;
  // TODO(martinduke): Add a map of Namespaces to source sessions and
  // namespace listeners.

  quiche::QuicheWeakPtr<MoqtSessionInterface> default_upstream_session_;
  // If true, PUBLISH_NAMESPACE messages will be forwarded to all sessions,
  // whether or not they are subscribed.
  bool broadcast_mode_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_RELAY_PUBLISHER_H_
