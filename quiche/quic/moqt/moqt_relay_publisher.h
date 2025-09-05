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

namespace moqt {

// MoqtRelayPublisher is a publisher that connects sessions that request objects
// and namespaces with upstream sessions that can deliver those things.
class MoqtRelayPublisher : public MoqtPublisher {
 public:
  MoqtRelayPublisher() = default;
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

  void Add(std::shared_ptr<MoqtRelayTrackPublisher> track_publisher);
  void Delete(const FullTrackName& track_name);

 private:
  absl::flat_hash_map<FullTrackName, std::shared_ptr<MoqtRelayTrackPublisher>>
      tracks_;
  // TODO(martinduke): Add a map of Namespaces to source sessions and
  // namespace listeners.
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_RELAY_PUBLISHER_H_
