// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_NAMESPACE_PUBLISHER_MULTIMAP_H_
#define QUICHE_QUIC_MOQT_NAMESPACE_PUBLISHER_MULTIMAP_H_

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {

class NamespacePublisherMultimap {
 public:
  void AddPublisher(const TrackNamespace& track_namespace,
                    MoqtSessionInterface* session) {
    absl::flat_hash_map<MoqtSessionInterface*,
                        quiche::QuicheWeakPtr<MoqtSessionInterface>>&
        publisher_map = namespace_map_[track_namespace];
    publisher_map.emplace(session, session->GetWeakPtr());
  }

  void RemovePublisher(const TrackNamespace& track_namespace,
                       MoqtSessionInterface* session) {
    auto it = namespace_map_.find(track_namespace);
    if (it == namespace_map_.end()) {
      return;
    }
    it->second.erase(session);
    if (it->second.empty()) {  // Last publisher for this namespace is gone.
      namespace_map_.erase(it);
    }
  }

  // Requires a precise match for |track_namespace|.
  quiche::QuicheWeakPtr<MoqtSessionInterface> GetValidPublisher(
      const TrackNamespace& track_namespace) {
    auto it = namespace_map_.find(track_namespace);
    if (it == namespace_map_.end()) {
      return quiche::QuicheWeakPtr<MoqtSessionInterface>();
    }
    for (const auto& [session, publisher] : it->second) {
      if (publisher.IsValid()) {
        return publisher.GetIfAvailable()->GetWeakPtr();
      }
    }
    return quiche::QuicheWeakPtr<MoqtSessionInterface>();
  }

 private:
  absl::flat_hash_map<
      TrackNamespace,
      absl::flat_hash_map<MoqtSessionInterface*,
                          quiche::QuicheWeakPtr<MoqtSessionInterface>>>
      namespace_map_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_NAMESPACE_PUBLISHER_MULTIMAP_H_
