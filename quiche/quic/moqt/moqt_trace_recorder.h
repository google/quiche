// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_TRACE_RECORDER_H_
#define QUICHE_QUIC_MOQT_MOQT_TRACE_RECORDER_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/base/nullability.h"
#include "absl/container/node_hash_set.h"
#include "quiche/quic/core/quic_trace_visitor.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quic_trace/quic_trace.pb.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

// Records MOQT-specific information into the provided QUIC trace proto.  The
// wrapped trace can be nullptr, in which case no recording takes place.
class MoqtTraceRecorder {
 public:
  MoqtTraceRecorder() : parent_(nullptr) {}
  explicit MoqtTraceRecorder(quic::QuicTraceVisitor* absl_nullable parent)
      : parent_(parent) {}

  MoqtTraceRecorder(const MoqtTraceRecorder&) = delete;
  MoqtTraceRecorder(MoqtTraceRecorder&&) = delete;
  MoqtTraceRecorder& operator=(const MoqtTraceRecorder&) = delete;
  MoqtTraceRecorder& operator=(MoqtTraceRecorder&&) = delete;

  void SetParentRecorder(quic::QuicTraceVisitor* absl_nullable parent) {
    parent_ = parent;
  }

  // Annotates the specified stream as the MOQT control stream.
  void RecordControlStreamCreated(webtransport::StreamId stream_id);

  // Annotates the specified stream as an MOQT subgroup data stream.
  void RecordSubgroupStreamCreated(webtransport::StreamId stream_id,
                                   uint64_t track_alias, DataStreamIndex index);

  // Annotates the specified stream as an MOQT fetch data stream.
  void RecordFetchStreamCreated(webtransport::StreamId stream_id);

  // Annotates the specified stream as an MOQT probe stream.
  void RecordProbeStreamCreated(webtransport::StreamId stream_id,
                                uint64_t probe_id);

  // Records the track-related events by registering the recorder as a listener
  // of `publisher`.
  void StartRecordingTrack(uint64_t track_alias,
                           std::shared_ptr<MoqtTrackPublisher> publisher);
  // Removes a previously added track.
  void StopRecordingTrack(uint64_t track_alias);

 private:
  // Visitor that records events for a specific published track.
  class Track : public MoqtObjectListener {
   public:
    Track(MoqtTraceRecorder* recorder,
          std::shared_ptr<MoqtTrackPublisher> publisher, uint64_t track_alias);
    ~Track();

    Track(const Track&) = delete;
    Track(Track&&) = delete;
    Track& operator=(const Track&) = delete;
    Track& operator=(Track&&) = delete;

    // MoqtObjectListener implementation.
    void OnSubscribeAccepted() override {}
    void OnSubscribeRejected(MoqtSubscribeErrorReason reason) override {}
    void OnNewObjectAvailable(Location sequence, uint64_t subgroup,
                              MoqtPriority publisher_priority) override;
    void OnNewFinAvailable(Location final_object_in_subgroup,
                           uint64_t subgroup_id) override {}
    void OnSubgroupAbandoned(
        uint64_t group, uint64_t subgroup,
        webtransport::StreamErrorCode error_code) override {}
    void OnGroupAbandoned(uint64_t group_id) override {}
    void OnTrackPublisherGone() override {}

    uint64_t track_alias() const { return track_alias_; }

   private:
    MoqtTraceRecorder* const recorder_;
    std::shared_ptr<MoqtTrackPublisher> const publisher_;
    const uint64_t track_alias_;
  };

  // Index Track objects by track_alias.
  struct TrackAliasEq {
    using is_transparent = void;
    bool operator()(const Track& a, const Track& b) const {
      return a.track_alias() == b.track_alias();
    }
    bool operator()(const Track& a, uint64_t b) const {
      return a.track_alias() == b;
    }
  };
  struct TrackAliasHash {
    using is_transparent = void;
    size_t operator()(uint64_t track_alias) const;
    size_t operator()(const Track& track) const {
      return (*this)(track.track_alias());
    }
  };

  // Adds a new event to the trace, and populates the timestamp.
  quic_trace::Event* AddEvent();

  quic::QuicTraceVisitor* absl_nullable parent_;
  absl::node_hash_set<Track, TrackAliasHash, TrackAliasEq> tracks_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_TRACE_RECORDER_H_
