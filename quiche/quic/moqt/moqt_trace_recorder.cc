// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_trace_recorder.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "absl/hash/hash.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quic_trace/quic_trace.pb.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

using ::quic_trace::EventType;

void MoqtTraceRecorder::RecordControlStreamCreated(
    webtransport::StreamId stream_id) {
  if (parent_ == nullptr) {
    return;
  }
  quic_trace::StreamAnnotation* annotation =
      parent_->trace()->add_stream_annotations();
  annotation->set_stream_id(stream_id);
  annotation->set_moqt_control_stream(true);
}

void MoqtTraceRecorder::RecordSubgroupStreamCreated(
    webtransport::StreamId stream_id, uint64_t track_alias,
    DataStreamIndex index) {
  if (parent_ == nullptr) {
    return;
  }
  quic_trace::StreamAnnotation* annotation =
      parent_->trace()->add_stream_annotations();
  annotation->set_stream_id(stream_id);
  annotation->mutable_moqt_subgroup_stream()->set_track_alias(track_alias);
  annotation->mutable_moqt_subgroup_stream()->set_group_id(index.group);
  annotation->mutable_moqt_subgroup_stream()->set_subgroup_id(index.subgroup);
}

void MoqtTraceRecorder::RecordFetchStreamCreated(
    webtransport::StreamId stream_id) {
  if (parent_ == nullptr) {
    return;
  }
  quic_trace::StreamAnnotation* annotation =
      parent_->trace()->add_stream_annotations();
  annotation->set_stream_id(stream_id);
  annotation->mutable_moqt_fetch_stream();
}

void MoqtTraceRecorder::RecordProbeStreamCreated(
    webtransport::StreamId stream_id, uint64_t probe_id) {
  if (parent_ == nullptr) {
    return;
  }
  quic_trace::StreamAnnotation* annotation =
      parent_->trace()->add_stream_annotations();
  annotation->set_stream_id(stream_id);
  annotation->mutable_moqt_probe_stream()->set_probe_id(probe_id);
}

quic_trace::Event* MoqtTraceRecorder::AddEvent() {
  quic_trace::Event* event = parent_->trace()->add_events();
  event->set_time_us(parent_->NowInRecordedFormat());
  return event;
}

MoqtTraceRecorder::Track::Track(MoqtTraceRecorder* recorder,
                                std::shared_ptr<MoqtTrackPublisher> publisher,
                                uint64_t track_alias)
    : recorder_(recorder),
      publisher_(std::move(publisher)),
      track_alias_(track_alias) {
  publisher_->AddObjectListener(this);
}

MoqtTraceRecorder::Track::~Track() { publisher_->RemoveObjectListener(this); }

void MoqtTraceRecorder::Track::OnNewObjectAvailable(
    Location sequence, uint64_t subgroup, MoqtPriority publisher_priority) {
  if (recorder_->parent_ == nullptr) {
    return;
  }
  quic_trace::Event* event = recorder_->AddEvent();
  event->set_event_type(EventType::MOQT_OBJECT_ENQUEUED);
  recorder_->parent_->PopulateTransportState(event->mutable_transport_state());

  quic_trace::MoqtObject* object = event->mutable_moqt_object();
  object->set_track_alias(track_alias_);
  object->set_group_id(sequence.group);
  object->set_object_id(sequence.object);
  object->set_subgroup_id(subgroup);
  object->set_publisher_priority(publisher_priority);

  std::optional<PublishedObject> object_copy =
      publisher_->GetCachedObject(sequence.group, subgroup, sequence.object);
  if (object_copy.has_value() && object_copy->metadata.location == sequence) {
    object->set_payload_size(object_copy->payload.length());
  } else {
    QUICHE_DLOG(WARNING) << "Track " << track_alias_ << " has marked "
                         << sequence
                         << " as enqueued, but GetCachedObject was not able to "
                            "return the said object";
  }
}

size_t MoqtTraceRecorder::TrackAliasHash::operator()(
    uint64_t track_alias) const {
  return absl::HashOf(track_alias);
}

void MoqtTraceRecorder::StartRecordingTrack(
    uint64_t track_alias, std::shared_ptr<MoqtTrackPublisher> publisher) {
  if (parent_ == nullptr) {
    return;
  }
  auto [it, added] = tracks_.emplace(this, std::move(publisher), track_alias);
  QUICHE_DCHECK(added);
}

void MoqtTraceRecorder::StopRecordingTrack(uint64_t track_alias) {
  if (parent_ == nullptr) {
    return;
  }
  size_t erased = tracks_.erase(track_alias);
  QUICHE_DCHECK_EQ(erased, 1);
}

}  // namespace moqt
