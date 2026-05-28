// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file

#include "quiche/quic/moqt/moqt_track.h"

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace {

constexpr quic::QuicTimeDelta kMinPublishDoneTimeout =
    quic::QuicTimeDelta::FromSeconds(1);
constexpr quic::QuicTimeDelta kMaxPublishDoneTimeout =
    quic::QuicTimeDelta::FromSeconds(10);

}  // namespace

SubscribeRemoteTrack::~SubscribeRemoteTrack() {
  if (publish_done_alarm_ != nullptr) {
    publish_done_alarm_->PermanentCancel();
  }
  if (register_track_alias_callback_ && track_alias_.has_value()) {
    register_track_alias_callback_(*track_alias_, nullptr);
  }
  visitor_->OnPublishDone(full_track_name());
}

void SubscribeRemoteTrack::OnStreamOpened() {
  ++currently_open_streams_;
  if (publish_done_alarm_ != nullptr && publish_done_alarm_->IsSet()) {
    publish_done_alarm_->Cancel();
  }
}

void SubscribeRemoteTrack::OnStreamClosed(
    bool fin_received, std::optional<DataStreamIndex> index) {
  ++streams_closed_;
  --currently_open_streams_;
  QUICHE_DCHECK_GE(currently_open_streams_, -1);
  if (index.has_value()) {
    // If index is nullopt, there was not an object received on the stream.
    if (fin_received) {
      visitor_->OnStreamFin(full_track_name(), *index);
    } else {
      visitor_->OnStreamReset(full_track_name(), *index);
    }
  }
  if (all_streams_closed()) {
    Destroy();
    return;
  }
  if (publish_done_alarm_ == nullptr) {
    return;
  }
  MaybeSetPublishDoneAlarm();
}

void SubscribeRemoteTrack::OnPublishDone(
    uint64_t stream_count, const quic::QuicClock* clock,
    quic::QuicAlarmFactory* alarm_factory) {
  total_streams_ = stream_count;
  clock_ = clock;
  if (all_streams_closed()) {
    Destroy();
    return;
  }
  publish_done_alarm_ = std::unique_ptr<quic::QuicAlarm>(
      alarm_factory->CreateAlarm(new PublishDoneDelegate(this)));
  MaybeSetPublishDoneAlarm();
}

void SubscribeRemoteTrack::MaybeSetPublishDoneAlarm() {
  if (currently_open_streams_ == 0 && total_streams_.has_value() &&
      clock_ != nullptr) {
    quic::QuicTimeDelta timeout =
        std::min(parameters_.delivery_timeout.value_or(kDefaultDeliveryTimeout),
                 publisher_delivery_timeout_);
    timeout = std::min(timeout, kMaxPublishDoneTimeout);
    timeout = std::max(timeout, kMinPublishDoneTimeout);
    publish_done_alarm_->Set(clock_->ApproximateNow() + timeout);
  }
}

void SubscribeRemoteTrack::OnJoiningFetchReady(
    std::unique_ptr<MoqtFetchTask> fetch_task) {
  fetch_task_ = std::move(fetch_task);
  fetch_task_->SetObjectAvailableCallback([this]() { FetchObjects(); });
}

void SubscribeRemoteTrack::FetchObjects() {
  if (fetch_task_ == nullptr) {
    return;
  }
  if (visitor_ == nullptr || !fetch_task_->GetStatus().ok()) {
    fetch_task_.reset();
    return;
  }
  while (true) {
    PublishedObject object;
    switch (fetch_task_->GetNextObject(object)) {
      case MoqtFetchTask::GetNextObjectResult::kSuccess:
        if (object.metadata.payload_length == 0) {
          QUICHE_DCHECK_EQ(fetch_object_offset_, 0);
          visitor_->OnObjectFragment(full_track_name(), object.metadata, "", 0);
          break;
        }
        for (size_t i = 0; i < object.payload.size(); ++i) {
          if (fetch_object_offset_ > 0 && object.payload[i].empty()) {
            QUICHE_BUG(SubscribeRemoteTrack_empty_payload)
                << "Empty payload for partial object "
                << object.metadata.location;
            continue;
          }
          visitor_->OnObjectFragment(full_track_name(), object.metadata,
                                     object.payload[i].AsStringView(),
                                     fetch_object_offset_);
          fetch_object_offset_ += object.payload[i].length();
          if (fetch_object_offset_ == object.metadata.payload_length) {
            fetch_object_offset_ = 0;
            break;
          }
        }
        break;
      case MoqtFetchTask::GetNextObjectResult::kError:
      case MoqtFetchTask::GetNextObjectResult::kEof:
        fetch_task_.reset();
        return;
      case MoqtFetchTask::GetNextObjectResult::kPending:
        return;
    }
  }
}

UpstreamFetch::~UpstreamFetch() {
  UpstreamFetchTask* task = task_.GetIfAvailable();
  if (task != nullptr) {
    // Notify the task (which the application owns) that nothing more is coming.
    // If this has already been called, UpstreamFetchTask will ignore it.
    task->OnStreamAndFetchClosed(kResetCodeCancelled, "");
  }
}

void UpstreamFetch::OnFetchResult(Location largest_location,
                                  absl::Status status,
                                  TaskDestroyedCallback callback) {
  if (!status.ok()) {
    std::move(ok_callback_)(std::make_unique<MoqtFailedFetch>(status));
    // This is called from OnRequestError, which will delete UpstreamFetch. So
    // there is no need to call |callback|, which would inappropriately send a
    // FETCH_CANCEL.
    return;
  }
  auto task = std::make_unique<UpstreamFetchTask>(largest_location, status,
                                                  std::move(callback));
  task_ = task->weak_ptr();
  if (relative_groups_.has_value() &&
      (*relative_groups_ < largest_location.group)) {
    start_ = Location(largest_location.group - *relative_groups_, 0);
    relative_groups_.reset();
  }
  end_ = std::min(end_, largest_location);
  std::move(ok_callback_)(std::move(task));
  if (can_read_callback_) {
    task_.GetIfAvailable()->set_can_read_callback(
        std::move(can_read_callback_));
  }
}

void UpstreamFetch::OnStreamOpened(CanReadCallback can_read_callback) {
  if (task_.IsValid()) {
    task_.GetIfAvailable()->set_can_read_callback(std::move(can_read_callback));
  } else {
    can_read_callback_ = std::move(can_read_callback);
  }
}

bool UpstreamFetch::LocationIsValid(Location location, MoqtObjectStatus status,
                                    bool end_of_message) {
  if (end_of_track_.has_value()) {
    // Cannot exceed or change end_of_track_.
    if (location > end_of_track_) {
      return false;
    }
    if (status == MoqtObjectStatus::kEndOfTrack && location != *end_of_track_) {
      return false;
    }
  }
  if (end_of_message && status == MoqtObjectStatus::kEndOfTrack) {
    if (highest_location_.has_value() && location < *highest_location_) {
      return false;
    }
    end_of_track_ = location;
  }
  bool last_group_is_finished = last_group_is_finished_;
  last_group_is_finished_ =
      status == MoqtObjectStatus::kEndOfGroup && end_of_message;
  std::optional<Location> last_location = last_location_;
  if (end_of_message) {
    last_location_ = location;
    if (!highest_location_.has_value()) {
      highest_location_ = location;
    } else {
      highest_location_ = std::max(*highest_location_, location);
    }
  }
  if (!last_location.has_value()) {
    return true;
  }
  if (last_location->group == location.group) {
    return (!last_group_is_finished && location.object > last_location->object);
  }
  // Group ID has changed.
  return ((location.group > last_location->group) ==
          (group_order_ == MoqtDeliveryOrder::kAscending));
}

UpstreamFetch::UpstreamFetchTask::~UpstreamFetchTask() {
  // Set status_ so that callbacks into UpstreamFetchTask exit early.
  status_ = absl::CancelledError("UpstreamFetchTask destroyed");
  if (task_destroyed_callback_) {
    std::move(task_destroyed_callback_)();
  }
}

MoqtFetchTask::GetNextObjectResult
UpstreamFetch::UpstreamFetchTask::GetNextObject(PublishedObject& output) {
  if (!next_object_.has_value()) {
    if (!status_.ok()) {
      return kError;
    }
    if (eof_) {
      return kEof;
    }
    need_object_available_callback_ = true;
    return kPending;
  }
  if (next_object_->payload_length > 0 && payload_.empty()) {
    need_object_available_callback_ = true;
    return kPending;
  }
  while (!payload_.empty()) {
    payload_offset_ += payload_.front().length();
    output.payload.push_back(std::move(payload_.front()));
    payload_.pop_front();
  }
  output.metadata.location =
      Location(next_object_->group_id, next_object_->object_id);
  output.metadata.subgroup = next_object_->subgroup_id;
  output.metadata.status = next_object_->object_status;
  output.metadata.publisher_priority = next_object_->publisher_priority;
  output.metadata.payload_length = next_object_->payload_length;
  output.fin_after_this = false;
  // TODO(martinduke): Make sure the whole object has been delivered.
  if (output.metadata.location ==
      largest_location_) {  // This is the last object.
    eof_ = true;
  }
  if (payload_offset_ == next_object_->payload_length) {
    next_object_.reset();
    payload_offset_ = 0;
    payload_length_ = 0;
  }
  can_read_callback_();
  return kSuccess;
}

void UpstreamFetch::UpstreamFetchTask::NewObject(const MoqtObject& message) {
  next_object_ = message;
  while (!payload_.empty()) {
    payload_.pop_front();
  };
  payload_offset_ = 0;
  payload_length_ = 0;
}

void UpstreamFetch::UpstreamFetchTask::AppendPayloadToObject(
    absl::string_view payload) {
  QUICHE_BUG_IF(quic_bug_AppendPayloadToObjectCalledEarly,
                !next_object_.has_value())
      << "AppendPayloadToObject called without an object";
  QUICHE_BUG_IF(quic_bug_AlreadyGotPayload, next_object_->payload_length == 0)
      << "AppendPayloadToObject called after payload was already full";
  // Copy |payload| to the right spot in the buffer.
  payload_length_ += payload.length();
  payload_.push_back(quiche::QuicheMemSlice::Copy(payload));
}

void UpstreamFetch::UpstreamFetchTask::NotifyNewObject() {
  if (need_object_available_callback_ && object_available_callback_) {
    need_object_available_callback_ = false;
    object_available_callback_();
  }
}

void UpstreamFetch::UpstreamFetchTask::OnStreamAndFetchClosed(
    std::optional<webtransport::StreamErrorCode> error,
    absl::string_view reason_phrase) {
  if (eof_ || !status_.ok()) {
    return;
  }
  // Delete callbacks, because IncomingDataStream and UpstreamFetch are gone.
  can_read_callback_ = nullptr;
  task_destroyed_callback_ = nullptr;
  if (!error.has_value()) {  // This was a FIN.
    eof_ = true;
  } else {
    status_ = MoqtStreamErrorToStatus(*error, reason_phrase);
  }
  if (object_available_callback_) {
    object_available_callback_();
  }
}

}  // namespace moqt
