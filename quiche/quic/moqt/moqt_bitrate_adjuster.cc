// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_bitrate_adjuster.h"

#include <cstdlib>
#include <optional>

#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace {

using ::quic::QuicBandwidth;
using ::quic::QuicTime;
using ::quic::QuicTimeDelta;

}  // namespace

void MoqtBitrateAdjuster::Start() {
  if (start_time_.IsInitialized()) {
    QUICHE_BUG(MoqtBitrateAdjuster_double_init)
        << "MoqtBitrateAdjuster::Start() called more than once.";
    return;
  }
  start_time_ = clock_->Now();
  outstanding_objects_.emplace(
      /*max_out_of_order_objects=*/parameters_.max_out_of_order_objects);
}

void MoqtBitrateAdjuster::OnObjectAckReceived(
    Location location, QuicTimeDelta delta_from_deadline) {
  if (!start_time_.IsInitialized() || !outstanding_objects_.has_value()) {
    return;
  }

  // Update the state.
  int reordering_delta = outstanding_objects_->OnObjectAcked(location);

  // Decide whether to act based on the latest signal.
  if (!ShouldUseAckAsActionSignal(location)) {
    return;
  }
  if (ShouldAttemptAdjustingDown(reordering_delta, delta_from_deadline)) {
    AttemptAdjustingDown();
  }
}

bool MoqtBitrateAdjuster::ShouldUseAckAsActionSignal(Location location) {
  // Allow for some time to pass for the connection to reach the point at which
  // the rate adaptation signals can become useful.
  const QuicTime earliest_action_time = start_time_ + parameters_.initial_delay;
  const bool too_early_in_the_connection = clock_->Now() < earliest_action_time;

  // Ignore out-of-order acks for the purpose of deciding whether to adjust up
  // or down.  Generally, if an ack is out of order, the bitrate adjuster has
  // already reacted to the later object appropriately.
  const bool is_out_of_order_ack = location < last_acked_object_;
  last_acked_object_ = location;

  return !too_early_in_the_connection && !is_out_of_order_ack;
}

bool MoqtBitrateAdjuster::ShouldAttemptAdjustingDown(
    int reordering_delta, quic::QuicTimeDelta delta_from_deadline) const {
  const bool has_exceeded_max_out_of_order =
      reordering_delta > parameters_.max_out_of_order_objects;
  QUICHE_DLOG_IF(INFO, has_exceeded_max_out_of_order)
      << "Adjusting connection down due to reordering, delta: "
      << reordering_delta;

  const bool time_delta_too_close =
      delta_from_deadline < parameters_.adjust_down_threshold * time_window_;
  QUICHE_DLOG_IF(INFO, time_delta_too_close)
      << "Adjusting connection down due to object arriving too late, time "
         "delta: "
      << delta_from_deadline;

  return has_exceeded_max_out_of_order || time_delta_too_close;
}

void MoqtBitrateAdjuster::AttemptAdjustingDown() {
  webtransport::SessionStats stats = session_->GetSessionStats();
  QuicBandwidth target_bandwidth =
      parameters_.target_bitrate_multiplier_down *
      QuicBandwidth::FromBitsPerSecond(stats.estimated_send_rate_bps);
  QUICHE_DLOG(INFO) << "Adjusting the bitrate down to " << target_bandwidth;
  SuggestNewBitrate(target_bandwidth, BitrateAdjustmentType::kDown);
}

void MoqtBitrateAdjuster::OnObjectAckSupportKnown(
    std::optional<quic::QuicTimeDelta> time_window) {
  if (!time_window.has_value() || *time_window <= QuicTimeDelta::Zero()) {
    QUICHE_DLOG(WARNING)
        << "OBJECT_ACK not supported; bitrate adjustments will not work.";
    return;
  }
  time_window_ = *time_window;
  Start();
}

bool ShouldIgnoreBitrateAdjustment(quic::QuicBandwidth new_bitrate,
                                   BitrateAdjustmentType type,
                                   quic::QuicBandwidth old_bitrate,
                                   float min_change) {
  const float min_change_bps = old_bitrate.ToBitsPerSecond() * min_change;
  const float change_bps =
      new_bitrate.ToBitsPerSecond() - old_bitrate.ToBitsPerSecond();
  if (std::abs(change_bps) < min_change_bps) {
    return true;
  }

  switch (type) {
    case moqt::BitrateAdjustmentType::kDown:
      if (new_bitrate >= old_bitrate) {
        return true;
      }
      break;
    case moqt::BitrateAdjustmentType::kUp:
      if (old_bitrate >= new_bitrate) {
        return true;
      }
      break;
  }
  return false;
}

void MoqtBitrateAdjuster::SuggestNewBitrate(quic::QuicBandwidth bitrate,
                                            BitrateAdjustmentType type) {
  adjustable_->ConsiderAdjustingBitrate(bitrate, type);
  trace_recorder_.RecordTargetBitrateSet(bitrate);
}

void MoqtBitrateAdjuster::OnNewObjectEnqueued(Location location) {
  if (!start_time_.IsInitialized() || !outstanding_objects_.has_value()) {
    return;
  }
  outstanding_objects_->OnObjectAdded(location);
}

}  // namespace moqt
