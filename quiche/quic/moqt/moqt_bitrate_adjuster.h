// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_BITRATE_ADJUSTER_H_
#define QUICHE_QUIC_MOQT_MOQT_BITRATE_ADJUSTER_H_

#include <optional>

#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_outstanding_objects.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

// Indicates the type of new bitrate estimate.
enum class BitrateAdjustmentType {
  // Indicates that the sender is sending too much data.
  kDown,

  // Indicates that the sender should attempt to increase the amount of data
  // sent.
  kUp,
};

// A sender that can potentially have its outgoing bitrate adjusted.
class BitrateAdjustable {
 public:
  virtual ~BitrateAdjustable() {}

  // Returns the currently used bitrate.
  // TODO(vasilvv): we should not depend on this value long-term, since the
  // self-reported bitrate is not reliable in most real encoders.
  virtual quic::QuicBandwidth GetCurrentBitrate() const = 0;

  // Returns true if the sender could make use of more bandwidth than it is
  // currently sending at.
  virtual bool CouldUseExtraBandwidth() = 0;

  // Notifies the sender that it should consider increasing or decreasing its
  // bandwidth.  `bandwidth` is the estimate of bandwidth available to the
  // application.
  virtual void ConsiderAdjustingBitrate(quic::QuicBandwidth bandwidth,
                                        BitrateAdjustmentType type) = 0;
};

// Parameters (mostly magic numbers) that determine behavior of
// MoqtBitrateAdjuster.
struct MoqtBitrateAdjusterParameters {
  // When bitrate is adjusted down, multiply the congestion controller estimate
  // by this factor.  This should be less than 1, since congestion controller
  // estimate tends to be overly optimistic in practice.
  float target_bitrate_multiplier_down = 0.9f;

  // Do not perform any updates within `initial_delay` after the connection
  // start.
  quic::QuicTimeDelta initial_delay = quic::QuicTimeDelta::FromSeconds(2);

  // If the object arrives too close to the deadline, the bitrate will be
  // adjusted down.  The threshold is expressed as a fraction of `time_window`
  // (which typically would be equal to the size of the buffer in seconds).
  float adjust_down_threshold = 0.1f;

  // The maximum gap between the next object expected to be received, and the
  // actually received object, expressed as a number of objects.
  //
  // The default is 12, which corresponds to about 400ms for 30fps video.
  int max_out_of_order_objects = 12;
};

// MoqtBitrateAdjuster monitors the progress of delivery for a single track, and
// adjusts the bitrate of the track in question accordingly.
class MoqtBitrateAdjuster : public MoqtPublishingMonitorInterface {
 public:
  MoqtBitrateAdjuster(const quic::QuicClock* clock,
                      webtransport::Session* session,
                      BitrateAdjustable* adjustable)
      : clock_(clock), session_(session), adjustable_(adjustable) {}

  // MoqtPublishingMonitorInterface implementation.
  void OnObjectAckSupportKnown(
      std::optional<quic::QuicTimeDelta> time_window) override;
  void OnNewObjectEnqueued(Location location) override;
  void OnObjectAckReceived(Location location,
                           quic::QuicTimeDelta delta_from_deadline) override;

  MoqtTraceRecorder& trace_recorder() { return trace_recorder_; }
  MoqtBitrateAdjusterParameters& parameters() { return parameters_; }

 private:
  void Start();

  // Checks if the bitrate adjuster should react to an individual ack.
  bool ShouldUseAckAsActionSignal(Location location);

  // Checks if the bitrate should be adjusted down based on the result of
  // processing an object ACK.
  bool ShouldAttemptAdjustingDown(
      int reordering_delta, quic::QuicTimeDelta delta_from_deadline) const;

  // Attempts adjusting the bitrate down.
  void AttemptAdjustingDown();

  void SuggestNewBitrate(quic::QuicBandwidth bitrate,
                         BitrateAdjustmentType type);

  const quic::QuicClock* clock_;    // Not owned.
  webtransport::Session* session_;  // Not owned.
  BitrateAdjustable* adjustable_;   // Not owned.
  MoqtTraceRecorder trace_recorder_;
  MoqtBitrateAdjusterParameters parameters_;

  // The time at which Start() has been called.
  quic::QuicTime start_time_ = quic::QuicTime::Zero();

  // The window size received from the peer.  This amount is used to establish
  // the scale for incoming time deltas in the object ACKs.
  quic::QuicTimeDelta time_window_ = quic::QuicTimeDelta::Zero();

  std::optional<MoqtOutstandingObjects> outstanding_objects_;
  Location last_acked_object_;
};

// Given a suggestion to change bitrate `old_bitrate` to `new_bitrate` with the
// specified adjustment type, returns true if the change should be ignored.
// `min_change` is the threshold below which the change should be ignored,
// specified as a fraction of old bitrate.
bool ShouldIgnoreBitrateAdjustment(quic::QuicBandwidth new_bitrate,
                                   BitrateAdjustmentType type,
                                   quic::QuicBandwidth old_bitrate,
                                   float min_change);

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_BITRATE_ADJUSTER_H_
