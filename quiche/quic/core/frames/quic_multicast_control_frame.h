// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_FRAMES_QUIC_MULTICAST_CONTROL_FRAME_H_
#define QUICHE_QUIC_CORE_FRAMES_QUIC_MULTICAST_CONTROL_FRAME_H_

#include <cstdint>
#include <ostream>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quic {

// An outgoing draft-jholland-quic-multicast control frame (MC_LIMITS,
// MC_STATE, MC_ACK, ...). QUICHE does not interpret it: the framer writes
// the frame type as a varint followed by |payload|, which the multicast codec
// has already encoded. It is a retransmittable control frame, except MC_ACK.
struct QUICHE_EXPORT QuicMulticastControlFrame {
  QuicMulticastControlFrame() = default;
  QuicMulticastControlFrame(QuicControlFrameId control_frame_id,
                            uint64_t frame_type, absl::string_view payload);

  // -08 section 8: every frame the draft defines except MC_ACK (both types) is
  // ack-eliciting and retransmitted until acknowledged. MC_ACK is sent as ACK
  // is: not ack-eliciting, not in flight, never retransmitted.
  static bool IsRetransmittable(uint64_t frame_type);

  friend QUICHE_EXPORT std::ostream& operator<<(
      std::ostream& os, const QuicMulticastControlFrame& frame);

  bool operator==(const QuicMulticastControlFrame& rhs) const;
  bool operator!=(const QuicMulticastControlFrame& rhs) const;

  // 0 when received, non-zero when sent.
  QuicControlFrameId control_frame_id = kInvalidControlFrameId;
  // The full frame type, e.g. 0xff3e809 for -08 MC_LIMITS.
  uint64_t frame_type = 0;
  // The frame body after the type varint.
  std::string payload;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_FRAMES_QUIC_MULTICAST_CONTROL_FRAME_H_
