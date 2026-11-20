// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/frames/quic_multicast_control_frame.h"

#include <cstdint>
#include <ostream>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_types.h"

namespace quic {

QuicMulticastControlFrame::QuicMulticastControlFrame(
    QuicControlFrameId control_frame_id, uint64_t frame_type,
    absl::string_view payload)
    : control_frame_id(control_frame_id),
      frame_type(frame_type),
      payload(payload) {}

// static
bool QuicMulticastControlFrame::IsRetransmittable(uint64_t frame_type) {
  return frame_type != kMcAck && frame_type != kMcAckEcn;
}

std::ostream& operator<<(std::ostream& os,
                         const QuicMulticastControlFrame& frame) {
  os << "{ control_frame_id: " << frame.control_frame_id << ", frame_type: 0x"
     << std::hex << frame.frame_type << std::dec
     << ", payload_length: " << frame.payload.size() << " }\n";
  return os;
}

bool QuicMulticastControlFrame::operator==(
    const QuicMulticastControlFrame& rhs) const {
  return control_frame_id == rhs.control_frame_id &&
         frame_type == rhs.frame_type && payload == rhs.payload;
}

bool QuicMulticastControlFrame::operator!=(
    const QuicMulticastControlFrame& rhs) const {
  return !(*this == rhs);
}

}  // namespace quic
