// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_ack_timestamp_list.h"

#include <algorithm>
#include <cstddef>
#include <cstdint>

#include "absl/types/span.h"
#include "quiche/quic/core/frames/quic_ack_frame.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

namespace {

// The maximum exponent allowed by the specification.
constexpr uint32_t kMaxExponent = 20;

// TimestampDeltaEncoder wraps the timestamp delta encoding parameters
// (`exponent`) to improve readability via Encode/Decode methods.
struct TimestampDeltaEncoder {
  uint32_t exponent;

  uint64_t Encode(QuicTimeDelta delta) {
    return delta.ToMicroseconds() >> exponent;
  }
  uint64_t EncodeWhileRoundingUp(QuicTimeDelta delta) {
    if (delta.IsZero()) {
      // Avoid bitshift arithmetic on negative numbers in the edge case when
      // `delta` is zero.
      return 0;
    }
    return ((delta.ToMicroseconds() - 1) >> exponent) + 1;
  }
  QuicTimeDelta Decode(uint64_t encoded_delta) {
    return QuicTimeDelta::FromMicroseconds(encoded_delta << exponent);
  }
};

QuicByteCount VarintSize(uint64_t value) {
  return static_cast<QuicByteCount>(QuicDataWriter::GetVarInt62Len(value));
}

}  // namespace

QuicAckTimestampList::QuicAckTimestampList(const QuicAckFrame& ack,
                                           uint32_t max_ack_count,
                                           uint32_t exponent,
                                           QuicTime receive_timestamp_basis)
    : timestamps_(
          std::min<size_t>(ack.received_packet_times.size(), max_ack_count)) {
  if (exponent > kMaxExponent) {
    error_ =
        "The specified exponent exceeds the one allowed by the specification";
    return;
  }
  TimestampDeltaEncoder encoder(exponent);

  // Since the timestamps are delta-encoded and rounded, we need to keep track
  // of what is the latest timestamp written as it would be computed by the
  // decoder.
  QuicTime effective_previous_time = QuicTime::Zero();

  for (uint32_t i = 0; i < timestamps_.size(); ++i) {
    // `i` is the index into the output timestamp list; `i_src` is the index
    // into the original list. They differ since `ack.received_packet_times` is
    // sorted in the ascending time order, and the serialization is required
    // to be in descending order. Also, the output range can be smaller than the
    // input range, in which case the newer timestamps are selected as suggested
    // by the spec.
    const size_t i_src = ack.received_packet_times.size() - i - 1;
    const auto [packet_number, timestamp] = ack.received_packet_times[i_src];

    if (timestamp < receive_timestamp_basis) {
      error_ = "Packet is received earlier than framer creation time";
      return;
    }
    if (packet_number > ack.largest_acked) {
      error_ = "Packet number listed higher than largest_acked";
      return;
    }

    bool should_open_new_range;
    if (i >= 1) {
      QUICHE_DCHECK(effective_previous_time.IsInitialized());
      const auto [prev_packet_number, prev_timestamp] =
          ack.received_packet_times[i_src + 1];
      if (timestamp > prev_timestamp) {
        error_ =
            "Receive timestamps have to be in monotonically ascending order.";
        return;
      }

      should_open_new_range = prev_packet_number != (packet_number + 1);
      timestamps_[i] = encoder.Encode(effective_previous_time - timestamp);
      effective_previous_time =
          effective_previous_time - encoder.Decode(timestamps_[i]);
    } else {
      QUICHE_DCHECK(!effective_previous_time.IsInitialized());
      should_open_new_range = true;
      timestamps_[i] =
          encoder.EncodeWhileRoundingUp(timestamp - receive_timestamp_basis);
      effective_previous_time =
          receive_timestamp_basis + encoder.Decode(timestamps_[i]);
    }

    if (should_open_new_range) {
      ranges_.push_back(TimestampRange{
          .delta_from_largest_acked = ack.largest_acked - packet_number,
          .first_timestamp = i,
          .timestamp_count = 0});
    }
    ++ranges_.back().timestamp_count;
  }
}

QuicByteCount QuicAckTimestampList::EncodedSize() const {
  if (!error_.empty()) {
    QUIC_LOG(DFATAL) << "EncodedSize() called when error() is non-empty";
    return 0;
  }

  QuicByteCount total_size = 0;
  total_size += VarintSize(ranges_.size());
  for (const TimestampRange& range : ranges_) {
    total_size += VarintSize(range.delta_from_largest_acked);
    total_size += VarintSize(range.timestamp_count);
  }
  // Every element in `timestamps_` belongs to exactly one TimestampRange.
  for (const uint64_t timestamp : timestamps_) {
    total_size += VarintSize(timestamp);
  }
  return total_size;
}

[[nodiscard]] bool QuicAckTimestampList::Write(QuicDataWriter& writer) const {
  if (!error_.empty()) {
    QUIC_LOG(DFATAL) << "Write() called when error() is non-empty";
    return false;
  }

  if (!writer.WriteVarInt62(ranges_.size())) {
    return false;
  }
  for (const TimestampRange& range : ranges_) {
    if (!writer.WriteVarInt62(range.delta_from_largest_acked) ||
        !writer.WriteVarInt62(range.timestamp_count)) {
      return false;
    }
    const absl::Span<const uint64_t> timestamps_in_range(
        timestamps_.begin() + range.first_timestamp, range.timestamp_count);
    for (const uint64_t timestamp : timestamps_in_range) {
      if (!writer.WriteVarInt62(timestamp)) {
        return false;
      }
    }
  }
  return true;
}

}  // namespace quic
