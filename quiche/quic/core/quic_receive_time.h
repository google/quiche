// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_RECEIVE_TIME_H_
#define QUICHE_QUIC_CORE_QUIC_RECEIVE_TIME_H_

#include <compare>
#include <cstdint>
#include <optional>
#include <ostream>

#include "quiche/quic/core/quic_time.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quic {

// QuicReceiveTime represents a QUIC receive timestamp, in microseconds. Both
// timestamps generated locally and timestamps received from the peer are
// represented using this class. If a timestamp was generated locally, it is
// computed relative to the connection creation time using QuicClock associated
// with the connection. If a timestamp is remote, it is assumed to be relative
// to some fixed clock by the peer.
//
// Internally, QuicReceiveTime is a QuicTimeDelta; the class enforces an
// invariant that the time delta has to be non-negative.
class QUICHE_EXPORT QuicReceiveTime {
 public:
  // Creates a receive timestamp received from the peer.  Returns nullopt if the
  // timestamp is negative.
  static constexpr std::optional<QuicReceiveTime> FromPeerTime(
      QuicTimeDelta timestamp) {
    if (timestamp < QuicTimeDelta::Zero()) {
      return std::nullopt;
    }
    return QuicReceiveTime(timestamp);
  }

  // Creates a receive timestamp from local clock time.  Returns nullopt if the
  // timestamp is before the timestamp basis.
  static constexpr std::optional<QuicReceiveTime> FromLocalTime(
      QuicTime timestamp, QuicTime receive_timestamp_basis) {
    if (timestamp < receive_timestamp_basis) {
      return std::nullopt;
    }
    return QuicReceiveTime(timestamp - receive_timestamp_basis);
  }

  QuicReceiveTime(const QuicReceiveTime&) = default;
  QuicReceiveTime(QuicReceiveTime&&) = default;
  QuicReceiveTime& operator=(const QuicReceiveTime&) = default;
  QuicReceiveTime& operator=(QuicReceiveTime&&) = default;

  constexpr QuicTimeDelta raw_value() const {
    return delta_from_reference_time_;
  }

  // API compatibility with QuicTime.
  constexpr int64_t ToDebuggingValue() const {
    return delta_from_reference_time_.ToMicroseconds();
  }

  constexpr std::strong_ordering operator<=>(
      const QuicReceiveTime& other) const = default;
  constexpr QuicTimeDelta operator-(const QuicReceiveTime& other) const {
    return delta_from_reference_time_ - other.delta_from_reference_time_;
  }

  QUICHE_EXPORT friend std::ostream& operator<<(std::ostream& output,
                                                QuicReceiveTime t) {
    output << t.raw_value();
    return output;
  }

 private:
  explicit constexpr QuicReceiveTime(QuicTimeDelta value)
      : delta_from_reference_time_(value) {}

  QuicTimeDelta delta_from_reference_time_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_RECEIVE_TIME_H_
