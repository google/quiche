// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_QUICHE_TYPES_H_
#define QUICHE_COMMON_QUICHE_TYPES_H_

#include <cstdint>

namespace quiche {

using QuicheByteCount = uint64_t;

// The two bits in the IP header for Explicit Congestion Notification can take
// one of four values.
enum QuicheEcnCodepoint : uint8_t {
  // The NOT-ECT codepoint, indicating the packet sender is not using (or the
  // network has disabled) ECN.
  ECN_NOT_ECT = 0,
  // The ECT(1) codepoint, indicating the packet sender is using Low Latency,
  // Low Loss, Scalable Throughput (L4S) ECN (RFC9330).
  ECN_ECT1 = 1,
  // The ECT(0) codepoint, indicating the packet sender is using classic ECN
  // (RFC3168).
  ECN_ECT0 = 2,
  // The CE ("Congestion Experienced") codepoint, indicating the packet sender
  // is using ECN, and a router is experiencing congestion.
  ECN_CE = 3,
};
}  // namespace quiche

#endif  // QUICHE_COMMON_QUICHE_TYPES_H_
