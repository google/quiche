// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_SCONE_H_
#define QUICHE_QUIC_CORE_SCONE_H_

// Constants relevant to the SCONE protocol (draft-ietf-quic-scone-04).

#include <cstdint>

#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"

namespace quic {

// SCONE capable clients append this to datagrams in the first flight.
static constexpr uint16_t kSconeIndicator = 0xc813;
static constexpr QuicByteCount kSconeIndicatorLength = sizeof(kSconeIndicator);

// If a QUIC Long Header contains a SCONE version, it is actually for a SCONE
// packet.
static constexpr QuicVersionLabel kSconeVersionHigh = 0xef7dc0fd;

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_SCONE_H_
