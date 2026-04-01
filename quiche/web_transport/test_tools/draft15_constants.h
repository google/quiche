// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Machine-readable encoding of draft-ietf-webtrans-http3-15 IANA-registered
// codepoints. All draft-15 acceptance tests include this as the "spec truth"
// reference. Values come from:
// https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-15.html

#ifndef QUICHE_WEB_TRANSPORT_TEST_TOOLS_DRAFT15_CONSTANTS_H_
#define QUICHE_WEB_TRANSPORT_TEST_TOOLS_DRAFT15_CONSTANTS_H_

#include <cstdint>

#include "absl/strings/string_view.h"
#include "quiche/common/capsule.h"
#include "quiche/quic/core/http/http_constants.h"

namespace webtransport::draft15 {

// --- SETTINGS (Section 9.2) ---
// Reference production constants from http_constants.h to avoid duplication.
inline constexpr uint64_t kSettingsWtEnabled =
    quic::SETTINGS_WT_ENABLED;
inline constexpr uint64_t kSettingsWtInitialMaxStreamsUni =
    quic::SETTINGS_WT_INITIAL_MAX_STREAMS_UNI;
inline constexpr uint64_t kSettingsWtInitialMaxStreamsBidi =
    quic::SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI;
inline constexpr uint64_t kSettingsWtInitialMaxData =
    quic::SETTINGS_WT_INITIAL_MAX_DATA;

// --- Capsule types (Section 9.6) ---
// Reference production constants from capsule.h to avoid duplication.
inline constexpr uint64_t kWtCloseSession =
    static_cast<uint64_t>(quiche::CapsuleType::CLOSE_WEBTRANSPORT_SESSION);
inline constexpr uint64_t kWtDrainSession =
    static_cast<uint64_t>(quiche::CapsuleType::DRAIN_WEBTRANSPORT_SESSION);
inline constexpr uint64_t kWtMaxData =
    static_cast<uint64_t>(quiche::CapsuleType::WT_MAX_DATA);
inline constexpr uint64_t kWtMaxStreamsBidi =
    static_cast<uint64_t>(quiche::CapsuleType::WT_MAX_STREAMS_BIDI);
inline constexpr uint64_t kWtMaxStreamsUnidi =
    static_cast<uint64_t>(quiche::CapsuleType::WT_MAX_STREAMS_UNIDI);
inline constexpr uint64_t kWtDataBlocked =
    static_cast<uint64_t>(quiche::CapsuleType::WT_DATA_BLOCKED);
inline constexpr uint64_t kWtStreamsBlockedBidi =
    static_cast<uint64_t>(quiche::CapsuleType::WT_STREAMS_BLOCKED_BIDI);
inline constexpr uint64_t kWtStreamsBlockedUnidi =
    static_cast<uint64_t>(quiche::CapsuleType::WT_STREAMS_BLOCKED_UNIDI);

// --- Error codes (Section 9.5) ---
// Production constants defined in quiche/quic/core/http/http_constants.h.
// Reference them here to avoid duplicate definitions.
inline constexpr uint64_t kWtBufferedStreamRejected =
    quic::kWtBufferedStreamRejected;
inline constexpr uint64_t kWtSessionGone = quic::kWtSessionGone;
inline constexpr uint64_t kWtRequirementsNotMet = quic::kWtRequirementsNotMet;

// --- WT_APPLICATION_ERROR range (Section 4.4) ---
inline constexpr uint64_t kWtApplicationErrorFirst = 0x52e4a40fa8db;
inline constexpr uint64_t kWtApplicationErrorLast = 0x52e5ac983162;

// --- Stream types (Section 4.2, 4.3) ---
// Unidirectional stream type byte.
inline constexpr uint64_t kUniStreamType = 0x54;
// Bidirectional stream signal (WT_STREAM).
inline constexpr uint64_t kBidiSignal = 0x41;

// --- Upgrade token (Section 9.1) ---
inline constexpr absl::string_view kProtocolToken = "webtransport-h3";

// --- Legacy codepoints (draft-02/draft-07, for comparison) ---
inline constexpr uint64_t kSettingsWebtransDraft00 =
    quic::SETTINGS_WEBTRANS_DRAFT00;
inline constexpr uint64_t kSettingsWebtransMaxSessionsDraft07 =
    quic::SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07;

}  // namespace webtransport::draft15

#endif  // QUICHE_WEB_TRANSPORT_TEST_TOOLS_DRAFT15_CONSTANTS_H_
