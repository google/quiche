// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_ERROR_H_
#define QUICHE_QUIC_MOQT_MOQT_ERROR_H_

#include <cstdint>
#include <optional>
#include <string>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

// These are session errors sent in CONNECTION_CLOSE.
enum QUICHE_EXPORT MoqtError : uint64_t {
  kNoError = 0x0,
  kInternalError = 0x1,
  kUnauthorized = 0x2,
  kProtocolViolation = 0x3,
  kInvalidRequestId = 0x4,
  kDuplicateTrackAlias = 0x5,
  kKeyValueFormattingError = 0x6,
  kTooManyRequests = 0x7,
  kInvalidPath = 0x8,
  kMalformedPath = 0x9,
  kGoawayTimeout = 0x10,
  kControlMessageTimeout = 0x11,
  kDataStreamTimeout = 0x12,
  kAuthTokenCacheOverflow = 0x13,
  kDuplicateAuthTokenAlias = 0x14,
  kVersionNegotiationFailed = 0x15,
  kMalformedAuthToken = 0x16,
  kUnknownAuthTokenAlias = 0x17,
  kExpiredAuthToken = 0x18,
  kInvalidAuthority = 0x19,
  kMalformedAuthority = 0x1a,
};

// Error codes used by MoQT to reset streams.
inline constexpr webtransport::StreamErrorCode kResetCodeUnknown = 0x00;
inline constexpr webtransport::StreamErrorCode kResetCodeCanceled = 0x01;
inline constexpr webtransport::StreamErrorCode kResetCodeDeliveryTimeout = 0x02;
inline constexpr webtransport::StreamErrorCode kResetCodeSessionClosed = 0x03;
// TODO(martinduke): This is not in the spec, but is needed. The number might
// change.
inline constexpr webtransport::StreamErrorCode kResetCodeMalformedTrack = 0x04;

// Used for SUBSCRIBE_ERROR, PUBLISH_NAMESPACE_ERROR, PUBLISH_NAMESPACE_CANCEL,
// SUBSCRIBE_NAMESPACE_ERROR, and FETCH_ERROR.
enum class QUICHE_EXPORT RequestErrorCode : uint64_t {
  kInternalError = 0x0,
  kUnauthorized = 0x1,
  kTimeout = 0x2,
  kNotSupported = 0x3,
  kTrackDoesNotExist = 0x4,  // SUBSCRIBE_ERROR and FETCH_ERROR only.
  kUninterested =
      0x4,  // PUBLISH_NAMESPACE_ERROR and PUBLISH_NAMESPACE_CANCEL only.
  kNamespacePrefixUnknown = 0x4,   // SUBSCRIBE_NAMESPACE_ERROR only.
  kInvalidRange = 0x5,             // SUBSCRIBE_ERROR and FETCH_ERROR only.
  kNamespacePrefixOverlap = 0x5,   // SUBSCRIBE_NAMESPACE_ERROR only.
  kNoObjects = 0x6,                // FETCH_ERROR only.
  kInvalidJoiningRequestId = 0x7,  // FETCH_ERROR only.
  kUnknownStatusInRange = 0x8,     // FETCH_ERROR only.
  kMalformedTrack = 0x9,
  kMalformedAuthToken = 0x10,
  kExpiredAuthToken = 0x12,
};

struct MoqtRequestErrorInfo {
  RequestErrorCode error_code;
  std::optional<quic::QuicTimeDelta> retry_interval;
  std::string reason_phrase;
};

RequestErrorCode StatusToRequestErrorCode(absl::Status status);
absl::StatusCode RequestErrorCodeToStatusCode(RequestErrorCode error_code);
absl::Status RequestErrorCodeToStatus(RequestErrorCode error_code,
                                      absl::string_view reason_phrase);

absl::Status MoqtStreamErrorToStatus(webtransport::StreamErrorCode error_code,
                                     absl::string_view reason_phrase);

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_ERROR_H_
