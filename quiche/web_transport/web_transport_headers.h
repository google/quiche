// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_WEB_TRANSPORT_WEB_TRANSPORT_HEADERS_H_
#define QUICHE_WEB_TRANSPORT_WEB_TRANSPORT_HEADERS_H_

#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace webtransport {

inline constexpr absl::string_view kSubprotocolRequestHeader =
    "WebTransport-Subprotocols-Available";
inline constexpr absl::string_view kSubprotocolResponseHeader =
    "WebTransport-Subprotocol";

QUICHE_EXPORT absl::StatusOr<std::vector<std::string>>
ParseSubprotocolRequestHeader(absl::string_view value);
QUICHE_EXPORT absl::StatusOr<std::string> SerializeSubprotocolRequestHeader(
    absl::Span<const std::string> subprotocols);

}  // namespace webtransport

#endif  // QUICHE_WEB_TRANSPORT_WEB_TRANSPORT_HEADERS_H_
