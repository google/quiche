// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_HTTP_STATUS_CODE_MAPPING_H_
#define QUICHE_COMMON_HTTP_STATUS_CODE_MAPPING_H_

#include "absl/status/status.h"

namespace quiche {

// Converts an absl::StatusCode to an HTTP status code.
int StatusCodeAbslToHttp(absl::StatusCode code);

// Converts an absl::Status to an HTTP status code.
int StatusToHttpStatusCode(const absl::Status& status);

}  // namespace quiche

#endif  // QUICHE_COMMON_HTTP_STATUS_CODE_MAPPING_H_
