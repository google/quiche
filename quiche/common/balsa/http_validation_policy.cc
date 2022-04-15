// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/balsa/http_validation_policy.h"

#include <tuple>

#include "quiche/common/platform/api/quiche_logging.h"

namespace quiche {

HttpValidationPolicy::HttpValidationPolicy(bool enforce_header_keys,
                                           bool enforce_all)
    : enforce_header_keys_(enforce_header_keys), enforce_all_(enforce_all) {
  if (enforce_all_) {
    QUICHE_DCHECK(enforce_header_keys_);
  }
}

HttpValidationPolicy HttpValidationPolicy::CreateDefault() {
  return HttpValidationPolicy(true, false);
}

bool HttpValidationPolicy::operator==(const HttpValidationPolicy& other) const {
  return std::tie(enforce_header_keys_, enforce_all_) ==
         std::tie(other.enforce_header_keys_, other.enforce_all_);
}

}  // namespace quiche
