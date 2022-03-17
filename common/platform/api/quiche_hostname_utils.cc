// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "common/platform/api/quiche_hostname_utils.h"

#include "absl/strings/string_view.h"

namespace quiche {

// static
bool QuicheHostnameUtils::IsValidSNI(absl::string_view sni) {
  return QuicheHostnameUtilsImpl::IsValidSNI(sni);
}

// static
std::string QuicheHostnameUtils::NormalizeHostname(absl::string_view hostname) {
  return QuicheHostnameUtilsImpl::NormalizeHostname(hostname);
}

}  // namespace quiche
