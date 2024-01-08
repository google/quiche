// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_server_id.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"

namespace quic {

std::optional<LoadBalancerServerId> LoadBalancerServerId::Create(
    const absl::Span<const uint8_t> data) {
  if (data.length() == 0 || data.length() > kLoadBalancerMaxServerIdLen) {
    QUIC_BUG(quic_bug_433312504_01)
        << "Attempted to create LoadBalancerServerId with length "
        << data.length();
    return std::optional<LoadBalancerServerId>();
  }
  return LoadBalancerServerId(data);
}

std::string LoadBalancerServerId::ToString() const {
  return absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char*>(data_.data()), length_));
}

LoadBalancerServerId::LoadBalancerServerId(const absl::Span<const uint8_t> data)
    : length_(data.length()) {
  memcpy(data_.data(), data.data(), data.length());
}

}  // namespace quic
