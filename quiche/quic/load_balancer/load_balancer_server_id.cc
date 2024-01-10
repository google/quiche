// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_server_id.h"

#include <array>
#include <cstdint>
#include <cstring>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"

namespace quic {

LoadBalancerServerId::LoadBalancerServerId(absl::string_view data)
    : LoadBalancerServerId(
          absl::MakeSpan(reinterpret_cast<const uint8_t*>(data.data()),
                         data.length()),
          absl::Span<const uint8_t>()) {}

LoadBalancerServerId::LoadBalancerServerId(absl::Span<const uint8_t> data)
    : LoadBalancerServerId(data, absl::Span<const uint8_t>()) {}

LoadBalancerServerId::LoadBalancerServerId(absl::Span<const uint8_t> data1,
                                           absl::Span<const uint8_t> data2)
    : length_(data1.length() + data2.length()) {
  if (length_ == 0 || length_ > kLoadBalancerMaxServerIdLen) {
    QUIC_BUG(quic_bug_433312504_02)
        << "Attempted to create LoadBalancerServerId with length "
        << static_cast<int>(length_);
    length_ = 0;
    return;
  }
  memcpy(data_.data(), data1.data(), data1.length());
  if (data2.empty()) {
    return;
  }
  memcpy(data_.data() + data1.length(), data2.data(), data2.length());
}

std::string LoadBalancerServerId::ToString() const {
  return absl::BytesToHexString(
      absl::string_view(reinterpret_cast<const char*>(data_.data()), length_));
}

}  // namespace quic
