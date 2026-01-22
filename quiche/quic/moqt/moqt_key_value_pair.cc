// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_key_value_pair.h"

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace moqt {

void KeyValuePairList::insert(uint64_t key,
                              std::variant<uint64_t, absl::string_view> value) {
  QUICHE_DCHECK(
      (key % 2 == 1 && std::holds_alternative<absl::string_view>(value)) ||
      (key % 2 == 0 && std::holds_alternative<uint64_t>(value)));
  if (std::holds_alternative<absl::string_view>(value)) {
    map_.insert({key, std::string(std::get<absl::string_view>(value))});
  } else {
    map_.insert({key, std::get<uint64_t>(value)});
  }
}

bool KeyValuePairList::ForEach(ValueCallback callback) const {
  for (const auto& [key, value] : map_) {
    if (!std::visit([&](const auto& val) { return callback(key, val); },
                    value)) {
      return false;
    }
  }
  return true;
}

KeyValuePairList::ValueVector KeyValuePairList::Get(uint64_t key) const {
  std::vector<std::variant<uint64_t, absl::string_view>> values;
  auto entries = map_.equal_range(key);
  for (auto it = entries.first; it != entries.second; ++it) {
    std::visit([&](const auto& value) { values.push_back(value); }, it->second);
  }
  return values;
}

void SubscriptionFilter::OnLargestObject(
    const std::optional<Location>& largest_object) {
  switch (type_) {
    case MoqtFilterType::kAbsoluteStart:
    case MoqtFilterType::kAbsoluteRange:
      return;
    case MoqtFilterType::kNextGroupStart:
      if (largest_object.has_value()) {
        start_ = Location(largest_object->group + 1, 0);
      }
      break;
    case MoqtFilterType::kLargestObject:
      if (largest_object.has_value()) {
        start_ = largest_object->Next();
      }
      break;
  }
  type_ = MoqtFilterType::kAbsoluteStart;
}

}  // namespace moqt
