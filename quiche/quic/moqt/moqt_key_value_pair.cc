// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_key_value_pair.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_key_value_serialization.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/wire_serialization.h"

namespace moqt {

void KeyValuePairList::insert(KeyValuePair pair) {
  QUICHE_DCHECK(
      (pair.key % 2 == 1 &&
       std::holds_alternative<absl::string_view>(pair.value)) ||
      (pair.key % 2 == 0 && std::holds_alternative<uint64_t>(pair.value)));
  if (std::holds_alternative<absl::string_view>(pair.value)) {
    map_.insert(
        {pair.key, std::string(std::get<absl::string_view>(pair.value))});
  } else {
    map_.insert({pair.key, std::get<uint64_t>(pair.value)});
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

void LocationFilter::ConvertRelativeToAbsolute(
    const std::optional<Location>& largest_object) {
  switch (type_) {
    case MoqtLocationFilterType::kRelativeStart:
      type_ = MoqtLocationFilterType::kAbsoluteStart;
      if (!largest_object.has_value() ||
          largest_object->group + 1 < start_.group) {
        start_ = Location(0, 0);
        break;
      }
      start_ = Location(largest_object->group + 1 - start_.group, 0);
      break;
    case MoqtLocationFilterType::kNextObject:
      type_ = MoqtLocationFilterType::kAbsoluteStart;
      if (!largest_object.has_value()) {
        break;
      }
      start_ = largest_object->Next();
      break;
    default:
      return;
  }
  type_ = MoqtLocationFilterType::kAbsoluteStart;
}

absl::Status LocationFilter::TrimEndLocation(const Location& end_location) {
  if (end_location < start()) {
    return absl::OutOfRangeError("End location is before start location");
  }
  end_ = std::min(end_, end_location);
  return absl::OkStatus();
}

void MessageParameters::Update(const MessageParameters& other) {
  // In order of MessageParameter enum.
  if (other.object_delivery_timeout.has_value()) {
    object_delivery_timeout = other.object_delivery_timeout;
  }
  if (!other.authorization_tokens.empty()) {
    authorization_tokens = other.authorization_tokens;
  }
  // RENDEZVOUS_TIMEOUT cannot be updated.
  if (other.subgroup_delivery_timeout.has_value()) {
    subgroup_delivery_timeout = other.subgroup_delivery_timeout;
  }
  if (other.expires.has_value()) {
    expires = other.expires;
  }
  if (other.largest_object.has_value()) {
    largest_object = other.largest_object;
  }
  if (other.forward_.has_value()) {
    forward_ = other.forward_;
  }
  if (other.subscriber_priority.has_value()) {
    subscriber_priority = other.subscriber_priority;
  }
  if (other.location_filter.has_value()) {
    location_filter = other.location_filter;
  }
  // GROUP_ORDER cannot be updated.
  if (other.new_group_request.has_value()) {
    new_group_request = other.new_group_request;
  }
  if (other.track_namespace_prefix.has_value()) {
    track_namespace_prefix = other.track_namespace_prefix;
  }
  if (other.oack_window_size.has_value()) {
    oack_window_size = other.oack_window_size;
  }
  if (location_filter.has_value() && !location_filter->WindowKnown()) {
    location_filter->ConvertRelativeToAbsolute(largest_object);
  }
}

void MoqtProperties::AddImmutablePropertyList(
    std::optional<KeyValuePairList> immutable) {
  if (!immutable.has_value() || immutable->contains(static_cast<uint64_t>(
                                    PropertyType::kImmutableProperties))) {
    malformed_immutable_properties_ = true;
    return;
  }
  if (immutable->size() == 0) {
    return;
  }
  immutable_properties_ = *std::move(immutable);
  if (!contains(static_cast<uint64_t>(PropertyType::kImmutableProperties))) {
    absl::StatusOr<std::string> serialized = quiche::SerializeIntoString(
        WireKeyValuePairList(immutable_properties_));
    if (!serialized.ok()) {
      QUICHE_BUG(moqt_failed_immutable_serialization)
          << "Failed to serialize immutable properties: "
          << serialized.status();
      return;
    }
    insert({PropertyType::kImmutableProperties, *serialized});
  }
}

quic::QuicTimeDelta MoqtProperties::object_delivery_timeout() const {
  std::optional<uint64_t> value =
      GetValueIfExactlyOne(PropertyType::kObjectDeliveryTimeout);
  return (value.has_value() && *value > 0)
             ? quic::QuicTimeDelta::FromMilliseconds(*value)
             : kDefaultDeliveryTimeout;
}
quic::QuicTimeDelta MoqtProperties::max_cache_duration() const {
  std::optional<uint64_t> value =
      GetValueIfExactlyOne(PropertyType::kMaxCacheDuration);
  return value.has_value() ? quic::QuicTimeDelta::FromMilliseconds(*value)
                           : kDefaultMaxCacheDuration;
}
quic::QuicTimeDelta MoqtProperties::subgroup_delivery_timeout() const {
  std::optional<uint64_t> value =
      GetValueIfExactlyOne(PropertyType::kSubgroupDeliveryTimeout);
  return (value.has_value() && *value > 0)
             ? quic::QuicTimeDelta::FromMilliseconds(*value)
             : kDefaultDeliveryTimeout;
}
absl::string_view MoqtProperties::immutable_properties() const {
  ValueVector values =
      Get(static_cast<uint64_t>(PropertyType::kImmutableProperties));
  return (values.size() != 1 ||
          !std::holds_alternative<absl::string_view>(values[0]))
             ? ""
             : std::get<absl::string_view>(values[0]);
}
MoqtPriority MoqtProperties::default_publisher_priority() const {
  std::optional<uint64_t> value =
      GetValueIfExactlyOne(PropertyType::kDefaultPublisherPriority);
  return (!value.has_value() || *value > kMaxPriority)
             ? kDefaultPublisherPriority
             : static_cast<MoqtPriority>(*value);
}
MoqtGroupOrder MoqtProperties::default_publisher_group_order() const {
  std::optional<uint64_t> value =
      GetValueIfExactlyOne(PropertyType::kDefaultPublisherGroupOrder);
  return (!value.has_value() || *value > kMaxMoqtGroupOrder ||
          *value < kMinMoqtGroupOrder)
             ? kDefaultGroupOrder
             : static_cast<MoqtGroupOrder>(*value);
}
bool MoqtProperties::dynamic_groups() const {
  std::optional<uint64_t> value =
      GetValueIfExactlyOne(PropertyType::kDynamicGroups);
  return (!value.has_value() || *value > 1) ? kDefaultDynamicGroups
                                            : (*value == 1);
}

bool MoqtProperties::Validate() const {
  return (ValidateInner(PropertyType::kDefaultPublisherPriority, std::nullopt,
                        kMaxPriority) &&
          ValidateInner(PropertyType::kDefaultPublisherGroupOrder,
                        kMinMoqtGroupOrder, kMaxMoqtGroupOrder) &&
          ValidateInner(PropertyType::kDynamicGroups, 0, 1));
}

bool MoqtProperties::IsMalformed() const {
  return malformed_immutable_properties_ ||
         TotalCount(PropertyType::kObjectDeliveryTimeout) > 1 ||
         TotalCount(PropertyType::kMaxCacheDuration) > 1 ||
         TotalCount(PropertyType::kSubgroupDeliveryTimeout) > 1 ||
         TotalCount(PropertyType::kImmutableProperties) > 1 ||
         TotalCount(PropertyType::kDefaultPublisherPriority) > 1 ||
         TotalCount(PropertyType::kDefaultPublisherGroupOrder) > 1 ||
         TotalCount(PropertyType::kDynamicGroups) > 1 ||
         TotalCount(PropertyType::kPriorGroupIdGap) > 1 ||
         TotalCount(PropertyType::kPriorObjectIdGap) > 1;
}

// private
std::optional<uint64_t> MoqtProperties::GetValueIfExactlyOne(
    PropertyType header) const {
  uint64_t key = static_cast<uint64_t>(header);
  QUICHE_BUG_IF(moqt_bug_must_be_even, (key % 2) == 1)
      << "MoqtKeyValuePair extracting integer from odd key.";
  if (TotalCount(header) != 1) {
    return std::nullopt;
  }
  ValueVector values =
      contains(key) ? Get(key) : immutable_properties_.Get(key);
  if (values.empty() || !std::holds_alternative<uint64_t>(values[0])) {
    return std::nullopt;
  }
  return std::get<uint64_t>(values[0]);
}

bool MoqtProperties::ValidateInner(PropertyType header,
                                   std::optional<uint64_t> min,
                                   std::optional<uint64_t> max) const {
  uint64_t key = static_cast<uint64_t>(header);
  for (const ValueVector& list : {Get(key), immutable_properties_.Get(key)}) {
    for (const auto& value : list) {
      if (!std::holds_alternative<uint64_t>(value)) {
        return false;
      }
      uint64_t int_value = std::get<uint64_t>(value);
      if ((min.has_value() && int_value < *min) ||
          (max.has_value() && int_value > *max)) {
        return false;
      }
    }
  }
  return true;
}

bool TrackProperties::IsMalformed() const {
  return MoqtProperties::IsMalformed() ||
         TotalCount(PropertyType::kPriorGroupIdGap) > 0 ||
         TotalCount(PropertyType::kPriorObjectIdGap) > 0;
}

bool ObjectProperties::IsMalformed() const {
  return MoqtProperties::IsMalformed() ||
         !CheckForUnknownMandatoryProperty().ok() ||
         TotalCount(PropertyType::kMaxCacheDuration) > 0 ||
         TotalCount(PropertyType::kDefaultPublisherPriority) > 0 ||
         TotalCount(PropertyType::kDefaultPublisherGroupOrder) > 0 ||
         TotalCount(PropertyType::kDynamicGroups) > 0;
}

}  // namespace moqt
