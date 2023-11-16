// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/web_transport_headers.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/structured_headers.h"

namespace webtransport {

using ::quiche::structured_headers::ItemTypeToString;
using ::quiche::structured_headers::List;
using ::quiche::structured_headers::ParameterizedItem;
using ::quiche::structured_headers::ParameterizedMember;

absl::StatusOr<std::vector<std::string>> ParseSubprotocolRequestHeader(
    absl::string_view value) {
  std::optional<List> parsed = quiche::structured_headers::ParseList(value);
  if (!parsed.has_value()) {
    return absl::InvalidArgumentError(
        "Failed to parse the header as an sf-list");
  }

  std::vector<std::string> result;
  result.reserve(parsed->size());
  for (ParameterizedMember& member : *parsed) {
    if (member.member_is_inner_list || member.member.size() != 1) {
      return absl::InvalidArgumentError(
          "Expected all members to be tokens, found a nested list instead");
    }
    ParameterizedItem& item = member.member[0];
    if (!item.item.is_token()) {
      return absl::InvalidArgumentError(
          absl::StrCat("Expected all members to be tokens, found ",
                       ItemTypeToString(item.item.Type()), " instead"));
    }
    result.push_back(std::move(item).item.TakeString());
  }
  return result;
}

absl::StatusOr<std::string> SerializeSubprotocolRequestHeader(
    absl::Span<const std::string> subprotocols) {
  // Serialize tokens manually via a simple StrJoin call; this lets us provide
  // better error messages, and is probably more efficient too.
  for (const std::string& token : subprotocols) {
    if (!quiche::structured_headers::IsValidToken(token)) {
      return absl::InvalidArgumentError(absl::StrCat("Invalid token: ", token));
    }
  }
  return absl::StrJoin(subprotocols, ", ");
}

}  // namespace webtransport
