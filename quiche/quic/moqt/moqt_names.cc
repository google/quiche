// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_names.h"

#include <iterator>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"

namespace moqt {

TrackNamespace::TrackNamespace(absl::Span<const absl::string_view> elements)
    : tuple_(elements.begin(), elements.end()) {
  if (std::size(elements) > kMaxNamespaceElements) {
    tuple_.clear();
    QUICHE_BUG(Moqt_namespace_too_large_01)
        << "Constructing a namespace that is too large.";
    return;
  }
  for (auto it : elements) {
    length_ += it.size();
    if (length_ > kMaxFullTrackNameSize) {
      tuple_.clear();
      QUICHE_BUG(Moqt_namespace_too_large_02)
          << "Constructing a namespace that is too large.";
      return;
    }
  }
}

TrackNamespace::TrackNamespace(absl::Span<const std::string> elements)
    : tuple_(elements.begin(), elements.end()) {
  if (std::size(elements) > kMaxNamespaceElements) {
    tuple_.clear();
    QUICHE_BUG(Moqt_namespace_too_large_01)
        << "Constructing a namespace that is too large.";
    return;
  }
  for (const auto& it : elements) {
    length_ += it.size();
    if (length_ > kMaxFullTrackNameSize) {
      tuple_.clear();
      QUICHE_BUG(Moqt_namespace_too_large_02)
          << "Constructing a namespace that is too large.";
      return;
    }
  }
}

bool TrackNamespace::InNamespace(const TrackNamespace& other) const {
  if (tuple_.size() < other.tuple_.size()) {
    return false;
  }
  for (int i = 0; i < other.tuple_.size(); ++i) {
    if (tuple_[i] != other.tuple_[i]) {
      return false;
    }
  }
  return true;
}

void TrackNamespace::AddElement(absl::string_view element) {
  if (!CanAddElement(element)) {
    QUICHE_BUG(Moqt_namespace_too_large_03)
        << "Constructing a namespace that is too large.";
    return;
  }
  length_ += element.length();
  tuple_.push_back(std::string(element));
}

std::string TrackNamespace::ToString() const {
  std::vector<std::string> bits;
  bits.reserve(tuple_.size());
  for (absl::string_view raw_bit : tuple_) {
    bits.push_back(absl::StrCat("\"", absl::CHexEscape(raw_bit), "\""));
  }
  return absl::StrCat("{", absl::StrJoin(bits, "::"), "}");
}

FullTrackName::FullTrackName(absl::string_view ns, absl::string_view name)
    : namespace_(ns), name_(name) {
  QUICHE_BUG_IF(Moqt_full_track_name_too_large_01, !IsValid())
      << "Constructing a Full Track Name that is too large.";
}
FullTrackName::FullTrackName(TrackNamespace ns, absl::string_view name)
    : namespace_(ns), name_(name) {
  QUICHE_BUG_IF(Moqt_full_track_name_too_large_02, !IsValid())
      << "Constructing a Full Track Name that is too large.";
}

std::string FullTrackName::ToString() const {
  return absl::StrCat(namespace_.ToString(), "::", name_);
}
void FullTrackName::set_name(absl::string_view name) {
  QUICHE_BUG_IF(Moqt_name_too_large_03, !CanAddName(name))
      << "Setting a name that is too large.";
  name_ = name;
}

}  // namespace moqt
