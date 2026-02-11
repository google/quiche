// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_names.h"

#include <cstddef>
#include <initializer_list>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"

namespace moqt {

absl::StatusOr<TrackNamespace> TrackNamespace::Create(MoqtStringTuple tuple) {
  if (tuple.size() > kMaxNamespaceElements) {
    return absl::OutOfRangeError(
        absl::StrFormat("Tuple has %d elements, whereas MOQT only allows %d",
                        tuple.size(), kMaxNamespaceElements));
  }
  return TrackNamespace(std::move(tuple));
}

TrackNamespace::TrackNamespace(std::initializer_list<absl::string_view> tuple) {
  bool success = tuple_.Append(tuple);
  if (!success) {
    QUICHE_BUG(TrackNamespace_constructor)
        << "Invalid namespace supplied to the TrackNamspace constructor";
    tuple_ = MoqtStringTuple();
    return;
  }
}

bool TrackNamespace::InNamespace(const TrackNamespace& other) const {
  return tuple_.IsPrefix(other.tuple_);
}

bool TrackNamespace::AddElement(absl::string_view element) {
  if (tuple_.size() >= kMaxNamespaceElements) {
    return false;
  }
  return tuple_.Add(element);
}
bool TrackNamespace::PopElement() {
  if (tuple_.empty()) {
    return false;
  }
  return tuple_.Pop();
}

std::string TrackNamespace::ToString() const {
  // TODO(vasilvv): switch to the standard encoding.
  return absl::StrCat(tuple_);
}

absl::StatusOr<FullTrackName> FullTrackName::Create(TrackNamespace ns,
                                                    std::string name) {
  const size_t total_length = ns.total_length() + name.size();
  if (ns.total_length() + name.size() > kMaxFullTrackNameSize) {
    return absl::OutOfRangeError(
        absl::StrFormat("Attempting to create a full track name of size %d, "
                        "whereas at most %d bytes are allowed by the protocol",
                        total_length, kMaxFullTrackNameSize));
  }
  return FullTrackName(std::move(ns), std::move(name),
                       FullTrackNameIsValidTag());
}

FullTrackName::FullTrackName(TrackNamespace ns, absl::string_view name)
    : namespace_(std::move(ns)), name_(name) {
  if (namespace_.total_length() + name.size() > kMaxFullTrackNameSize) {
    QUICHE_BUG(Moqt_full_track_name_too_large_01)
        << "Constructing a Full Track Name that is too large.";
    namespace_.Clear();
    name_.clear();
  }
}
FullTrackName::FullTrackName(absl::string_view ns, absl::string_view name)
    : namespace_(TrackNamespace({ns})), name_(name) {
  if (ns.size() + name.size() > kMaxFullTrackNameSize) {
    QUICHE_BUG(Moqt_full_track_name_too_large_02)
        << "Constructing a Full Track Name that is too large.";
    namespace_.Clear();
    name_.clear();
  }
}
FullTrackName::FullTrackName(std::initializer_list<absl::string_view> ns,
                             absl::string_view name)
    : namespace_(ns), name_(name) {
  if (namespace_.total_length() + name.size() > kMaxFullTrackNameSize) {
    QUICHE_BUG(Moqt_full_track_name_too_large_03)
        << "Constructing a Full Track Name that is too large.";
    namespace_.Clear();
    name_.clear();
  }
}

FullTrackName::FullTrackName(TrackNamespace ns, std::string name,
                             FullTrackNameIsValidTag)
    : namespace_(std::move(ns)), name_(std::move(name)) {}

std::string FullTrackName::ToString() const {
  // TODO(vasilvv): switch to the standard encoding.
  return absl::StrCat(namespace_.ToString(), "::", name_);
}

}  // namespace moqt
