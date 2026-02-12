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
#include "absl/strings/ascii.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"

namespace moqt {

namespace {

bool IsTrackNameSafeCharacter(char c) {
  return absl::ascii_isalnum(c) || c == '_';
}

// Appends escaped version of a track name component into `output`.  It is up to
// the caller to reserve() an appropriate amount of space in advance.  The text
// format is defined in
// https://www.ietf.org/archive/id/draft-ietf-moq-transport-16.html#name-representing-namespace-and-amount
void EscapeTrackNameComponent(absl::string_view input, std::string& output) {
  for (char c : input) {
    if (IsTrackNameSafeCharacter(c)) {
      output.push_back(c);
    } else {
      output.push_back('.');
      absl::StrAppend(&output, absl::Hex(c, absl::kZeroPad2));
    }
  }
}

// Similarly to the function above, the caller should call reserve() on `output`
// before calling.
void AppendEscapedTrackNameTuple(const MoqtStringTuple& tuple,
                                 std::string& output) {
  for (size_t i = 0; i < tuple.size(); ++i) {
    EscapeTrackNameComponent(tuple[i], output);
    if (i < (tuple.size() - 1)) {
      output.push_back('-');
    }
  }
}

}  // namespace

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
  std::string output;
  output.reserve(3 * tuple_.TotalBytes() + tuple_.size());
  AppendEscapedTrackNameTuple(tuple_, output);
  return output;
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
  if (namespace_.total_length() + name.size() > kMaxFullTrackNameSize) {
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
  std::string output;
  output.reserve(3 * namespace_.total_length() +
                 namespace_.number_of_elements() + 3 * name_.size() + 2);
  AppendEscapedTrackNameTuple(namespace_.tuple(), output);
  output.append("--");
  EscapeTrackNameComponent(name_, output);
  return output;
}

}  // namespace moqt
