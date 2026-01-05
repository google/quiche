// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_NAMES_H_
#define QUICHE_QUIC_MOQT_MOQT_NAMES_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"

namespace moqt {

// Protocol-specified limits on the length and structure of MoQT namespaces.
inline constexpr uint64_t kMinNamespaceElements = 1;
inline constexpr uint64_t kMaxNamespaceElements = 32;
inline constexpr size_t kMaxFullTrackNameSize = 1024;

class TrackNamespace {
 public:
  explicit TrackNamespace(absl::Span<const absl::string_view> elements);
  explicit TrackNamespace(
      std::initializer_list<const absl::string_view> elements)
      : TrackNamespace(absl::Span<const absl::string_view>(
            std::data(elements), std::size(elements))) {}
  explicit TrackNamespace(absl::string_view ns) : TrackNamespace({ns}) {}
  TrackNamespace() : TrackNamespace({}) {}

  bool IsValid() const {
    return !tuple_.empty() && tuple_.size() <= kMaxNamespaceElements &&
           length_ <= kMaxFullTrackNameSize;
  }
  bool InNamespace(const TrackNamespace& other) const;
  // Check if adding an element will exceed limits, without triggering a
  // bug. Useful for the parser, which has to be robust to malformed data.
  bool CanAddElement(absl::string_view element) {
    return (tuple_.size() < kMaxNamespaceElements &&
            length_ + element.length() <= kMaxFullTrackNameSize);
  }
  void AddElement(absl::string_view element);
  bool PopElement() {
    if (tuple_.size() == 1) {
      return false;
    }
    length_ -= tuple_.back().length();
    tuple_.pop_back();
    return true;
  }
  std::string ToString() const;
  // Returns the number of elements in the tuple.
  size_t number_of_elements() const { return tuple_.size(); }
  // Returns the sum of the lengths of all elements in the tuple.
  size_t total_length() const { return length_; }

  auto operator<=>(const TrackNamespace& other) const {
    return std::lexicographical_compare_three_way(
        tuple_.cbegin(), tuple_.cend(), other.tuple_.cbegin(),
        other.tuple_.cend());
  }
  bool operator==(const TrackNamespace&) const = default;

  const std::vector<std::string>& tuple() const { return tuple_; }

  template <typename H>
  friend H AbslHashValue(H h, const TrackNamespace& m) {
    return H::combine(std::move(h), m.tuple_);
  }
  template <typename Sink>
  friend void AbslStringify(Sink& sink, const TrackNamespace& track_namespace) {
    sink.Append(track_namespace.ToString());
  }

 private:
  std::vector<std::string> tuple_;
  size_t length_ = 0;  // size in bytes.
};

class FullTrackName {
 public:
  FullTrackName(absl::string_view ns, absl::string_view name);
  FullTrackName(TrackNamespace ns, absl::string_view name);
  FullTrackName() = default;

  bool IsValid() const {
    return namespace_.IsValid() && length() <= kMaxFullTrackNameSize;
  }
  const TrackNamespace& track_namespace() const { return namespace_; }
  TrackNamespace& track_namespace() { return namespace_; }
  absl::string_view name() const { return name_; }
  void AddElement(absl::string_view element) {
    return namespace_.AddElement(element);
  }
  std::string ToString() const;
  // Check if the name will exceed limits, without triggering a bug. Useful for
  // the parser, which has to be robust to malformed data.
  bool CanAddName(absl::string_view name) {
    return (namespace_.total_length() + name.length() <= kMaxFullTrackNameSize);
  }
  void set_name(absl::string_view name);
  size_t length() const { return namespace_.total_length() + name_.length(); }

  auto operator<=>(const FullTrackName&) const = default;
  template <typename H>
  friend H AbslHashValue(H h, const FullTrackName& m) {
    return H::combine(std::move(h), m.namespace_.tuple(), m.name_);
  }
  template <typename Sink>
  friend void AbslStringify(Sink& sink, const FullTrackName& full_track_name) {
    sink.Append(full_track_name.ToString());
  }

 private:
  TrackNamespace namespace_;
  std::string name_ = "";
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_NAMES_H_
