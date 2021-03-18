// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_SPDY_CORE_HPACK_HPACK_ENTRY_H_
#define QUICHE_SPDY_CORE_HPACK_HPACK_ENTRY_H_

#include <cstddef>
#include <cstdint>
#include <string>
#include <utility>

#include "absl/strings/string_view.h"
#include "common/platform/api/quiche_export.h"

// All section references below are to
// http://tools.ietf.org/html/draft-ietf-httpbis-header-compression-08

namespace spdy {

// The constant amount added to name().size() and value().size() to
// get the size of an HpackEntry as defined in 5.1.
constexpr size_t kHpackEntrySizeOverhead = 32;

// A structure for looking up entries in the static and dynamic tables.
struct QUICHE_EXPORT_PRIVATE HpackLookupEntry {
  absl::string_view name;
  absl::string_view value;

  bool operator==(const HpackLookupEntry& other) const {
    return name == other.name && value == other.value;
  }

  // Abseil hashing framework extension according to absl/hash/hash.h:
  template <typename H>
  friend H AbslHashValue(H h, const HpackLookupEntry& entry) {
    return H::combine(std::move(h), entry.name, entry.value);
  }
};

// A structure for an entry in the static table (3.3.1)
// and the header table (3.3.2).
class QUICHE_EXPORT_PRIVATE HpackEntry {
 public:
  // Copies |name| and |value| in the constructor.
  // |insertion_index| is this entry's index in the total set of entries ever
  // inserted into the header table (including static entries).  This allows an
  // HpackEntryTable to determine the index of an HpackEntry in O(1) time.
  HpackEntry(absl::string_view name,
             absl::string_view value,
             size_t insertion_index);

  // Creates an entry with empty name and value. Only defined so that
  // entries can be stored in STL containers.
  HpackEntry();

  ~HpackEntry() = default;

  absl::string_view name() const { return name_; }
  absl::string_view value() const { return value_; }

  // Used to compute the entry's index in the header table.
  size_t InsertionIndex() const { return insertion_index_; }

  // Returns the size of an entry as defined in 5.1.
  static size_t Size(absl::string_view name, absl::string_view value);
  size_t Size() const;

  std::string GetDebugString() const;

  // Returns the estimate of dynamically allocated memory in bytes.
  size_t EstimateMemoryUsage() const;

 private:
  std::string name_;
  std::string value_;

  // The entry's index in the total set of entries ever inserted into the header
  // table.
  size_t insertion_index_;
};

}  // namespace spdy

#endif  // QUICHE_SPDY_CORE_HPACK_HPACK_ENTRY_H_
