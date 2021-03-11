// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_HTTP2_HPACK_HPACK_STRING_H_
#define QUICHE_HTTP2_HPACK_HPACK_STRING_H_

#include <stddef.h>

#include <iosfwd>
#include <string>

#include "absl/strings/string_view.h"
#include "common/platform/api/quiche_export.h"

namespace http2 {

struct QUICHE_EXPORT_PRIVATE HpackStringPair {
  HpackStringPair(std::string name, std::string value);
  ~HpackStringPair();

  // Returns the size of a header entry with this name and value, per the RFC:
  // http://httpwg.org/specs/rfc7541.html#calculating.table.size
  size_t size() const { return 32 + name.size() + value.size(); }

  std::string DebugString() const;

  const std::string name;
  const std::string value;
};

QUICHE_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                               const HpackStringPair& p);

}  // namespace http2

#endif  // QUICHE_HTTP2_HPACK_HPACK_STRING_H_
