// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "http2/hpack/hpack_string.h"

#include <utility>

#include "absl/strings/str_cat.h"
#include "http2/platform/api/http2_logging.h"

namespace http2 {

HpackStringPair::HpackStringPair(std::string name, std::string value)
    : name(std::move(name)), value(std::move(value)) {
  HTTP2_DVLOG(3) << DebugString() << " ctor";
}

HpackStringPair::~HpackStringPair() {
  HTTP2_DVLOG(3) << DebugString() << " dtor";
}

std::string HpackStringPair::DebugString() const {
  return absl::StrCat("HpackStringPair(name=", name, ", value=", value, ")");
}

std::ostream& operator<<(std::ostream& os, const HpackStringPair& p) {
  os << p.DebugString();
  return os;
}

}  // namespace http2
