// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_PLATFORM_API_QUICHE_CODE_COUNT_READER_H_
#define QUICHE_COMMON_PLATFORM_API_QUICHE_CODE_COUNT_READER_H_

#include <cstdint>

#include "quiche_platform_impl/quiche_code_count_reader_impl.h"

#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quiche::test {

// Test-only helper for verifying that QUICHE_CODE_COUNT(name) was hit.
//
// QUICHE_CODE_COUNT is a no-op on many platforms (e.g. Chromium, Envoy and the
// default platform implementation). On those platforms IsSupported() returns
// false, and Delta() must not be called. Tests should check IsSupported()
// before querying code counts.
class QUICHE_NO_EXPORT QuicheCodeCountReader {
 public:
  QuicheCodeCountReader() = default;
  QuicheCodeCountReader(const QuicheCodeCountReader&) = delete;
  QuicheCodeCountReader& operator=(const QuicheCodeCountReader&) = delete;

  // Returns true if the platform records QUICHE_CODE_COUNT invocations and the
  // values returned by Delta() are meaningful.
  static bool IsSupported() { return QuicheCodeCountReaderImpl::IsSupported(); }

  // Returns the number of times QUICHE_CODE_COUNT(name) (or QUICHE_CODE_COUNT_N
  // when passed the full name such as "name_1_of_2") has fired since this
  // reader was constructed, or since the previous call to Delta() with the
  // same `name`, whichever is later. Returns 0 if the code point was never hit.
  // Must not be called when IsSupported() returns false.
  int64_t Delta(absl::string_view name) { return impl_.Delta(name); }

 private:
  QuicheCodeCountReaderImpl impl_;
};

}  // namespace quiche::test

#endif  // QUICHE_COMMON_PLATFORM_API_QUICHE_CODE_COUNT_READER_H_
