// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_CODE_COUNT_READER_IMPL_H_
#define QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_CODE_COUNT_READER_IMPL_H_

#include <cstdint>

#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quiche::test {

// The default platform implements QUICHE_CODE_COUNT as a no-op, so there is
// nothing to read back.
class QUICHE_NO_EXPORT QuicheCodeCountReaderImpl {
 public:
  QuicheCodeCountReaderImpl() = default;
  QuicheCodeCountReaderImpl(const QuicheCodeCountReaderImpl&) = delete;
  QuicheCodeCountReaderImpl& operator=(const QuicheCodeCountReaderImpl&) =
      delete;

  static bool IsSupported() { return false; }
  int64_t Delta(absl::string_view /*name*/) { return 0; }
};

}  // namespace quiche::test

#endif  // QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_CODE_COUNT_READER_IMPL_H_
