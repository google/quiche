// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_QUICHE_IOVEC_H_
#define QUICHE_COMMON_QUICHE_IOVEC_H_

#include <cstddef>
#include <type_traits>

#include "common/platform/api/quiche_export.h"

#if defined(_WIN32)

// See <https://pubs.opengroup.org/onlinepubs/009604599/basedefs/sys/uio.h.html>
struct QUICHE_EXPORT_PRIVATE iovec {
  void* iov_base;
  size_t iov_len;
};

#else

#include <sys/uio.h>  // IWYU pragma: export

#endif  // defined(_WIN32)

static_assert(std::is_standard_layout<struct iovec>::value,
              "iovec has to be a standard-layout struct");

static_assert(offsetof(struct iovec, iov_base) < sizeof(struct iovec),
              "iovec has to have iov_base");
static_assert(offsetof(struct iovec, iov_len) < sizeof(struct iovec),
              "iovec has to have iov_len");

#endif  // QUICHE_COMMON_QUICHE_IOVEC_H_
