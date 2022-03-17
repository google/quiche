// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_PLATFORM_API_QUICHE_ERROR_CODE_WRAPPERS_H_
#define QUICHE_COMMON_PLATFORM_API_QUICHE_ERROR_CODE_WRAPPERS_H_

#include "quiche_platform_impl/quiche_error_code_wrappers_impl.h"

// TODO(vasilvv): ensure WRITE_STATUS_MSG_TOO_BIG works everywhere and remove
// this.
#define QUICHE_EMSGSIZE QUICHE_EMSGSIZE_IMPL

#endif  // QUICHE_COMMON_PLATFORM_API_QUICHE_ERROR_CODE_WRAPPERS_H_
