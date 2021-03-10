// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_SPDY_PLATFORM_API_SPDY_BUG_TRACKER_H_
#define QUICHE_SPDY_PLATFORM_API_SPDY_BUG_TRACKER_H_

#include "net/spdy/platform/impl/spdy_bug_tracker_impl.h"

#define SPDY_BUG SPDY_BUG_IMPL
#define SPDY_BUG_IF(condition) SPDY_BUG_IF_IMPL(condition)

// V2 macros are the same as all the SPDY_BUG flavor above, but they take a
// bug_id parameter.
#define SPDY_BUG_V2 SPDY_BUG_V2_IMPL
#define SPDY_BUG_IF_V2 SPDY_BUG_IF_V2_IMPL

#define FLAGS_spdy_always_log_bugs_for_tests \
  FLAGS_spdy_always_log_bugs_for_tests_impl

#endif  // QUICHE_SPDY_PLATFORM_API_SPDY_BUG_TRACKER_H_
