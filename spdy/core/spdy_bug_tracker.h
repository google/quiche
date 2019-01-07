// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_SPDY_CORE_SPDY_BUG_TRACKER_H_
#define QUICHE_SPDY_CORE_SPDY_BUG_TRACKER_H_

// Defined in Blaze when targetting non-production platforms (iOS, Android, etc)
// The fallback implimentation is the same as in Chromium which simply delegates
// to LOG(DFATAL) which is part of PG3.
#if SPDY_GENERIC_BUG

#define SPDY_BUG LOG(DFATAL)
#define SPDY_BUG_IF(condition) LOG_IF(DFATAL, condition)
#define FLAGS_spdy_always_log_bugs_for_tests true

#else

#include "gfe/gfe2/base/bug_utils.h"

// For external SPDY, SPDY_BUG should be #defined to LOG(DFATAL) and
// SPDY_BUG_IF(condition) to LOG_IF(DFATAL, condition) as client-side log rate
// limiting is less important and chrome doesn't LOG_FIRST_N anyway.
//
// This file should change infrequently if ever, so update cost should be
// minimal. Meanwhile we do want different macros so we can rate limit server
// side, so the google3 shared code increments GFE varz, and chrome can have its
// own custom hooks.
#define SPDY_BUG GFE_BUG
#define SPDY_BUG_IF GFE_BUG_IF
#define FLAGS_spdy_always_log_bugs_for_tests FLAGS_gfe_always_log_bug_for_tests

#endif  // __ANDROID__

#endif  // QUICHE_SPDY_CORE_SPDY_BUG_TRACKER_H_
