// Copyright (c) 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_TEST_TOOLS_QUICHE_TEST_UTILS_H_
#define QUICHE_COMMON_TEST_TOOLS_QUICHE_TEST_UTILS_H_

#include <string>

#include "absl/base/macros.h"
#include "absl/status/status_matchers.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_iovec.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace quiche {
namespace test {

void CompareCharArraysWithHexError(const std::string& description,
                                   const char* actual, int actual_len,
                                   const char* expected, int expected_len);

// Create iovec that points to that data that `str` points to.
iovec MakeIOVector(absl::string_view str);

// Due to binary size considerations, googleurl library can be built with or
// without IDNA support, meaning that we have to adjust our tests accordingly.
// This function checks if IDNAs are supported.
bool GoogleUrlSupportsIdnaForTest();

[[deprecated(
    "Use absl_testing::IsOk directly.")]] ABSL_REFACTOR_INLINE inline auto
IsOk() {
  return absl_testing::IsOk();
}

template <typename InnerMatcherT>
[[deprecated(
    "Use absl_testing::IsOkAndHolds "
    "directly.")]] ABSL_REFACTOR_INLINE inline auto
IsOkAndHolds(InnerMatcherT&& matcher) {
  return absl_testing::IsOkAndHolds(matcher);
}

template <typename InnerMatcherT>
[[deprecated(
    "Use absl_testing::StatusIs directly.")]] ABSL_REFACTOR_INLINE inline auto
StatusIs(InnerMatcherT&& matcher) {
  return absl_testing::StatusIs(matcher);
}

template <typename MatcherT, typename MessageT>
[[deprecated(
    "Use absl_testing::StatusIs directly.")]] ABSL_REFACTOR_INLINE inline auto
StatusIs(MatcherT&& matcher, MessageT&& message) {
  return absl_testing::StatusIs(matcher, message);
}

// We can't deprecate these directly, since they're macros.
#define QUICHE_EXPECT_OK(arg) EXPECT_THAT(arg, ::quiche::test::IsOk())
#define QUICHE_ASSERT_OK(arg) ASSERT_THAT(arg, ::quiche::test::IsOk())

}  // namespace test
}  // namespace quiche

#endif  // QUICHE_COMMON_TEST_TOOLS_QUICHE_TEST_UTILS_H_
