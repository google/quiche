// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef THIRD_PARTY_ANONYMOUS_TOKENS_CPP_TESTING_TESTDATA_UTILS_H_
#define THIRD_PARTY_ANONYMOUS_TOKENS_CPP_TESTING_TESTDATA_UTILS_H_

#include <string>

#include "quiche/common/platform/api/quiche_test.h"

namespace anonymous_tokens {

// Note: This function is defined in a separate header so that other projects
// that use this library can easily provide their own implementation if the test
// data path is different.
inline std::string GetTestdataPath() {
  return quiche::test::QuicheGetCommonSourcePath();
}

}  // namespace anonymous_tokens

#endif  // THIRD_PARTY_ANONYMOUS_TOKENS_CPP_TESTING_TESTDATA_UTILS_H_
