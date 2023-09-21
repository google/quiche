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

#ifndef THIRD_PARTY_ANONYMOUS_TOKENS_CPP_SHARED_PROTO_UTILS_H_
#define THIRD_PARTY_ANONYMOUS_TOKENS_CPP_SHARED_PROTO_UTILS_H_

#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "quiche/common/platform/api/quiche_export.h"
// copybara:strip_begin(internal comment)
// The QUICHE_EXPORT annotation is necessary for some classes and functions
// to link correctly on Windows. Please do not remove them!
// copybara:strip_end

namespace private_membership {
namespace anonymous_tokens {

// Returns AnonymousTokensUseCase parsed from a string_view.
absl::StatusOr<AnonymousTokensUseCase> QUICHE_EXPORT ParseUseCase(
    absl::string_view use_case);

// Takes in private_membership::anonymous_tokens::Timestamp and converts it to absl::Time.
//
// Timestamp is defined here:
// https://developers.google.com/protocol-buffers/docs/reference/private_membership.anonymous_tokens#timestamp
absl::StatusOr<absl::Time> QUICHE_EXPORT TimeFromProto(
    const private_membership::anonymous_tokens::Timestamp& proto);

// Takes in absl::Time and converts it to private_membership::anonymous_tokens::Timestamp.
//
// Timestamp is defined here:
// https://developers.google.com/protocol-buffers/docs/reference/private_membership.anonymous_tokens#timestamp
absl::StatusOr<private_membership::anonymous_tokens::Timestamp> QUICHE_EXPORT TimeToProto(
    absl::Time time);

}  // namespace anonymous_tokens
}  // namespace private_membership

#endif  // THIRD_PARTY_ANONYMOUS_TOKENS_CPP_SHARED_PROTO_UTILS_H_
