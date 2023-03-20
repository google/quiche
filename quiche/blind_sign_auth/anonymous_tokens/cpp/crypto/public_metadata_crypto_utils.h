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

#ifndef THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_PUBLIC_METADATA_CRYPTO_UTILS_H_
#define THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_PUBLIC_METADATA_CRYPTO_UTILS_H_

#include <stddef.h>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace private_membership {
namespace anonymous_tokens {

// Internal functions only exposed for testing.
namespace public_metadata_crypto_utils_internal {

absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT PublicMetadataHashWithHKDF(
    absl::string_view input, absl::string_view rsa_modulus_str,
    size_t out_len_bytes);

}  // namespace public_metadata_crypto_utils_internal

// Compute exponent based only on the public metadata. Assumes that n is a safe
// modulus i.e. it produces a strong RSA key pair. If not, the exponent may be
// invalid.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT PublicMetadataExponent(
    const BIGNUM& n, absl::string_view public_metadata);

// Computes final exponent by multiplying the public exponent e with the
// exponent derived from public metadata. Assumes that n is a safe modulus i.e.
// it produces a strong RSA key pair. If not, the exponent may be invalid.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT ComputeFinalExponentUnderPublicMetadata(
    const BIGNUM& n, const BIGNUM& e, absl::string_view public_metadata);

// Converts AnonymousTokens RSAPublicKey to RSA under a fixed public_metadata.
//
// If the public_metadata is empty, this method doesn't modify the public
// exponent but instead simply outputs the RSA for the unmodified RSAPublicKey.
//
// TODO(b/271441409): Stop using RSA object from boringssl in
// AnonymousTokensService. Replace with a new internal struct.
absl::StatusOr<bssl::UniquePtr<RSA>> QUICHE_EXPORT RSAPublicKeyToRSAUnderPublicMetadata(
    const RSAPublicKey& public_key, absl::string_view public_metadata);

}  // namespace anonymous_tokens
}  // namespace private_membership

#endif  // THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_PUBLIC_METADATA_CRYPTO_UTILS_H_
