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

#ifndef THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_CRYPTO_UTILS_H_
#define THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_CRYPTO_UTILS_H_

#include <stddef.h>

#include <memory>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/bn.h"
#include "openssl/evp.h"
// #include "quiche/common/platform/api/quiche_export.h"

namespace private_membership {
namespace anonymous_tokens {

// Deletes a BN_CTX.
class BnCtxDeleter {
 public:
  void operator()(BN_CTX* ctx) { BN_CTX_free(ctx); }
};
typedef std::unique_ptr<BN_CTX, BnCtxDeleter> BnCtxPtr;

// Deletes a BN_MONT_CTX.
class BnMontCtxDeleter {
 public:
  void operator()(BN_MONT_CTX* mont_ctx) { BN_MONT_CTX_free(mont_ctx); }
};
typedef std::unique_ptr<BN_MONT_CTX, BnMontCtxDeleter> BnMontCtxPtr;

// Deletes an EVP_MD_CTX.
class EvpMdCtxDeleter {
 public:
  void operator()(EVP_MD_CTX* ctx) { EVP_MD_CTX_destroy(ctx); }
};
typedef std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter> EvpMdCtxPtr;

// Creates and starts a BIGNUM context.
absl::StatusOr<BnCtxPtr> QUICHE_EXPORT GetAndStartBigNumCtx();

// Creates a new BIGNUM.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT NewBigNum();

// Converts a BIGNUM to string.
absl::StatusOr<std::string> QUICHE_EXPORT BignumToString(
    const BIGNUM& big_num, size_t output_len);

// Converts a string to BIGNUM.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT StringToBignum(
    absl::string_view input_str);

// Retrieve error messages from OpenSSL.
std::string QUICHE_EXPORT GetSslErrors();

// Mask message using protocol at
// https://datatracker.ietf.org/doc/draft-irtf-cfrg-rsa-blind-signatures/
std::string MaskMessageConcat(absl::string_view mask,
                              absl::string_view message);

// Compute 2^(x - 1/2).
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT GetRsaSqrtTwo(
    int x);

// Compute compute 2^x.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT ComputePowerOfTwo(
    int x);

// ComputeHash sub-routine used druing blindness and verification of RSA PSS
// AnonymousTokens.
absl::StatusOr<std::string> QUICHE_EXPORT ComputeHash(
    absl::string_view input, const EVP_MD& hasher);

// Computes the Carmichael LCM given phi(p) and phi(q) where N = pq is a safe
// RSA modulus.
absl::StatusOr<bssl::UniquePtr<BIGNUM>> QUICHE_EXPORT
ComputeCarmichaelLcm(const BIGNUM& phi_p, const BIGNUM& phi_q, BN_CTX& bn_ctx);

// Converts AnonymousTokens::RSAPrivateKey To bssl::UniquePtr<RSA>
absl::StatusOr<bssl::UniquePtr<RSA>> QUICHE_EXPORT
AnonymousTokensRSAPrivateKeyToRSA(const RSAPrivateKey& private_key);

}  // namespace anonymous_tokens
}  // namespace private_membership

#endif  // THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_CRYPTO_UTILS_H_
