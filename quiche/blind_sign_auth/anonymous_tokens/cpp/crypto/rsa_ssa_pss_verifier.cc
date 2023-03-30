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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/rsa_ssa_pss_verifier.h"

#include <stdint.h>

#include <memory>
#include <string>
#include <utility>

#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/shared/status_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/bn.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {

absl::StatusOr<std::unique_ptr<RsaSsaPssVerifier>> RsaSsaPssVerifier::New(
    const int salt_length, const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
    const RSAPublicKey& public_key,
    std::optional<absl::string_view> public_metadata) {
  // Convert to OpenSSL RSA which will be used in the code paths for the
  // standard RSA blind signature scheme.
  //
  // Moreover, it will also be passed as an argument to PSS related padding
  // verification methods irrespective of whether RsaBlinder is being used as a
  // part of the standard RSA blind signature scheme or the scheme with public
  // metadata support.
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<RSA> rsa_public_key,
                               AnonymousTokensRSAPublicKeyToRSA(public_key));
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> rsa_modulus,
                               StringToBignum(public_key.n()));
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> rsa_e,
                               StringToBignum(public_key.e()));

  bssl::UniquePtr<BIGNUM> augmented_rsa_e = nullptr;
  // If public metadata is supported, RsaSsaPssVerifier will compute a new
  // public exponent using the public metadata.
  //
  // Empty string is a valid public metadata value.
  if (public_metadata.has_value()) {
    ANON_TOKENS_ASSIGN_OR_RETURN(
        augmented_rsa_e,
        ComputeFinalExponentUnderPublicMetadata(
            *rsa_modulus.get(), *rsa_e.get(), *public_metadata));
  } else {
    augmented_rsa_e = std::move(rsa_e);
  }
  return absl::WrapUnique(
      new RsaSsaPssVerifier(salt_length, public_metadata, sig_hash, mgf1_hash,
                            std::move(rsa_public_key), std::move(rsa_modulus),
                            std::move(augmented_rsa_e)));
}

RsaSsaPssVerifier::RsaSsaPssVerifier(
    int salt_length, std::optional<absl::string_view> public_metadata,
    const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
    bssl::UniquePtr<RSA> rsa_public_key, bssl::UniquePtr<BIGNUM> rsa_modulus,
    bssl::UniquePtr<BIGNUM> augmented_rsa_e)
    : salt_length_(salt_length),
      public_metadata_(public_metadata),
      sig_hash_(sig_hash),
      mgf1_hash_(mgf1_hash),
      rsa_public_key_(std::move(rsa_public_key)),
      rsa_modulus_(std::move(rsa_modulus)),
      augmented_rsa_e_(std::move(augmented_rsa_e)) {}

absl::Status RsaSsaPssVerifier::Verify(absl::string_view unblind_token,
                                       absl::string_view message) {
  std::string augmented_message(message);
  if (public_metadata_.has_value()) {
    augmented_message = EncodeMessagePublicMetadata(message, *public_metadata_);
  }
  ANON_TOKENS_ASSIGN_OR_RETURN(std::string message_digest,
                               ComputeHash(augmented_message, *sig_hash_));
  const int hash_size = EVP_MD_size(sig_hash_);
  // Make sure the size of the digest is correct.
  if (message_digest.size() != hash_size) {
    return absl::InvalidArgumentError(
        absl::StrCat("Size of the digest doesn't match the one "
                     "of the hashing algorithm; expected ",
                     hash_size, " got ", message_digest.size()));
  }
  const int rsa_modulus_size = BN_num_bytes(rsa_modulus_.get());
  if (unblind_token.size() != rsa_modulus_size) {
    return absl::InternalError("Signature size not equal to modulus size.");
  }

  std::string recovered_message_digest(rsa_modulus_size, 0);
  if (!public_metadata_.has_value()) {
    int recovered_message_digest_size = RSA_public_decrypt(
        /*flen=*/unblind_token.size(),
        /*from=*/reinterpret_cast<const uint8_t*>(unblind_token.data()),
        /*to=*/
        reinterpret_cast<uint8_t*>(recovered_message_digest.data()),
        /*rsa=*/rsa_public_key_.get(),
        /*padding=*/RSA_NO_PADDING);
    if (recovered_message_digest_size != rsa_modulus_size) {
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid signature size (likely an incorrect key is "
                       "used); expected ",
                       rsa_modulus_size, " got ", recovered_message_digest_size,
                       ": ", GetSslErrors()));
    }
  } else {
    ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> unblind_token_bn,
                                 StringToBignum(unblind_token));
    if (BN_ucmp(unblind_token_bn.get(), rsa_modulus_.get()) >= 0) {
      return absl::InternalError("Data too large for modulus.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(BnCtxPtr bn_ctx, GetAndStartBigNumCtx());
    bssl::UniquePtr<BN_MONT_CTX> bn_mont_ctx(
        BN_MONT_CTX_new_for_modulus(rsa_modulus_.get(), bn_ctx.get()));
    if (!bn_mont_ctx) {
      return absl::InternalError("BN_MONT_CTX_new_for_modulus failed.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(
        bssl::UniquePtr<BIGNUM> recovered_message_digest_bn, NewBigNum());
    if (BN_mod_exp_mont(recovered_message_digest_bn.get(),
                        unblind_token_bn.get(), augmented_rsa_e_.get(),
                        rsa_modulus_.get(), bn_ctx.get(),
                        bn_mont_ctx.get()) != kBsslSuccess) {
      return absl::InternalError("Exponentiation failed.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(
        recovered_message_digest,
        BignumToString(*recovered_message_digest_bn, rsa_modulus_size));
  }
  if (RSA_verify_PKCS1_PSS_mgf1(
          rsa_public_key_.get(),
          reinterpret_cast<const uint8_t*>(&message_digest[0]), sig_hash_,
          mgf1_hash_,
          reinterpret_cast<const uint8_t*>(recovered_message_digest.data()),
          salt_length_) != kBsslSuccess) {
    return absl::InvalidArgumentError(
        absl::StrCat("PSS padding verification failed: ", GetSslErrors()));
  }
  return absl::OkStatus();
}

}  // namespace anonymous_tokens
}  // namespace private_membership
