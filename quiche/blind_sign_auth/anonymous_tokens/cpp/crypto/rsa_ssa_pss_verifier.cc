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
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {

absl::StatusOr<std::unique_ptr<RsaSsaPssVerifier>> RsaSsaPssVerifier::New(
    const RSAPublicKey& rsa_public_key, const EVP_MD* sig_hash,
    const EVP_MD* mgf1_hash, const int salt_length,
    absl::string_view public_metadata) {
  ANON_TOKENS_ASSIGN_OR_RETURN(
      bssl::UniquePtr<RSA> rsa,
      RSAPublicKeyToRSAUnderPublicMetadata(rsa_public_key, public_metadata));
  return absl::WrapUnique(new RsaSsaPssVerifier(
      std::move(rsa), sig_hash, mgf1_hash, salt_length, public_metadata));
}

RsaSsaPssVerifier::RsaSsaPssVerifier(bssl::UniquePtr<RSA> public_key,
                                     const EVP_MD* sig_hash,
                                     const EVP_MD* mgf1_hash,
                                     int32_t salt_length,
                                     absl::string_view public_metadata)
    : public_key_(std::move(public_key)),
      sig_hash_(sig_hash),
      mgf1_hash_(mgf1_hash),
      salt_length_(salt_length),
      public_metadata_(public_metadata) {}

absl::Status RsaSsaPssVerifier::Verify(absl::string_view unblind_token,
                                       absl::string_view message) {
  if (message.empty()) {
    return absl::InvalidArgumentError("Input message string is empty.");
  }

  ANON_TOKENS_ASSIGN_OR_RETURN(std::string message_digest,
                               ComputeHash(message, *sig_hash_));
  const int kHashSize = EVP_MD_size(sig_hash_);
  // Make sure the size of the digest is correct.
  if (message_digest.size() != kHashSize) {
    return absl::InvalidArgumentError(
        absl::StrCat("Size of the digest doesn't match the one "
                     "of the hashing algorithm; expected ",
                     kHashSize, " got ", message_digest.size()));
  }
  const int kRsaModulusSize = RSA_size(public_key_.get());
  if (unblind_token.size() != kRsaModulusSize) {
    return absl::InternalError("Signature size not equal to modulus size.");
  }

  std::string recovered_message_digest(kRsaModulusSize, 0);
  if (public_metadata_.empty()) {
    int recovered_message_digest_size = RSA_public_decrypt(
        /*flen=*/unblind_token.size(),
        /*from=*/reinterpret_cast<const uint8_t*>(unblind_token.data()),
        /*to=*/
        reinterpret_cast<uint8_t*>(recovered_message_digest.data()),
        /*rsa=*/public_key_.get(),
        /*padding=*/RSA_NO_PADDING);
    if (recovered_message_digest_size != kRsaModulusSize) {
      return absl::InvalidArgumentError(
          absl::StrCat("Invalid signature size (likely an incorrect key is "
                       "used); expected ",
                       kRsaModulusSize, " got ", recovered_message_digest_size,
                       ": ", GetSslErrors()));
    }
  } else {
    ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> unblind_token_bn,
                                 StringToBignum(unblind_token));
    if (BN_ucmp(unblind_token_bn.get(), RSA_get0_n(public_key_.get())) >= 0) {
      return absl::InternalError("Data too large for modulus.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(BnCtxPtr bn_ctx, GetAndStartBigNumCtx());
    bssl::UniquePtr<BN_MONT_CTX> bn_mont_ctx(BN_MONT_CTX_new_for_modulus(
        RSA_get0_n(public_key_.get()), bn_ctx.get()));
    if (!bn_mont_ctx) {
      return absl::InternalError("BN_MONT_CTX_new_for_modulus failed.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(
        bssl::UniquePtr<BIGNUM> recovered_message_digest_bn, NewBigNum());
    if (BN_mod_exp_mont(recovered_message_digest_bn.get(),
                        unblind_token_bn.get(), RSA_get0_e(public_key_.get()),
                        RSA_get0_n(public_key_.get()), bn_ctx.get(),
                        bn_mont_ctx.get()) != kBsslSuccess) {
      return absl::InternalError("Exponentiation failed.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(
        recovered_message_digest,
        BignumToString(*recovered_message_digest_bn, kRsaModulusSize));
  }
  if (RSA_verify_PKCS1_PSS_mgf1(
          public_key_.get(),
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
