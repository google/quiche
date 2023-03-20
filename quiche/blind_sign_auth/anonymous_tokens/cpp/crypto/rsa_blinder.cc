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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/rsa_blinder.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/public_metadata_crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/status_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/digest.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {

absl::StatusOr<std::unique_ptr<RsaBlinder>> RsaBlinder::New(
    const RSABlindSignaturePublicKey& public_key,
    absl::string_view public_metadata) {
  RSAPublicKey rsa_public_key_proto;
  if (!rsa_public_key_proto.ParseFromString(
          public_key.serialized_public_key())) {
    return absl::InvalidArgumentError("Public key is malformed.");
  }

  // Convert to OpenSSL RSA.
  //
  // If public metadata is empty, RSAPublicKeyToRSAUnderPublicMetadata returns
  // bssl::UniquePtr<RSA> valid for no public metadata.
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<RSA> rsa_public_key,
                               RSAPublicKeyToRSAUnderPublicMetadata(
                                   rsa_public_key_proto, public_metadata));

  // Owned by BoringSSL.
  const EVP_MD* sig_hash;
  if (public_key.sig_hash_type() == AT_HASH_TYPE_SHA256) {
    sig_hash = EVP_sha256();
  } else if (public_key.sig_hash_type() == AT_HASH_TYPE_SHA384) {
    sig_hash = EVP_sha384();
  } else {
    return absl::InvalidArgumentError("Signature hash type is not safe.");
  }

  // Owned by BoringSSL.
  const EVP_MD* mgf1_hash;
  if (public_key.mask_gen_function() == AT_MGF_SHA256) {
    mgf1_hash = EVP_sha256();
  } else if (public_key.mask_gen_function() == AT_MGF_SHA384) {
    mgf1_hash = EVP_sha384();
  } else {
    return absl::InvalidArgumentError("Mask generation function is not safe.");
  }

  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> r, NewBigNum());
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> r_inv_mont, NewBigNum());

  // Limit r between [2, n) so that an r of 1 never happens. An r of 1 doesn't
  // blind.
  if (BN_rand_range_ex(r.get(), 2, RSA_get0_n(rsa_public_key.get())) !=
      kBsslSuccess) {
    return absl::InternalError(
        "BN_rand_range_ex failed when called from RsaBlinder::New.");
  }

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    return absl::InternalError("BN_CTX_new failed.");
  }

  bssl::UniquePtr<BN_MONT_CTX> bn_mont_ctx(BN_MONT_CTX_new_for_modulus(
      RSA_get0_n(rsa_public_key.get()), bn_ctx.get()));
  if (!bn_mont_ctx) {
    return absl::InternalError("BN_MONT_CTX_new_for_modulus failed.");
  }

  // We wish to compute r^-1 in the Montgomery domain, or r^-1 R mod n. This is
  // can be done with BN_mod_inverse_blinded followed by BN_to_montgomery, but
  // it is equivalent and slightly more efficient to first compute r R^-1 mod n
  // with BN_from_montgomery, and then inverting that to give r^-1 R mod n.
  int is_r_not_invertible = 0;
  if (BN_from_montgomery(r_inv_mont.get(), r.get(), bn_mont_ctx.get(),
                         bn_ctx.get()) != kBsslSuccess ||
      BN_mod_inverse_blinded(r_inv_mont.get(), &is_r_not_invertible,
                             r_inv_mont.get(), bn_mont_ctx.get(),
                             bn_ctx.get()) != kBsslSuccess) {
    return absl::InternalError(
        absl::StrCat("BN_mod_inverse failed when called from RsaBlinder::New, "
                     "is_r_not_invertible = ",
                     is_r_not_invertible));
  }

  return absl::WrapUnique(new RsaBlinder(
      std::move(r), std::move(r_inv_mont), std::move(rsa_public_key),
      std::move(bn_mont_ctx), sig_hash, mgf1_hash, public_key.salt_length(),
      public_metadata));
}

RsaBlinder::RsaBlinder(bssl::UniquePtr<BIGNUM> r,
                       bssl::UniquePtr<BIGNUM> r_inv_mont,
                       bssl::UniquePtr<RSA> public_key,
                       bssl::UniquePtr<BN_MONT_CTX> mont_n,
                       const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
                       int32_t salt_length, absl::string_view public_metadata)
    : r_(std::move(r)),
      r_inv_mont_(std::move(r_inv_mont)),
      public_key_(std::move(public_key)),
      mont_n_(std::move(mont_n)),
      sig_hash_(sig_hash),
      mgf1_hash_(mgf1_hash),
      salt_length_(salt_length),
      public_metadata_(public_metadata),
      message_(""),
      blinder_state_(RsaBlinder::BlinderState::kCreated) {}

absl::StatusOr<std::string> RsaBlinder::Blind(const absl::string_view message) {
  // Check that the blinder state was kCreated
  if (blinder_state_ != RsaBlinder::BlinderState::kCreated) {
    return absl::FailedPreconditionError(
        "RsaBlinder is in wrong state to blind message.");
  }

  if (message.empty()) {
    return absl::InvalidArgumentError("Input message string is empty.");
  }
  ANON_TOKENS_ASSIGN_OR_RETURN(std::string digest_str,
                               ComputeHash(message, *sig_hash_));
  std::vector<uint8_t> digest(digest_str.begin(), digest_str.end());

  // Construct the PSS padded message, using the same workflow as BoringSSL's
  // RSA_sign_pss_mgf1 for processing the message (but not signing the message):
  // google3/third_party/openssl/boringssl/src/crypto/fipsmodule/rsa/rsa.c?l=557
  if (digest.size() != EVP_MD_size(sig_hash_)) {
    return absl::InternalError("Invalid input message length.");
  }

  // Allocate for padded length
  const int padded_len = RSA_size(public_key_.get());
  std::vector<uint8_t> padded(padded_len);

  // The |md| and |mgf1_md| arguments identify the hash used to calculate
  // |digest| and the MGF1 hash, respectively. If |mgf1_md| is NULL, |md| is
  // used. |salt_len| specifies the expected salt length in bytes. If |salt_len|
  // is -1, then the salt length is the same as the hash length. If -2, then the
  // salt length is maximal given the size of |rsa|. If unsure, use -1.
  if (RSA_padding_add_PKCS1_PSS_mgf1(
          /*rsa=*/public_key_.get(), /*EM=*/padded.data(),
          /*mHash=*/digest.data(), /*Hash=*/sig_hash_, /*mgf1Hash=*/mgf1_hash_,
          /*sLen=*/salt_length_) != kBsslSuccess) {
    return absl::InternalError(
        "RSA_padding_add_PKCS1_PSS_mgf1 failed when called from "
        "RsaBlinder::Blind");
  }

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    return absl::InternalError("BN_CTX_new failed.");
  }

  std::string encoded_message(padded.begin(), padded.end());
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> encoded_message_bn,
                               StringToBignum(encoded_message));

  // Take `r^e mod n`. This is an equivalent operation to RSA_encrypt, without
  // extra encode/decode trips.
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> rE, NewBigNum());
  if (BN_mod_exp_mont(rE.get(), r_.get(), RSA_get0_e(public_key_.get()),
                      RSA_get0_n(public_key_.get()), bn_ctx.get(),
                      mont_n_.get()) != kBsslSuccess) {
    return absl::InternalError(
        "BN_mod_exp_mont failed when called from RsaBlinder::Blind.");
  }

  // Do `encoded_message*r^e mod n`.
  //
  // To avoid leaking side channels, we use Montgomery reduction. This would be
  // FromMontgomery(ModMulMontgomery(ToMontgomery(m), ToMontgomery(r^e))).
  // However, this is equivalent to ModMulMontgomery(m, ToMontgomery(r^e)).
  // Each BN_mod_mul_montgomery removes a factor of R, so by having only one
  // input in the Montgomery domain, we save a To/FromMontgomery pair.
  //
  // Internally, BN_mod_exp_mont actually computes r^e in the Montgomery domain
  // and converts it out, but there is no public API for this, so we perform an
  // extra conversion.
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> multiplication_res,
                               NewBigNum());
  if (BN_to_montgomery(multiplication_res.get(), rE.get(), mont_n_.get(),
                       bn_ctx.get()) != kBsslSuccess ||
      BN_mod_mul_montgomery(multiplication_res.get(), encoded_message_bn.get(),
                            multiplication_res.get(), mont_n_.get(),
                            bn_ctx.get()) != kBsslSuccess) {
    return absl::InternalError(
        "BN_mod_mul failed when called from RsaBlinder::Blind.");
  }

  absl::StatusOr<std::string> blinded_msg = BignumToString(
      *multiplication_res, BN_num_bytes(RSA_get0_n(public_key_.get())));

  // Update RsaBlinder state to kBlinded
  blinder_state_ = RsaBlinder::BlinderState::kBlinded;

  return blinded_msg;
}

// Unblinds `blind_signature`.
absl::StatusOr<std::string> RsaBlinder::Unblind(
    const absl::string_view blind_signature) {
  if (blinder_state_ != RsaBlinder::BlinderState::kBlinded) {
    return absl::FailedPreconditionError(
        "RsaBlinder is in wrong state to unblind signature.");
  }
  const size_t mod_size = RSA_size(public_key_.get());
  // Parse the signed_blinded_data as BIGNUM.
  if (blind_signature.size() != mod_size) {
    return absl::InternalError(absl::StrCat(
        "Expected blind signature size = ", mod_size,
        " actual blind signature size = ", blind_signature.size(), " bytes."));
  }

  bssl::UniquePtr<BN_CTX> bn_ctx(BN_CTX_new());
  if (!bn_ctx) {
    return absl::InternalError("BN_CTX_new failed.");
  }

  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> signed_big_num,
                               StringToBignum(blind_signature));
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> unblinded_sig_big,
                               NewBigNum());
  // Do `signed_message*r^-1 mod n`.
  //
  // To avoid leaking side channels, we use Montgomery reduction. This would be
  // FromMontgomery(ModMulMontgomery(ToMontgomery(m), ToMontgomery(r^-1))).
  // However, this is equivalent to ModMulMontgomery(m, ToMontgomery(r^-1)).
  // Each BN_mod_mul_montgomery removes a factor of R, so by having only one
  // input in the Montgomery domain, we save a To/FromMontgomery pair.
  if (BN_mod_mul_montgomery(unblinded_sig_big.get(), signed_big_num.get(),
                            r_inv_mont_.get(), mont_n_.get(),
                            bn_ctx.get()) != kBsslSuccess) {
    return absl::InternalError(
        "BN_mod_mul failed when called from RsaBlinder::Unblind.");
  }
  absl::StatusOr<std::string> unblinded_signed_message = BignumToString(
      *unblinded_sig_big,
      /*output_len=*/BN_num_bytes(RSA_get0_n(public_key_.get())));
  blinder_state_ = RsaBlinder::BlinderState::kUnblinded;
  return unblinded_signed_message;
}

absl::Status RsaBlinder::Verify(absl::string_view signature,
                                absl::string_view message) {
  if (message.empty()) {
    return absl::InvalidArgumentError("Input message string is empty.");
  }
  ANON_TOKENS_ASSIGN_OR_RETURN(std::string message_digest,
                               ComputeHash(message, *sig_hash_));

  const size_t kHashSize = EVP_MD_size(sig_hash_);
  // Make sure the size of the digest is correct.
  if (message_digest.size() != kHashSize) {
    return absl::InvalidArgumentError(
        absl::StrCat("Size of the digest doesn't match the one "
                     "of the hashing algorithm; expected ",
                     kHashSize, " got ", message_digest.size()));
  }
  const int kRsaModulusSize = RSA_size(public_key_.get());
  if (signature.size() != kRsaModulusSize) {
    return absl::InvalidArgumentError(
        "Signature size not equal to modulus size.");
  }

  std::string recovered_message_digest(kRsaModulusSize, 0);
  if (public_metadata_.empty()) {
    int recovered_message_digest_size = RSA_public_decrypt(
        /*flen=*/signature.size(),
        /*from=*/reinterpret_cast<const uint8_t*>(signature.data()),
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
    ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> signature_bn,
                                 StringToBignum(signature));
    if (BN_ucmp(signature_bn.get(), RSA_get0_n(public_key_.get())) >= 0) {
      return absl::InvalidArgumentError("Data too large for modulus.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(BnCtxPtr bn_ctx, GetAndStartBigNumCtx());
    bssl::UniquePtr<BN_MONT_CTX> bn_mont_ctx(BN_MONT_CTX_new_for_modulus(
        RSA_get0_n(public_key_.get()), bn_ctx.get()));
    if (!bn_mont_ctx) {
      return absl::InternalError("BN_MONT_CTX_new_for_modulus failed.");
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(
        bssl::UniquePtr<BIGNUM> recovered_message_digest_bn, NewBigNum());
    if (BN_mod_exp_mont(recovered_message_digest_bn.get(), signature_bn.get(),
                        RSA_get0_e(public_key_.get()),
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
          reinterpret_cast<const uint8_t*>(&recovered_message_digest[0]),
          salt_length_) != kBsslSuccess) {
    return absl::InvalidArgumentError(
        absl::StrCat("PSS padding verification failed.", GetSslErrors()));
  }

  return absl::OkStatus();
}

}  // namespace anonymous_tokens
}  // namespace private_membership
