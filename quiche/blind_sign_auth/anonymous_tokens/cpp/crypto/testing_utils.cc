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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/testing_utils.h"

#include <stddef.h>
#include <stdint.h>

#include <fstream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/public_metadata_crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/status_utils.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {

namespace {

absl::StatusOr<std::string> ReadFileToString(absl::string_view path) {
  std::ifstream file((std::string(path)));
  if (!file.is_open()) {
    return absl::InternalError("Reading file failed.");
  }
  std::ostringstream ss;
  ss << file.rdbuf();
  return ss.str();
}

absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>> ParseRsaKeysFromFile(
    absl::string_view path) {
  ANON_TOKENS_ASSIGN_OR_RETURN(std::string text_proto, ReadFileToString(path));
  RSAPrivateKey private_key;
  if (!private_key.ParseFromString(text_proto)) {
    return absl::InternalError("Parsing text proto failed.");
  }
  RSAPublicKey public_key;
  public_key.set_n(private_key.n());
  public_key.set_e(private_key.e());
  return std::make_pair(std::move(public_key), std::move(private_key));
}

absl::StatusOr<bssl::UniquePtr<RSA>> GenerateRSAKey(int modulus_bit_size,
                                                    const BIGNUM& e) {
  bssl::UniquePtr<RSA> rsa(RSA_new());
  if (!rsa.get()) {
    return absl::InternalError(
        absl::StrCat("RSA_new failed: ", GetSslErrors()));
  }
  if (RSA_generate_key_ex(rsa.get(), modulus_bit_size, &e,
                          /*cb=*/nullptr) != kBsslSuccess) {
    return absl::InternalError(
        absl::StrCat("Error generating private key: ", GetSslErrors()));
  }
  return rsa;
}

}  // namespace

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateTestKey(int key_size, HashType sig_hash, MaskGenFunction mfg1_hash,
              int salt_length, MessageMaskType message_mask_type,
              int message_mask_size) {
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> rsa_f4, NewBigNum());
  BN_set_u64(rsa_f4.get(), RSA_F4);

  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<RSA> rsa_key,
                               GenerateRSAKey(key_size * 8, *rsa_f4));

  RSAPublicKey rsa_public_key;
  ANON_TOKENS_ASSIGN_OR_RETURN(
      *rsa_public_key.mutable_n(),
      BignumToString(*RSA_get0_n(rsa_key.get()), key_size));
  ANON_TOKENS_ASSIGN_OR_RETURN(
      *rsa_public_key.mutable_e(),
      BignumToString(*RSA_get0_e(rsa_key.get()), key_size));

  RSABlindSignaturePublicKey public_key;
  public_key.set_serialized_public_key(rsa_public_key.SerializeAsString());
  public_key.set_sig_hash_type(sig_hash);
  public_key.set_mask_gen_function(mfg1_hash);
  public_key.set_salt_length(salt_length);
  public_key.set_key_size(key_size);
  public_key.set_message_mask_type(message_mask_type);
  public_key.set_message_mask_size(message_mask_size);

  return std::make_pair(std::move(rsa_key), std::move(public_key));
}

absl::StatusOr<std::string> TestSign(const absl::string_view blinded_data,
                                     RSA* rsa_key) {
  if (blinded_data.empty()) {
    return absl::InvalidArgumentError("blinded_data string is empty.");
  }
  const size_t mod_size = RSA_size(rsa_key);
  if (blinded_data.size() != mod_size) {
    return absl::InternalError(absl::StrCat(
        "Expected blind data size = ", mod_size,
        " actual blind data size = ", blinded_data.size(), " bytes."));
  }
  // Compute a raw RSA signature.
  std::string signature(mod_size, 0);
  size_t out_len;
  if (RSA_sign_raw(/*rsa=*/rsa_key, /*out_len=*/&out_len,
                   /*out=*/reinterpret_cast<uint8_t*>(&signature[0]),
                   /*max_out=*/mod_size,
                   /*in=*/reinterpret_cast<const uint8_t*>(&blinded_data[0]),
                   /*in_len=*/mod_size,
                   /*padding=*/RSA_NO_PADDING) != kBsslSuccess) {
    return absl::InternalError(
        "RSA_sign_raw failed when called from RsaBlindSigner::Sign");
  }
  if (out_len != mod_size && out_len == signature.size()) {
    return absl::InternalError(absl::StrCat(
        "Expected value of out_len = ", mod_size,
        " bytes, actual value of out_len and signature.size() = ", out_len,
        " and ", signature.size(), " bytes."));
  }
  return signature;
}

absl::StatusOr<std::string> TestSignWithPublicMetadata(
    const absl::string_view blinded_data, absl::string_view public_metadata,
    const RSA& rsa_key) {
  if (public_metadata.empty()) {
    return absl::InvalidArgumentError("Public Metadata is empty.");
  } else if (blinded_data.empty()) {
    return absl::InvalidArgumentError("blinded_data string is empty.");
  } else if (blinded_data.size() != RSA_size(&rsa_key)) {
    return absl::InternalError(absl::StrCat(
        "Expected blind data size = ", RSA_size(&rsa_key),
        " actual blind data size = ", blinded_data.size(), " bytes."));
  }
  ANON_TOKENS_ASSIGN_OR_RETURN(
      bssl::UniquePtr<BIGNUM> new_e,
      ComputeFinalExponentUnderPublicMetadata(
          *RSA_get0_n(&rsa_key), *RSA_get0_e(&rsa_key), public_metadata));
  // Compute phi(p) = p-1
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> phi_p, NewBigNum());
  if (BN_sub(phi_p.get(), RSA_get0_p(&rsa_key), BN_value_one()) != 1) {
    return absl::InternalError(
        absl::StrCat("Unable to compute phi(p): ", GetSslErrors()));
  }
  // Compute phi(q) = q-1
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> phi_q, NewBigNum());
  if (BN_sub(phi_q.get(), RSA_get0_q(&rsa_key), BN_value_one()) != 1) {
    return absl::InternalError(
        absl::StrCat("Unable to compute phi(q): ", GetSslErrors()));
  }
  // Compute phi(n) = phi(p)*phi(q)
  ANON_TOKENS_ASSIGN_OR_RETURN(auto ctx, GetAndStartBigNumCtx());
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> phi_n, NewBigNum());
  if (BN_mul(phi_n.get(), phi_p.get(), phi_q.get(), ctx.get()) != 1) {
    return absl::InternalError(
        absl::StrCat("Unable to compute phi(n): ", GetSslErrors()));
  }
  // Compute lcm(phi(p), phi(q)).
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> lcm, NewBigNum());
  if (BN_rshift1(lcm.get(), phi_n.get()) != 1) {
    return absl::InternalError(absl::StrCat(
        "Could not compute LCM(phi(p), phi(q)): ", GetSslErrors()));
  }
  // Compute the new private exponent new_d
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> new_d, NewBigNum());
  if (!BN_mod_inverse(new_d.get(), new_e.get(), lcm.get(), ctx.get())) {
    return absl::InternalError(
        absl::StrCat("Could not compute private exponent d: ", GetSslErrors()));
  }

  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> input_bn,
                               StringToBignum(blinded_data));
  if (BN_ucmp(input_bn.get(), RSA_get0_n(&rsa_key)) >= 0) {
    return absl::InvalidArgumentError(
        "RsaSign input size too large for modulus size");
  }

  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> result, NewBigNum());
  if (!BN_mod_exp(result.get(), input_bn.get(), new_d.get(),
                  RSA_get0_n(&rsa_key), ctx.get())) {
    return absl::InternalError(
        "BN_mod_exp failed in TestSignWithPublicMetadata");
  }

  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> vrfy, NewBigNum());
  if (vrfy == nullptr ||
      !BN_mod_exp(vrfy.get(), result.get(), new_e.get(), RSA_get0_n(&rsa_key),
                  ctx.get()) ||
      BN_cmp(vrfy.get(), input_bn.get()) != 0) {
    return absl::InternalError("Signature verification failed in RsaSign");
  }

  return BignumToString(*result, BN_num_bytes(RSA_get0_n(&rsa_key)));
}

absl::StatusOr<std::string> EncodeMessageForTests(absl::string_view message,
                                                  RSAPublicKey public_key,
                                                  const EVP_MD* sig_hasher,
                                                  const EVP_MD* mgf1_hasher,
                                                  int32_t salt_length) {
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> rsa_modulus,
                               StringToBignum(public_key.n()));
  ANON_TOKENS_ASSIGN_OR_RETURN(bssl::UniquePtr<BIGNUM> e,
                               StringToBignum(public_key.e()));
  // Convert to OpenSSL RSA.
  bssl::UniquePtr<RSA> rsa_public_key(RSA_new());
  if (!rsa_public_key.get()) {
    return absl::InternalError(
        absl::StrCat("RSA_new failed: ", GetSslErrors()));
  } else if (RSA_set0_key(rsa_public_key.get(), rsa_modulus.release(),
                          e.release(), nullptr) != kBsslSuccess) {
    return absl::InternalError(
        absl::StrCat("RSA_set0_key failed: ", GetSslErrors()));
  }

  const int padded_len = RSA_size(rsa_public_key.get());
  std::vector<uint8_t> padded(padded_len);
  ANON_TOKENS_ASSIGN_OR_RETURN(std::string digest,
                               ComputeHash(message, *sig_hasher));
  if (RSA_padding_add_PKCS1_PSS_mgf1(
          /*rsa=*/rsa_public_key.get(), /*EM=*/padded.data(),
          /*mHash=*/reinterpret_cast<uint8_t*>(&digest[0]), /*Hash=*/sig_hasher,
          /*mgf1Hash=*/mgf1_hasher,
          /*sLen=*/salt_length) != kBsslSuccess) {
    return absl::InternalError(
        "RSA_padding_add_PKCS1_PSS_mgf1 failed when called from "
        "testing_utils");
  }
  std::string encoded_message(padded.begin(), padded.end());
  return encoded_message;
}

absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>> GetStrongRsaKeys2048() {
  ANON_TOKENS_ASSIGN_OR_RETURN(
      auto key_pair,
      ParseRsaKeysFromFile("quiche/blind_sign_auth/anonymous_tokens/testing/data/"
                           "strong_rsa_modulus2048_example.binarypb"));
  return std::make_pair(std::move(key_pair.first), std::move(key_pair.second));
}

absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>
GetAnotherStrongRsaKeys2048() {
  ANON_TOKENS_ASSIGN_OR_RETURN(
      auto key_pair,
      ParseRsaKeysFromFile("quiche/blind_sign_auth/anonymous_tokens/testing/data/"
                           "strong_rsa_modulus2048_example_2.binarypb"));
  return std::make_pair(std::move(key_pair.first), std::move(key_pair.second));
}

absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>> GetStrongRsaKeys3072() {
  ANON_TOKENS_ASSIGN_OR_RETURN(
      auto key_pair,
      ParseRsaKeysFromFile("quiche/blind_sign_auth/anonymous_tokens/testing/data/"
                           "strong_rsa_modulus3072_example.binarypb"));
  return std::make_pair(std::move(key_pair.first), std::move(key_pair.second));
}

absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>> GetStrongRsaKeys4096() {
  ANON_TOKENS_ASSIGN_OR_RETURN(
      auto key_pair,
      ParseRsaKeysFromFile("quiche/blind_sign_auth/anonymous_tokens/testing/data/"
                           "strong_rsa_modulus4096_example.binarypb"));
  return std::make_pair(std::move(key_pair.first), std::move(key_pair.second));
}

}  // namespace anonymous_tokens
}  // namespace private_membership
