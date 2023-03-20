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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/public_metadata_crypto_utils.h"

#include <memory>
#include <string>
#include <utility>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/strings/escaping.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/testing_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

std::pair<RSAPublicKey, std::string> GetFixedTestPublicKeyAndPublicMetadata() {
  RSAPublicKey public_key;
  public_key.set_n(absl::HexStringToBytes(
      "b2ae391467872a7506468a9ac4e980fa76164666955ef8999917295dbbd89dd7aa9c0e41"
      "2dcda3dd1aa867e0c414d80afb9544a7c71c32d83e1b8417f293f325d2ffe2f9e296d28f"
      "b89a443de5cc06ab3c516913fc18694539c370315d3e7f4ac5f87faaf3fee751c9f439ae"
      "8d53eee249d8c49b33bd3bb7aa060eb462522da98a02f92eff110cc9408ca0ccc54abf2c"
      "fcb68b77fb0ec7048d8b76416f61f2b182ea73169ed18f0d1d238dcaf6fc9de067d4831f"
      "68f485483dd5c9ec17d9384825ba7284bc38bb1ea5e40d9207d9007e609a19e3fab695a1"
      "8c30f1a7c4b03c77ef72211415a0bfeacd3298dccafa7e06e41dc2131f9076b92bb352c8"
      "f7bccfe9"));
  public_key.set_e(absl::HexStringToBytes("03"));
  std::string public_metadata = absl::HexStringToBytes("6d65746164617461");
  return std::make_pair(std::move(public_key), std::move(public_metadata));
}

std::string GetFixedTestNewPublicKeyExponentUnderPublicMetadata() {
  std::string new_e = absl::HexStringToBytes(
      "0b2d80537b4c899c7107eef3b74ddc0dcd931aff9c583ce3cf3527d42483052b27d55dd4"
      "d2f831a38430f13d81574c51aa97af6f5c3a6c03b269bc156d029273bd60e7af578fff15"
      "c52cbb5c19288fd1ce59f6f756b2d93b6f2586210fb969efb5065700da5598bb8914d395"
      "4d97a49c5ca05b2386bc3cf098281958cf372481");
  return new_e;
}

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class PublicMetadataCryptoUtilsTest
    : public testing::TestWithParam<CreateTestKeyPairFunction*> {
 protected:
  void SetUp() override {
    ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
        private_key_, AnonymousTokensRSAPrivateKeyToRSA(keys_pair.second));
    public_key_ = std::move(keys_pair.first);
  }

  bssl::UniquePtr<RSA> private_key_;
  RSAPublicKey public_key_;
};

TEST_P(PublicMetadataCryptoUtilsTest, PublicExponentCoprime) {
  std::string metadata = "md";
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp,
      PublicMetadataExponent(*RSA_get0_n(private_key_.get()), metadata));
  int rsa_mod_size_bits = BN_num_bits(RSA_get0_n(private_key_.get()));
  // Check that exponent is odd.
  EXPECT_EQ(BN_is_odd(exp.get()), 1);
  // Check that exponent is small enough.
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> sqrt2,
                                   GetRsaSqrtTwo(rsa_mod_size_bits / 2));
  EXPECT_LT(BN_cmp(exp.get(), sqrt2.get()), 0);
  EXPECT_LT(BN_cmp(exp.get(), RSA_get0_p(private_key_.get())), 0);
  EXPECT_LT(BN_cmp(exp.get(), RSA_get0_q(private_key_.get())), 0);
}

TEST_P(PublicMetadataCryptoUtilsTest, PublicExponentHash) {
  std::string metadata1 = "md1";
  std::string metadata2 = "md2";
  // Check that hash is deterministic.
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp1,
      PublicMetadataExponent(*RSA_get0_n(private_key_.get()), metadata1));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> another_exp1,
      PublicMetadataExponent(*RSA_get0_n(private_key_.get()), metadata1));
  EXPECT_EQ(BN_cmp(exp1.get(), another_exp1.get()), 0);
  // Check that hashes are distinct for different metadata.
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp2,
      PublicMetadataExponent(*RSA_get0_n(private_key_.get()), metadata2));
  EXPECT_NE(BN_cmp(exp1.get(), exp2.get()), 0);
}

TEST_P(PublicMetadataCryptoUtilsTest, FinalExponentCoprime) {
  std::string metadata = "md";
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> final_exponent,
      ComputeFinalExponentUnderPublicMetadata(*RSA_get0_n(private_key_.get()),
                                              *RSA_get0_e(private_key_.get()),
                                              metadata));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());

  // Check that exponent is odd.
  EXPECT_EQ(BN_is_odd(final_exponent.get()), 1);
  // Check that exponent is co-prime to factors of the rsa modulus.
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> gcd_p_fe,
                                   NewBigNum());
  ASSERT_EQ(BN_gcd(gcd_p_fe.get(), RSA_get0_p(private_key_.get()),
                   final_exponent.get(), ctx.get()),
            1);
  EXPECT_EQ(BN_cmp(gcd_p_fe.get(), BN_value_one()), 0);
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> gcd_q_fe,
                                   NewBigNum());
  ASSERT_EQ(BN_gcd(gcd_q_fe.get(), RSA_get0_q(private_key_.get()),
                   final_exponent.get(), ctx.get()),
            1);
  EXPECT_EQ(BN_cmp(gcd_q_fe.get(), BN_value_one()), 0);
}

TEST_P(PublicMetadataCryptoUtilsTest,
       DeterministicRSAPublicKeyToRSAUnderPublicMetadata) {
  std::string metadata = "md";
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_public_key_1,
      RSAPublicKeyToRSAUnderPublicMetadata(public_key_, metadata));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_public_key_2,
      RSAPublicKeyToRSAUnderPublicMetadata(public_key_, metadata));
  EXPECT_EQ(BN_cmp(RSA_get0_e(rsa_public_key_1.get()),
                   RSA_get0_e(rsa_public_key_2.get())),
            0);
}

TEST_P(PublicMetadataCryptoUtilsTest,
       DifferentPublicMetadataRSAPublicKeyToRSAUnderPublicMetadata) {
  std::string metadata_1 = "md1";
  std::string metadata_2 = "md2";
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_public_key_1,
      RSAPublicKeyToRSAUnderPublicMetadata(public_key_, metadata_1));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_public_key_2,
      RSAPublicKeyToRSAUnderPublicMetadata(public_key_, metadata_2));
  // Check that exponent is different in all keys
  EXPECT_NE(BN_cmp(RSA_get0_e(rsa_public_key_1.get()),
                   RSA_get0_e(rsa_public_key_2.get())),
            0);
  EXPECT_NE(BN_cmp(RSA_get0_e(rsa_public_key_1.get()),
                   RSA_get0_e(private_key_.get())),
            0);
  EXPECT_NE(BN_cmp(RSA_get0_e(rsa_public_key_1.get()),
                   RSA_get0_e(private_key_.get())),
            0);
}

TEST_P(PublicMetadataCryptoUtilsTest,
       NoPublicMetadataRSAPublicKeyToRSAUnderPublicMetadata) {
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_public_key,
      RSAPublicKeyToRSAUnderPublicMetadata(public_key_, ""));

  // Check that exponent is same in output and input.
  EXPECT_EQ(
      BN_cmp(RSA_get0_e(rsa_public_key.get()), RSA_get0_e(private_key_.get())),
      0);
  // Check that rsa_modulus is correct
  EXPECT_EQ(
      BN_cmp(RSA_get0_n(rsa_public_key.get()), RSA_get0_n(private_key_.get())),
      0);
}

INSTANTIATE_TEST_SUITE_P(
    PublicMetadataCryptoUtilsTest, PublicMetadataCryptoUtilsTest,
    testing::Values(&GetStrongRsaKeys2048, &GetAnotherStrongRsaKeys2048,
                    &GetStrongRsaKeys3072, &GetStrongRsaKeys4096));

TEST(PublicMetadataCryptoUtilsInternalTest, PublicMetadataHashWithHKDF) {
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> max_value,
                                   NewBigNum());
  ASSERT_TRUE(BN_set_word(max_value.get(), 4294967296));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(auto key_pair, GetStrongRsaKeys2048());
  std::string input1 = "ro1";
  std::string input2 = "ro2";
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> output1,
      public_metadata_crypto_utils_internal::PublicMetadataHashWithHKDF(
          input1, key_pair.first.n(), 1 + input1.size()));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> another_output1,
      public_metadata_crypto_utils_internal::PublicMetadataHashWithHKDF(
          input1, key_pair.first.n(), 1 + input1.size()));
  EXPECT_EQ(BN_cmp(output1.get(), another_output1.get()), 0);

  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> output2,
      public_metadata_crypto_utils_internal::PublicMetadataHashWithHKDF(
          input2, key_pair.first.n(), 1 + input2.size()));
  EXPECT_NE(BN_cmp(output1.get(), output2.get()), 0);

  EXPECT_LT(BN_cmp(output1.get(), max_value.get()), 0);
  EXPECT_LT(BN_cmp(output2.get(), max_value.get()), 0);
}

TEST(PublicMetadataCryptoUtilsTest, PublicExponentHashDifferentModulus) {
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(auto key_pair_1, GetStrongRsaKeys2048());
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(auto key_pair_2,
                                   GetAnotherStrongRsaKeys2048());
  std::string metadata = "md";
  // Check that same metadata and different modulus result in different
  // hashes.
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      auto rsa_private_key_1,
      AnonymousTokensRSAPrivateKeyToRSA(key_pair_1.second));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp1,
      PublicMetadataExponent(*RSA_get0_n(rsa_private_key_1.get()), metadata));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      auto rsa_private_key_2,
      AnonymousTokensRSAPrivateKeyToRSA(key_pair_2.second));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp2,
      PublicMetadataExponent(*RSA_get0_n(rsa_private_key_2.get()), metadata));
  EXPECT_NE(BN_cmp(exp1.get(), exp2.get()), 0);
}

TEST(PublicMetadataCryptoUtilsTest,
     FixedTestRSAPublicKeyToRSAUnderPublicMetadata) {
  const auto public_key_and_metadata = GetFixedTestPublicKeyAndPublicMetadata();
  const std::string expected_new_e_str =
      GetFixedTestNewPublicKeyExponentUnderPublicMetadata();
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> rsa_modulus,
      StringToBignum(public_key_and_metadata.first.n()));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> expected_new_e,
                                   StringToBignum(expected_new_e_str));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> modified_rsa_public_key,
      RSAPublicKeyToRSAUnderPublicMetadata(public_key_and_metadata.first,
                                           public_key_and_metadata.second));
  EXPECT_EQ(
      BN_cmp(RSA_get0_n(modified_rsa_public_key.get()), rsa_modulus.get()), 0);
  EXPECT_EQ(
      BN_cmp(RSA_get0_e(modified_rsa_public_key.get()), expected_new_e.get()),
      0);
}

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
