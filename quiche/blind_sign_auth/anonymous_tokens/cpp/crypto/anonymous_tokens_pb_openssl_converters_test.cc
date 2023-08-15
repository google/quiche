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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/anonymous_tokens_pb_openssl_converters.h"

#include <string>
#include <utility>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/proto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/bn.h"
#include "openssl/digest.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

TEST(AnonymousTokensPbOpensslConvertersTests, GenerateMaskTestInvalidType) {
  RSABlindSignaturePublicKey public_key;
  public_key.set_message_mask_type(AT_MESSAGE_MASK_TYPE_UNDEFINED);
  public_key.set_message_mask_size(kRsaMessageMaskSizeInBytes32);
  absl::StatusOr<std::string> mask_32_bytes = GenerateMask(public_key);
  EXPECT_EQ(mask_32_bytes.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(mask_32_bytes.status().message(),
              ::testing::HasSubstr("Unsupported message mask type"));
}

TEST(AnonymousTokensPbOpensslConvertersTests, GenerateMaskTestInvalidLength) {
  RSABlindSignaturePublicKey public_key;
  // Mask meant to be concatenated is less than 32 bytes.
  public_key.set_message_mask_type(AT_MESSAGE_MASK_CONCAT);
  public_key.set_message_mask_size(kRsaMessageMaskSizeInBytes32 - 1);
  absl::StatusOr<std::string> mask_32_bytes = GenerateMask(public_key);
  // Mask type set to no mask but mask length requested is greater than 0.
  public_key.set_message_mask_type(AT_MESSAGE_MASK_NO_MASK);
  public_key.set_message_mask_size(kRsaMessageMaskSizeInBytes32);
  absl::StatusOr<std::string> mask_0_bytes = GenerateMask(public_key);

  EXPECT_EQ(mask_32_bytes.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_EQ(mask_0_bytes.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(mask_32_bytes.status().message(),
              ::testing::HasSubstr("invalid message mask size"));
  EXPECT_THAT(mask_0_bytes.status().message(),
              ::testing::HasSubstr("invalid message mask size"));
}

TEST(AnonymousTokensPbOpensslConvertersTests, GenerateMaskTestSuccess) {
  RSABlindSignaturePublicKey public_key;
  public_key.set_message_mask_type(AT_MESSAGE_MASK_CONCAT);
  public_key.set_message_mask_size(kRsaMessageMaskSizeInBytes32);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string mask_32_bytes,
                                   GenerateMask(public_key));
  // Longer mask.
  public_key.set_message_mask_size(kRsaMessageMaskSizeInBytes32 * 2);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string mask_64_bytes,
                                   GenerateMask(public_key));

  // No mask.
  public_key.set_message_mask_type(AT_MESSAGE_MASK_NO_MASK);
  public_key.set_message_mask_size(0);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string mask_0_bytes,
                                   GenerateMask(public_key));

  EXPECT_FALSE(mask_32_bytes.empty());
  EXPECT_FALSE(mask_64_bytes.empty());
  EXPECT_TRUE(mask_0_bytes.empty());
  EXPECT_EQ(mask_32_bytes.size(), kRsaMessageMaskSizeInBytes32);
  EXPECT_EQ(mask_64_bytes.size(), kRsaMessageMaskSizeInBytes32 * 2);
  EXPECT_EQ(mask_0_bytes.size(), 0);
}

TEST(AnonymousTokensPbOpensslConvertersTests,
     HashTypeConverterTestInvalidType) {
  absl::StatusOr<const EVP_MD *> evp =
      ProtoHashTypeToEVPDigest(AT_HASH_TYPE_UNDEFINED);
  EXPECT_EQ(evp.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(evp.status().message(),
              ::testing::HasSubstr("Unknown hash type"));
}

TEST(AnonymousTokensPbOpensslConvertersTests, HashTypeConverterTestSuccess) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const EVP_MD *evp_256, ProtoHashTypeToEVPDigest(AT_HASH_TYPE_SHA256));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const EVP_MD *evp_384, ProtoHashTypeToEVPDigest(AT_HASH_TYPE_SHA384));
  EXPECT_EQ(evp_256, EVP_sha256());
  EXPECT_EQ(evp_384, EVP_sha384());
}

TEST(AnonymousTokensPbOpensslConvertersStrongTests,
     MaskGenFunctionConverterStrongTestInvalidType) {
  absl::StatusOr<const EVP_MD *> evp =
      ProtoMaskGenFunctionToEVPDigest(AT_MGF_UNDEFINED);
  EXPECT_EQ(evp.status().code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(evp.status().message(),
              ::testing::HasSubstr(
                  "Unknown hash type for mask generation hash function"));
}

TEST(AnonymousTokensPbOpensslConvertersTests,
     MaskGenFunctionConverterTestSuccess) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const EVP_MD *evp_256, ProtoMaskGenFunctionToEVPDigest(AT_MGF_SHA256));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const EVP_MD *evp_384, ProtoMaskGenFunctionToEVPDigest(AT_MGF_SHA384));
  EXPECT_EQ(evp_256, EVP_sha256());
  EXPECT_EQ(evp_384, EVP_sha384());
}

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class AnonymousTokensRsaKeyPairConverterTest
    : public testing::TestWithParam<CreateTestKeyPairFunction *> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    public_key_ = std::move(keys_pair.first);
    private_key_ = std::move(keys_pair.second);

    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_modulus_,
                                     StringToBignum(private_key_.n()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_e_, StringToBignum(private_key_.e()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_d_, StringToBignum(private_key_.d()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_p_, StringToBignum(private_key_.p()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_q_, StringToBignum(private_key_.q()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_dp_,
                                     StringToBignum(private_key_.dp()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_dq_,
                                     StringToBignum(private_key_.dq()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_crt_,
                                     StringToBignum(private_key_.crt()));
  }

  bssl::UniquePtr<BIGNUM> rsa_modulus_;
  bssl::UniquePtr<BIGNUM> rsa_e_;
  bssl::UniquePtr<BIGNUM> rsa_d_;
  bssl::UniquePtr<BIGNUM> rsa_p_;
  bssl::UniquePtr<BIGNUM> rsa_q_;
  bssl::UniquePtr<BIGNUM> rsa_dp_;
  bssl::UniquePtr<BIGNUM> rsa_dq_;
  bssl::UniquePtr<BIGNUM> rsa_crt_;

  RSAPublicKey public_key_;
  RSAPrivateKey private_key_;
};

TEST_P(AnonymousTokensRsaKeyPairConverterTest, PublicKeyTest) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_public_key,
      AnonymousTokensRSAPublicKeyToRSA(public_key_));

  EXPECT_EQ(BN_cmp(RSA_get0_n(rsa_public_key.get()), rsa_modulus_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_e(rsa_public_key.get()), rsa_e_.get()), 0);
}

TEST_P(AnonymousTokensRsaKeyPairConverterTest, PrivateKeyTest) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_private_key,
      AnonymousTokensRSAPrivateKeyToRSA(private_key_));

  EXPECT_EQ(BN_cmp(RSA_get0_n(rsa_private_key.get()), rsa_modulus_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_e(rsa_private_key.get()), rsa_e_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_d(rsa_private_key.get()), rsa_d_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_p(rsa_private_key.get()), rsa_p_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_q(rsa_private_key.get()), rsa_q_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_dmp1(rsa_private_key.get()), rsa_dp_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_dmq1(rsa_private_key.get()), rsa_dq_.get()), 0);
  EXPECT_EQ(BN_cmp(RSA_get0_iqmp(rsa_private_key.get()), rsa_crt_.get()), 0);
}

INSTANTIATE_TEST_SUITE_P(AnonymousTokensRsaKeyPairConverterTest,
                         AnonymousTokensRsaKeyPairConverterTest,
                         testing::Values(&GetStrongRsaKeys2048,
                                         &GetAnotherStrongRsaKeys2048,
                                         &GetStrongRsaKeys3072,
                                         &GetStrongRsaKeys4096));

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
