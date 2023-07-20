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
#include <tuple>
#include <utility>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "openssl/base.h"
#include "openssl/digest.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

// TODO(b/275965524): Figure out a way to test RsaBlinder class with IETF test
// vectors in rsa_blinder_test.cc.

struct RsaBlinderTestParameters {
  TestRsaPublicKey public_key;
  TestRsaPrivateKey private_key;
  const EVP_MD* sig_hash;
  const EVP_MD* mgf1_hash;
  int salt_length;
};

RsaBlinderTestParameters CreateDefaultTestKeyParameters() {
  const auto [public_key, private_key] = GetStrongTestRsaKeyPair4096();
  return {public_key, private_key, EVP_sha384(), EVP_sha384(),
          kSaltLengthInBytes48};
}

RsaBlinderTestParameters CreateShorterTestKeyParameters() {
  const auto [public_key, private_key] = GetStrongTestRsaKeyPair3072();
  return {public_key, private_key, EVP_sha384(), EVP_sha384(),
          kSaltLengthInBytes48};
}

RsaBlinderTestParameters CreateShortestTestKeyParameters() {
  const auto [public_key, private_key] = GetStrongTestRsaKeyPair2048();
  return {public_key, private_key, EVP_sha384(), EVP_sha384(),
          kSaltLengthInBytes48};
}

RsaBlinderTestParameters CreateSHA256TestKeyParameters() {
  const auto [public_key, private_key] = GetStrongTestRsaKeyPair4096();
  return {public_key, private_key, EVP_sha256(), EVP_sha256(), 32};
}

RsaBlinderTestParameters CreateLongerSaltTestKeyParameters() {
  const auto [public_key, private_key] = GetStrongTestRsaKeyPair4096();
  return {public_key, private_key, EVP_sha384(), EVP_sha384(), 64};
}

class RsaBlinderTest : public testing::TestWithParam<RsaBlinderTestParameters> {
 protected:
  void SetUp() override {
    rsa_blinder_test_params_ = GetParam();
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_key_,
        CreatePrivateKeyRSA(rsa_blinder_test_params_.private_key.n,
                            rsa_blinder_test_params_.private_key.e,
                            rsa_blinder_test_params_.private_key.d,
                            rsa_blinder_test_params_.private_key.p,
                            rsa_blinder_test_params_.private_key.q,
                            rsa_blinder_test_params_.private_key.dp,
                            rsa_blinder_test_params_.private_key.dq,
                            rsa_blinder_test_params_.private_key.crt));
  }

  RsaBlinderTestParameters rsa_blinder_test_params_;
  bssl::UniquePtr<RSA> rsa_key_;
};

TEST_P(RsaBlinderTest, BlindSignUnblindEnd2EndTest) {
  const absl::string_view message = "Hello World!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      /*use_rsa_public_exponent=*/true));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);

  EXPECT_TRUE(blinder->Verify(signature, message).ok());
}

TEST_P(RsaBlinderTest, DoubleBlindingFailure) {
  const absl::string_view message = "Hello World2!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      /*use_rsa_public_exponent=*/true));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_message,
                                   blinder->Blind(message));
  // Blind the blinded_message
  absl::StatusOr<std::string> result = blinder->Blind(blinded_message);
  EXPECT_EQ(result.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(result.status().message(), testing::HasSubstr("wrong state"));
  // Blind a new message
  const absl::string_view new_message = "Hello World3!";
  result = blinder->Blind(new_message);
  EXPECT_EQ(result.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(result.status().message(), testing::HasSubstr("wrong state"));
}

TEST_P(RsaBlinderTest, DoubleUnblindingFailure) {
  const absl::string_view message = "Hello World2!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      /*use_rsa_public_exponent=*/true));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_message,
                                   blinder->Blind(message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  // Unblind the unblinded signature
  absl::StatusOr<std::string> result = blinder->Unblind(signature);
  EXPECT_EQ(result.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(result.status().message(), testing::HasSubstr("wrong state"));
  // Unblind the blinded_signature again
  result = blinder->Unblind(signature);
  EXPECT_EQ(result.status().code(), absl::StatusCode::kFailedPrecondition);
  EXPECT_THAT(result.status().message(), testing::HasSubstr("wrong state"));
}

TEST_P(RsaBlinderTest, InvalidSignature) {
  const absl::string_view message = "Hello World2!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      /*use_rsa_public_exponent=*/true));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_message,
                                   blinder->Blind(message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_TRUE(blinder->Verify(signature, message).ok());

  // Invalidate the signature by replacing the last 10 characters by 10 '0's
  for (int i = 0; i < 10; i++) {
    signature.pop_back();
  }
  for (int i = 0; i < 10; i++) {
    signature.push_back('0');
  }

  absl::Status result = blinder->Verify(signature, message);
  EXPECT_EQ(result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(result.message(), testing::HasSubstr("verification failed"));
}

TEST_P(RsaBlinderTest, InvalidVerificationKey) {
  const absl::string_view message = "Hello World4!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      /*use_rsa_public_exponent=*/true));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_message,
                                   blinder->Blind(message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));

  const auto [bad_key, _] = GetAnotherStrongTestRsaKeyPair2048();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> bad_blinder,
      RsaBlinder::New(bad_key.n, bad_key.e, rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      /*use_rsa_public_exponent=*/true));
  EXPECT_THAT(bad_blinder->Verify(signature, message).code(),
              absl::StatusCode::kInvalidArgument);
}

INSTANTIATE_TEST_SUITE_P(RsaBlinderTest, RsaBlinderTest,
                         testing::Values(CreateDefaultTestKeyParameters(),
                                         CreateShorterTestKeyParameters(),
                                         CreateShortestTestKeyParameters(),
                                         CreateSHA256TestKeyParameters(),
                                         CreateLongerSaltTestKeyParameters()));

using RsaBlinderPublicMetadataTestParams =
    std::tuple<std::pair<TestRsaPublicKey, TestRsaPrivateKey>,
               /*use_rsa_public_exponent*/ bool>;

class RsaBlinderWithPublicMetadataTest
    : public testing::TestWithParam<RsaBlinderPublicMetadataTestParams> {
 protected:
  void SetUp() override {
    std::pair<TestRsaPublicKey, TestRsaPrivateKey> key_pair;
    std::tie(key_pair, use_rsa_public_exponent_) = GetParam();
    const auto [public_key, private_key] = key_pair;
    rsa_blinder_test_params_ = {public_key, private_key, EVP_sha384(),
                                EVP_sha384(), kSaltLengthInBytes48};
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_key_,
        CreatePrivateKeyRSA(rsa_blinder_test_params_.private_key.n,
                            rsa_blinder_test_params_.private_key.e,
                            rsa_blinder_test_params_.private_key.d,
                            rsa_blinder_test_params_.private_key.p,
                            rsa_blinder_test_params_.private_key.q,
                            rsa_blinder_test_params_.private_key.dp,
                            rsa_blinder_test_params_.private_key.dq,
                            rsa_blinder_test_params_.private_key.crt));
  }

  RsaBlinderTestParameters rsa_blinder_test_params_;
  bssl::UniquePtr<RSA> rsa_key_;
  bool use_rsa_public_exponent_;
};

TEST_P(RsaBlinderWithPublicMetadataTest,
       BlindSignUnblindWithPublicMetadataEnd2EndTest) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      use_rsa_public_exponent_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, public_metadata, *rsa_key_,
                                 use_rsa_public_exponent_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);

  EXPECT_TRUE(blinder->Verify(signature, message).ok());
}

TEST_P(RsaBlinderWithPublicMetadataTest,
       BlindSignUnblindWithEmptyPublicMetadataEnd2EndTest) {
  const absl::string_view message = "Hello World!";
  const absl::string_view empty_public_metadata = "";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      use_rsa_public_exponent_, empty_public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, empty_public_metadata,
                                 *rsa_key_, use_rsa_public_exponent_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);

  EXPECT_TRUE(blinder->Verify(signature, message).ok());
}

TEST_P(RsaBlinderWithPublicMetadataTest, WrongPublicMetadata) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";
  const absl::string_view public_metadata_2 = "pubmd2";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      use_rsa_public_exponent_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, public_metadata_2, *rsa_key_,
                                 use_rsa_public_exponent_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);
  absl::Status verification_result = blinder->Verify(signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              ::testing::HasSubstr("verification failed"));
}

TEST_P(RsaBlinderWithPublicMetadataTest, NoPublicMetadataForSigning) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(rsa_blinder_test_params_.public_key.n,
                      rsa_blinder_test_params_.public_key.e,
                      rsa_blinder_test_params_.sig_hash,
                      rsa_blinder_test_params_.mgf1_hash,
                      rsa_blinder_test_params_.salt_length,
                      use_rsa_public_exponent_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);
  absl::Status verification_result = blinder->Verify(signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              ::testing::HasSubstr("verification failed"));
}

TEST_P(RsaBlinderWithPublicMetadataTest, NoPublicMetadataInBlinding) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(
          rsa_blinder_test_params_.public_key.n,
          rsa_blinder_test_params_.public_key.e,
          rsa_blinder_test_params_.sig_hash, rsa_blinder_test_params_.mgf1_hash,
          rsa_blinder_test_params_.salt_length, use_rsa_public_exponent_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, public_metadata, *rsa_key_,
                                 use_rsa_public_exponent_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);
  absl::Status verification_result = blinder->Verify(signature, message);
  EXPECT_EQ(verification_result.code(), absl::StatusCode::kInvalidArgument);
  EXPECT_THAT(verification_result.message(),
              ::testing::HasSubstr("verification failed"));
}

INSTANTIATE_TEST_SUITE_P(
    RsaBlinderWithPublicMetadataTest, RsaBlinderWithPublicMetadataTest,
    testing::Combine(testing::Values(GetStrongTestRsaKeyPair2048(),
                                     GetAnotherStrongTestRsaKeyPair2048(),
                                     GetStrongTestRsaKeyPair3072(),
                                     GetStrongTestRsaKeyPair4096()),
                     /*use_rsa_public_exponent*/ testing::Values(true, false)));

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
