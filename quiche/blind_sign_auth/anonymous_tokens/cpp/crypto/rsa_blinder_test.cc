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

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

// TODO(b/275965524): Figure out a way to test RsaBlinder class with IETF test
// vectors in rsa_blinder_test.cc.

using CreateTestKeyFunction = absl::StatusOr<
    std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>();

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateStandardTestKey() {
  return CreateTestKey();
}

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateShorterTestKey() {
  return CreateTestKey(/*key_size=*/256);
}

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateLongerTestKey() {
  return CreateTestKey(/*key_size=*/544);
}

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateSHA256TestKey() {
  return CreateTestKey(/*key_size=*/512, AT_HASH_TYPE_SHA256, AT_MGF_SHA256);
}

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateLongerSaltTestKey() {
  return CreateTestKey(/*key_size=*/512, AT_HASH_TYPE_SHA384, AT_MGF_SHA384,
                       /*salt_length=*/64);
}

class RsaBlinderTest : public testing::TestWithParam<CreateTestKeyFunction*> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto test_key, (*GetParam())());
    rsa_key_ = std::move(test_key.first);
    public_key_ = std::move(test_key.second);
  }

  RSABlindSignaturePublicKey public_key_;
  bssl::UniquePtr<RSA> rsa_key_;
};

TEST_P(RsaBlinderTest, BlindSignUnblindEnd2EndTest) {
  const absl::string_view message = "Hello World!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> blinder,
                                   RsaBlinder::New(public_key_));
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

  QUICHE_EXPECT_OK(blinder->Verify(signature, message));
}

TEST_P(RsaBlinderTest, DoubleBlindingFailure) {
  const absl::string_view message = "Hello World2!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> blinder,
                                   RsaBlinder::New(public_key_));
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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> blinder,
                                   RsaBlinder::New(public_key_));
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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> blinder,
                                   RsaBlinder::New(public_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_message,
                                   blinder->Blind(message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  QUICHE_EXPECT_OK(blinder->Verify(signature, message));

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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> blinder,
                                   RsaBlinder::New(public_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_message,
                                   blinder->Blind(message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const std::string blinded_signature,
                                   TestSign(blinded_message, rsa_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto bad_key, CreateTestKey());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> bad_blinder,
                                   RsaBlinder::New(bad_key.second));
  EXPECT_THAT(bad_blinder->Verify(signature, message).code(),
              absl::StatusCode::kInvalidArgument);
}

INSTANTIATE_TEST_SUITE_P(RsaBlinderTest, RsaBlinderTest,
                         testing::Values(&CreateStandardTestKey,
                                         &CreateShorterTestKey,
                                         &CreateLongerTestKey,
                                         &CreateSHA256TestKey,
                                         &CreateLongerSaltTestKey));

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class RsaBlinderWithPublicMetadataTest
    : public testing::TestWithParam<CreateTestKeyPairFunction*> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto test_key, (*GetParam())());
    RSABlindSignaturePublicKey public_key;
    public_key.set_sig_hash_type(HashType::AT_HASH_TYPE_SHA384);
    public_key.set_mask_gen_function(AT_MGF_SHA384);
    public_key.set_salt_length(kSaltLengthInBytes48);
    public_key.set_serialized_public_key(
        std::move(test_key.first).SerializeAsString());
    public_key_ = std::move(public_key);
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        rsa_key_, AnonymousTokensRSAPrivateKeyToRSA(test_key.second));
  }

  RSABlindSignaturePublicKey public_key_;
  bssl::UniquePtr<RSA> rsa_key_;
};

TEST_P(RsaBlinderWithPublicMetadataTest,
       BlindSignUnblindWithPublicMetadataEnd2EndTest) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(public_key_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, public_metadata, *rsa_key_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);

  QUICHE_EXPECT_OK(blinder->Verify(signature, message));
}

TEST_P(RsaBlinderWithPublicMetadataTest,
       BlindSignUnblindWithEmptyPublicMetadataEnd2EndTest) {
  const absl::string_view message = "Hello World!";
  const absl::string_view empty_public_metadata = "";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(public_key_, empty_public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, empty_public_metadata,
                                 *rsa_key_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);

  QUICHE_EXPECT_OK(blinder->Verify(signature, message));
}

TEST_P(RsaBlinderWithPublicMetadataTest, WrongPublicMetadata) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";
  const absl::string_view public_metadata_2 = "pubmd2";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(public_key_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, public_metadata_2,
                                 *rsa_key_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);
  EXPECT_THAT(
      blinder->Verify(signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

TEST_P(RsaBlinderWithPublicMetadataTest, NoPublicMetadataForSigning) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlinder> blinder,
      RsaBlinder::New(public_key_, public_metadata));
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
  EXPECT_THAT(
      blinder->Verify(signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

TEST_P(RsaBlinderWithPublicMetadataTest, NoPublicMetadataInBlinding) {
  const absl::string_view message = "Hello World!";
  const absl::string_view public_metadata = "pubmd!";

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlinder> blinder,
                                   RsaBlinder::New(public_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blinded_message,
                                   blinder->Blind(message));
  EXPECT_NE(blinded_message, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string blinded_signature,
      TestSignWithPublicMetadata(blinded_message, public_metadata, *rsa_key_));
  EXPECT_NE(blinded_signature, blinded_message);
  EXPECT_NE(blinded_signature, message);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string signature,
                                   blinder->Unblind(blinded_signature));
  EXPECT_NE(signature, blinded_signature);
  EXPECT_NE(signature, blinded_message);
  EXPECT_NE(signature, message);
  EXPECT_THAT(
      blinder->Verify(signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

INSTANTIATE_TEST_SUITE_P(
    RsaBlinderWithPublicMetadataTest, RsaBlinderWithPublicMetadataTest,
    testing::Values(&GetStrongRsaKeys2048, &GetAnotherStrongRsaKeys2048,
                    &GetStrongRsaKeys3072, &GetStrongRsaKeys4096));

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
