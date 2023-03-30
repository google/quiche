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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/rsa_blind_signer.h"

#include <memory>
#include <random>
#include <string>
#include <utility>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/rsa_ssa_pss_verifier.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/digest.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class RsaBlindSignerTest
    : public ::testing::TestWithParam<CreateTestKeyPairFunction *> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    public_key_ = std::move(keys_pair.first);
    private_key_ = std::move(keys_pair.second);
    generator_.seed(0);
    // NOTE: using recommended RsaSsaPssParams
    sig_hash_ = EVP_sha384();
    mgf1_hash_ = EVP_sha384();
    salt_length_ = kSaltLengthInBytes48;
  }

  RSAPrivateKey private_key_;
  RSAPublicKey public_key_;
  std::mt19937_64 generator_;
  const EVP_MD *sig_hash_;   // Owned by BoringSSL.
  const EVP_MD *mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
  std::uniform_int_distribution<int> distr_u8_ =
      std::uniform_int_distribution<int>{0, 255};
};

// This test only tests whether the implemented signer 'signs' properly. The
// outline of method calls in this test should not be assumed a secure signature
// scheme (and used in other places) as the security has not been
// proven/analyzed.
//
// Test for the standard signer does not take public metadata as a parameter
// which means public metadata is set to std::nullopt.
TEST_P(RsaBlindSignerTest, StandardSignerWorks) {
  absl::string_view message = "Hello World!";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(message, public_key_, sig_hash_, mgf1_hash_,
                            salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlindSigner> signer,
                                   RsaBlindSigner::New(private_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_));
  QUICHE_EXPECT_OK(verifier->Verify(potentially_insecure_signature, message));
}

TEST_P(RsaBlindSignerTest, SignerFails) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::unique_ptr<RsaBlindSigner> signer,
                                   RsaBlindSigner::New(private_key_));
  absl::string_view message = "Hello World!";
  EXPECT_THAT(signer->Sign(message),
              quiche::test::StatusIs(
                  absl::StatusCode::kInternal,
                  ::testing::HasSubstr("Expected blind data size")));

  int sig_size = public_key_.n().size();
  std::string message2 = RandomString(sig_size, &distr_u8_, &generator_);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string insecure_sig,
                                   signer->Sign(message2));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_));
  EXPECT_THAT(
      verifier->Verify(insecure_sig, message2),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

INSTANTIATE_TEST_SUITE_P(RsaBlindSignerTest, RsaBlindSignerTest,
                         ::testing::Values(&GetStrongRsaKeys2048,
                                           &GetAnotherStrongRsaKeys2048,
                                           &GetStrongRsaKeys3072,
                                           &GetStrongRsaKeys4096));

class RsaBlindSignerTestWithPublicMetadata
    : public ::testing::TestWithParam<CreateTestKeyPairFunction *> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    public_key_ = std::move(keys_pair.first);
    private_key_ = std::move(keys_pair.second);
    // NOTE: using recommended RsaSsaPssParams
    sig_hash_ = EVP_sha384();
    mgf1_hash_ = EVP_sha384();
    salt_length_ = kSaltLengthInBytes48;
  }

  RSAPrivateKey private_key_;
  RSAPublicKey public_key_;
  const EVP_MD *sig_hash_;   // Owned by BoringSSL.
  const EVP_MD *mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
};

// This test only tests whether the implemented signer 'signs' properly under
// some public metadata. The outline of method calls in this test should not
// be assumed a secure signature scheme (and used in other places) as the
// security has not been proven/analyzed.
TEST_P(RsaBlindSignerTestWithPublicMetadata, SignerWorksWithPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier, RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_,
                                            public_key_, public_metadata));
  QUICHE_EXPECT_OK(verifier->Verify(potentially_insecure_signature, message));
}

TEST_P(RsaBlindSignerTestWithPublicMetadata,
       SignerWorksWithEmptyPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view empty_public_metadata = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, empty_public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, empty_public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             empty_public_metadata));
  QUICHE_EXPECT_OK(verifier->Verify(potentially_insecure_signature, message));
}

TEST_P(RsaBlindSignerTestWithPublicMetadata,
       SignatureFailstoVerifyWithWrongPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  absl::string_view public_metadata_2 = "pubmd2";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier, RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_,
                                            public_key_, public_metadata_2));
  EXPECT_THAT(
      verifier->Verify(potentially_insecure_signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

TEST_P(RsaBlindSignerTestWithPublicMetadata,
       SignatureFailsToVerifyWithNoPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  absl::string_view public_metadata_2 = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<RsaBlindSigner> signer,
      RsaBlindSigner::New(private_key_, public_metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string potentially_insecure_signature,
                                   signer->Sign(encoded_message));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier, RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_,
                                            public_key_, public_metadata_2));
  EXPECT_THAT(
      verifier->Verify(potentially_insecure_signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

INSTANTIATE_TEST_SUITE_P(
    RsaBlindSignerTestWithPublicMetadata, RsaBlindSignerTestWithPublicMetadata,
    ::testing::Values(&GetStrongRsaKeys2048, &GetAnotherStrongRsaKeys2048,
                      &GetStrongRsaKeys3072, &GetStrongRsaKeys4096));

// TODO(b/275956922): Consolidate all tests that use IETF test vectors into one
// E2E test.
//
// This test uses IETF test vectors for RSA blind signatures with public
// metadata. The vectors includes tests for public metadata set to an empty
// string as well as a non-empty value.
TEST(IetfRsaBlindSignerTest,
     IetfRsaBlindSignaturesWithPublicMetadataTestVectorsSuccess) {
  auto test_vectors = GetIetfRsaBlindSignatureWithPublicMetadataTestVectors();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto test_key,
      GetIetfRsaBlindSignatureWithPublicMetadataTestKeys());
  for (const auto &test_vector : test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        std::unique_ptr<RsaBlindSigner> signer,
        RsaBlindSigner::New(test_key.second, test_vector.public_metadata));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string blind_signature,
                                     signer->Sign(test_vector.blinded_message));
    EXPECT_EQ(blind_signature, test_vector.blinded_signature);
  }
}

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
