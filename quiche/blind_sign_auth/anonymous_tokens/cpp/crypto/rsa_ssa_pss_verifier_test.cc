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
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

// TODO(b/259581423): Add tests incorporating blinder and signer.
// TODO(b/275956922): Consolidate all tests that use IETF test vectors into one
// E2E test.
TEST(RsaSsaPssVerifier, SuccessfulVerification) {
  const IetfStandardRsaBlindSignatureTestVector test_vec =
      GetIetfStandardRsaBlindSignatureTestVector();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const auto test_keys,
                                   GetIetfStandardRsaBlindSignatureTestKeys());
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier, RsaSsaPssVerifier::New(salt_length, sig_hash,
                                                  mgf1_hash, test_keys.first));
  QUICHE_EXPECT_OK(verifier->Verify(test_vec.signature, test_vec.message));
}

TEST(RsaSsaPssVerifier, InvalidSignature) {
  const IetfStandardRsaBlindSignatureTestVector test_vec =
      GetIetfStandardRsaBlindSignatureTestVector();
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const auto test_keys,
                                   GetIetfStandardRsaBlindSignatureTestKeys());
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier, RsaSsaPssVerifier::New(salt_length, sig_hash,
                                                  mgf1_hash, test_keys.first));
  // corrupt signature
  std::string wrong_sig = test_vec.signature;
  wrong_sig.replace(10, 1, "x");

  EXPECT_THAT(
      verifier->Verify(wrong_sig, test_vec.message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                testing::HasSubstr("verification failed")));
}

TEST(RsaSsaPssVerifier, InvalidVerificationKey) {
  const IetfStandardRsaBlindSignatureTestVector test_vec =
      GetIetfStandardRsaBlindSignatureTestVector();
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  // wrong key
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto new_keys_pair, GetStandardRsaKeyPair());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto verifier,
      RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash,
                             new_keys_pair.first));

  EXPECT_THAT(
      verifier->Verify(test_vec.signature, test_vec.message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                testing::HasSubstr("verification failed")));
}

TEST(RsaSsaPssVerifierTestWithPublicMetadata,
     EmptyMessageStandardVerificationSuccess) {
  absl::string_view message = "";
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(const auto test_key,
                                   GetStandardRsaKeyPair());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto private_key, AnonymousTokensRSAPrivateKeyToRSA(test_key.second));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(message, test_key.first, sig_hash, mgf1_hash,
                            salt_length));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSign(encoded_message, private_key.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_key.first));
  QUICHE_EXPECT_OK(verifier->Verify(potentially_insecure_signature, message));
}

// TODO(b/275956922): Consolidate all tests that use IETF test vectors into one
// E2E test.
TEST(RsaSsaPssVerifierTestWithPublicMetadata,
     IetfRsaBlindSignaturesWithPublicMetadataTestVectorsSuccess) {
  auto test_vectors = GetIetfRsaBlindSignatureWithPublicMetadataTestVectors();
  const EVP_MD *sig_hash = EVP_sha384();   // Owned by BoringSSL
  const EVP_MD *mgf1_hash = EVP_sha384();  // Owned by BoringSSL
  const int salt_length = kSaltLengthInBytes48;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const auto test_key,
      GetIetfRsaBlindSignatureWithPublicMetadataTestKeys());
  for (const auto &test_vector : test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        auto verifier,
        RsaSsaPssVerifier::New(salt_length, sig_hash, mgf1_hash, test_key.first,
                               test_vector.public_metadata));
    QUICHE_EXPECT_OK(verifier->Verify(
        test_vector.signature,
        MaskMessageConcat(test_vector.message_mask, test_vector.message)));
  }
}

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class RsaSsaPssVerifierTestWithPublicMetadata
    : public ::testing::TestWithParam<CreateTestKeyPairFunction *> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    public_key_ = std::move(keys_pair.first);
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        private_key_, AnonymousTokensRSAPrivateKeyToRSA(keys_pair.second));
    // NOTE: using recommended RsaSsaPssParams
    sig_hash_ = EVP_sha384();
    mgf1_hash_ = EVP_sha384();
    salt_length_ = kSaltLengthInBytes48;
  }

  RSAPublicKey public_key_;
  bssl::UniquePtr<RSA> private_key_;
  const EVP_MD *sig_hash_;   // Owned by BoringSSL.
  const EVP_MD *mgf1_hash_;  // Owned by BoringSSL.
  int salt_length_;
};

// This test only tests whether the implemented verfier 'verifies' properly
// under some public metadata. The outline of method calls in this test should
// not be assumed a secure signature scheme (and used in other places) as the
// security has not been proven/analyzed.
TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierWorksWithPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier, RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_,
                                            public_key_, public_metadata));
  QUICHE_EXPECT_OK(verifier->Verify(potentially_insecure_signature, message));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierFailsToVerifyWithWrongPublicMetadata) {
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
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier, RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_,
                                            public_key_, public_metadata_2));
  EXPECT_THAT(
      verifier->Verify(potentially_insecure_signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierFailsToVerifyWithEmptyPublicMetadata) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  absl::string_view empty_public_metadata = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_,
                             empty_public_metadata));
  EXPECT_THAT(
      verifier->Verify(potentially_insecure_signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       VerifierFailsToVerifyWithoutPublicMetadataSupport) {
  absl::string_view message = "Hello World!";
  absl::string_view public_metadata = "pubmd!";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier,
      RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_, public_key_));
  EXPECT_THAT(
      verifier->Verify(potentially_insecure_signature, message),
      quiche::test::StatusIs(absl::StatusCode::kInvalidArgument,
                                  ::testing::HasSubstr("verification failed")));
}

TEST_P(RsaSsaPssVerifierTestWithPublicMetadata,
       EmptyMessageEmptyPublicMetadataVerificationSuccess) {
  absl::string_view message = "";
  absl::string_view public_metadata = "";
  std::string augmented_message =
      EncodeMessagePublicMetadata(message, public_metadata);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string encoded_message,
      EncodeMessageForTests(augmented_message, public_key_, sig_hash_,
                            mgf1_hash_, salt_length_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string potentially_insecure_signature,
      TestSignWithPublicMetadata(encoded_message, public_metadata,
                                 *private_key_.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto verifier, RsaSsaPssVerifier::New(salt_length_, sig_hash_, mgf1_hash_,
                                            public_key_, public_metadata));
  QUICHE_EXPECT_OK(verifier->Verify(potentially_insecure_signature, message));
}

INSTANTIATE_TEST_SUITE_P(RsaSsaPssVerifierTestWithPublicMetadata,
                         RsaSsaPssVerifierTestWithPublicMetadata,
                         ::testing::Values(&GetStrongRsaKeys2048,
                                           &GetAnotherStrongRsaKeys2048,
                                           &GetStrongRsaKeys3072,
                                           &GetStrongRsaKeys4096));

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
