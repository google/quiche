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

#ifndef THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_SSA_PSS_VERIFIER_H_
#define THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_SSA_PSS_VERIFIER_H_

#include <stdint.h>

#include <memory>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/verifier.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
// #include "quiche/common/platform/api/quiche_export.h"

namespace private_membership {
namespace anonymous_tokens {

// RsaSsaPssVerifier is able to verify an unblinded token (signature) against an
// inputted message using a public key and other input parameters.
class QUICHE_EXPORT RsaSsaPssVerifier : public Verifier {
 public:
  // TODO(b/259581423) Change absl::string_view public_metadata to
  // std::optional<absl::string_view> public_metadata to help determine whether
  // public metadata is supported.
  static absl::StatusOr<std::unique_ptr<RsaSsaPssVerifier>> New(
      int salt_length, const EVP_MD* sig_hash, const EVP_MD* mgf1_hash,
      const RSAPublicKey& public_key, absl::string_view public_metadata = "");

  // Verifies the signature.
  //
  // Returns OkStatus() on successful verification. Otherwise returns an error.
  absl::Status Verify(absl::string_view unblind_token,
                      absl::string_view message) override;

 private:
  // Use `New` to construct
  RsaSsaPssVerifier(int salt_length, const EVP_MD* sig_hash,
                    const EVP_MD* mgf1_hash,
                    bssl::UniquePtr<RSA> rsa_public_key,
                    bssl::UniquePtr<BIGNUM> rsa_modulus,
                    bssl::UniquePtr<BIGNUM> augmented_rsa_e);

  const int salt_length_;
  const EVP_MD* sig_hash_;   // Owned by BoringSSL.
  const EVP_MD* mgf1_hash_;  // Owned by BoringSSL.

  const bssl::UniquePtr<RSA> rsa_public_key_;
  // Storing RSA modulus separately for helping with BN computations.
  const bssl::UniquePtr<BIGNUM> rsa_modulus_;
  // If public metadata is not supported, modified_rsa_e_ will be a null
  // pointer.
  const bssl::UniquePtr<BIGNUM> augmented_rsa_e_;
};

}  // namespace anonymous_tokens
}  // namespace private_membership

#endif  // THIRD_PARTY_ANONYMOUS_TOKENS_CPP_CRYPTO_RSA_SSA_PSS_VERIFIER_H_
