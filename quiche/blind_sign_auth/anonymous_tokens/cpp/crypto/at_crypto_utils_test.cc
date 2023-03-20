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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/crypto_utils.h"

#include <string>
#include <vector>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/strings/escaping.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/testing_utils.h"
#include "openssl/base.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

TEST(CryptoUtilsTest, BignumToStringAndBack) {
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());

  // Create a new BIGNUM using the context and set it
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> bn_1, NewBigNum());
  ASSERT_EQ(BN_set_u64(bn_1.get(), 0x124435435), 1);
  EXPECT_NE(bn_1, nullptr);
  EXPECT_EQ(BN_is_zero(bn_1.get()), 0);
  EXPECT_EQ(BN_is_one(bn_1.get()), 0);

  // Convert bn_1 to string from BIGNUM
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(
      const std::string converted_str,
      BignumToString(*bn_1, BN_num_bytes(bn_1.get())));
  // Convert the string version of bn_1 back to BIGNUM
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> bn_2,
                                   StringToBignum(converted_str));
  // Check whether the conversion back worked
  EXPECT_EQ(BN_cmp(bn_1.get(), bn_2.get()), 0);
}

TEST(CryptoUtilsTest, PowerOfTwoAndRsaSqrtTwo) {
  // Compute 2^(10-1/2).
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> sqrt2,
                                   GetRsaSqrtTwo(10));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> small_pow2,
                                   ComputePowerOfTwo(9));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> large_pow2,
                                   ComputePowerOfTwo(10));
  EXPECT_GT(BN_cmp(sqrt2.get(), small_pow2.get()), 0);
  EXPECT_LT(BN_cmp(sqrt2.get(), large_pow2.get()), 0);
}

TEST(CryptoUtilsTest, ComputeHashAcceptsNullStringView) {
  absl::StatusOr<std::string> null_hash =
      ComputeHash(absl::string_view(nullptr, 0), *EVP_sha512());
  absl::StatusOr<std::string> empty_hash = ComputeHash("", *EVP_sha512());
  std::string str;
  absl::StatusOr<std::string> empty_str_hash = ComputeHash(str, *EVP_sha512());

  QUICHE_EXPECT_OK(null_hash);
  QUICHE_EXPECT_OK(empty_hash);
  QUICHE_EXPECT_OK(empty_str_hash);

  EXPECT_EQ(*null_hash, *empty_hash);
  EXPECT_EQ(*null_hash, *empty_str_hash);
}

TEST(CryptoUtilsTest, ComputeCarmichaelLcm) {
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());

  // Suppose that N = 1019 * 1187.
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> phi_p, NewBigNum());
  ASSERT_TRUE(BN_set_word(phi_p.get(), 1019 - 1));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> phi_q, NewBigNum());
  ASSERT_TRUE(BN_set_word(phi_q.get(), 1187 - 1));
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> expected_lcm,
                                   NewBigNum());
  ASSERT_TRUE(BN_set_word(expected_lcm.get(), (1019 - 1) * (1187 - 1) / 2));

  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> lcm,
                                   ComputeCarmichaelLcm(*phi_p, *phi_q, *ctx));
  EXPECT_EQ(BN_cmp(lcm.get(), expected_lcm.get()), 0);
}

struct ComputeHashTestParam {
  const EVP_MD* hasher;
  absl::string_view input_hex;
  absl::string_view expected_digest_hex;
};

using ComputeHashTest = testing::TestWithParam<ComputeHashTestParam>;

// Returns the test parameters for ComputeHashTestParam from NIST's
// samples.
std::vector<ComputeHashTestParam> GetComputeHashTestParams() {
  std::vector<ComputeHashTestParam> params;
  params.push_back({
      EVP_sha256(),
      "af397a8b8dd73ab702ce8e53aa9f",
      "d189498a3463b18e846b8ab1b41583b0b7efc789dad8a7fb885bbf8fb5b45c5c",
  });
  params.push_back({
      EVP_sha256(),
      "59eb45bbbeb054b0b97334d53580ce03f699",
      "32c38c54189f2357e96bd77eb00c2b9c341ebebacc2945f97804f59a93238288",
  });
  params.push_back({
      EVP_sha512(),
      "16b17074d3e3d97557f9ed77d920b4b1bff4e845b345a922",
      "6884134582a760046433abcbd53db8ff1a89995862f305b887020f6da6c7b903a314721e"
      "972bf438483f452a8b09596298a576c903c91df4a414c7bd20fd1d07",
  });
  params.push_back({
      EVP_sha512(),
      "7651ab491b8fa86f969d42977d09df5f8bee3e5899180b52c968b0db057a6f02a886ad61"
      "7a84915a",
      "f35e50e2e02b8781345f8ceb2198f068ba103476f715cfb487a452882c9f0de0c720b2a0"
      "88a39d06a8a6b64ce4d6470dfeadc4f65ae06672c057e29f14c4daf9",
  });
  return params;
}

TEST_P(ComputeHashTest, ComputesHash) {
  const ComputeHashTestParam& params = GetParam();
  ASSERT_NE(params.hasher, nullptr);
  std::string data = absl::HexStringToBytes(params.input_hex);
  std::string expected_digest =
      absl::HexStringToBytes(params.expected_digest_hex);
  ANON_TOKENS_QUICHE_EXPECT_OK_AND_ASSIGN(auto computed_hash,
                                   ComputeHash(data, *params.hasher));
  EXPECT_EQ(computed_hash, expected_digest);
}

INSTANTIATE_TEST_SUITE_P(ComputeHashTests, ComputeHashTest,
                         testing::ValuesIn(GetComputeHashTestParams()));

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
