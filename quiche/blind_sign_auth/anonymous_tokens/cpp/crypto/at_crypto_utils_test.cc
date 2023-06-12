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

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/strings/escaping.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/proto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

struct IetfNewPublicExponentWithPublicMetadataTestVector {
  RSAPublicKey public_key;
  std::string public_metadata;
  std::string new_e;
};

TEST(AnonymousTokensCryptoUtilsTest, BignumToStringAndBack) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());

  // Create a new BIGNUM using the context and set it
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> bn_1, NewBigNum());
  ASSERT_EQ(BN_set_u64(bn_1.get(), 0x124435435), 1);
  EXPECT_NE(bn_1, nullptr);
  EXPECT_EQ(BN_is_zero(bn_1.get()), 0);
  EXPECT_EQ(BN_is_one(bn_1.get()), 0);

  // Convert bn_1 to string from BIGNUM
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      const std::string converted_str,
      BignumToString(*bn_1, BN_num_bytes(bn_1.get())));
  // Convert the string version of bn_1 back to BIGNUM
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> bn_2,
                                   StringToBignum(converted_str));
  // Check whether the conversion back worked
  EXPECT_EQ(BN_cmp(bn_1.get(), bn_2.get()), 0);
}

TEST(AnonymousTokensCryptoUtilsTest, PowerOfTwoAndRsaSqrtTwo) {
  // Compute 2^(10-1/2).
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> sqrt2,
                                   GetRsaSqrtTwo(10));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> small_pow2,
                                   ComputePowerOfTwo(9));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> large_pow2,
                                   ComputePowerOfTwo(10));
  EXPECT_GT(BN_cmp(sqrt2.get(), small_pow2.get()), 0);
  EXPECT_LT(BN_cmp(sqrt2.get(), large_pow2.get()), 0);
}

TEST(AnonymousTokensCryptoUtilsTest, ComputeHashAcceptsNullStringView) {
  absl::StatusOr<std::string> null_hash =
      ComputeHash(absl::string_view(nullptr, 0), *EVP_sha512());
  absl::StatusOr<std::string> empty_hash = ComputeHash("", *EVP_sha512());
  std::string str;
  absl::StatusOr<std::string> empty_str_hash = ComputeHash(str, *EVP_sha512());

  ASSERT_TRUE(null_hash.ok());
  ASSERT_TRUE(empty_hash.ok());
  ASSERT_TRUE(empty_str_hash.ok());

  EXPECT_EQ(*null_hash, *empty_hash);
  EXPECT_EQ(*null_hash, *empty_str_hash);
}

TEST(AnonymousTokensCryptoUtilsTest, ComputeCarmichaelLcm) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());

  // Suppose that N = 1019 * 1187.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> phi_p, NewBigNum());
  ASSERT_TRUE(BN_set_word(phi_p.get(), 1019 - 1));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> phi_q, NewBigNum());
  ASSERT_TRUE(BN_set_word(phi_q.get(), 1187 - 1));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> expected_lcm,
                                   NewBigNum());
  ASSERT_TRUE(BN_set_word(expected_lcm.get(), (1019 - 1) * (1187 - 1) / 2));

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> lcm,
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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto computed_hash,
                                   ComputeHash(data, *params.hasher));
  EXPECT_EQ(computed_hash, expected_digest);
}

INSTANTIATE_TEST_SUITE_P(ComputeHashTests, ComputeHashTest,
                         testing::ValuesIn(GetComputeHashTestParams()));

TEST(PublicMetadataCryptoUtilsInternalTest, PublicMetadataHashWithHKDF) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> max_value,
                                   NewBigNum());
  ASSERT_TRUE(BN_set_word(max_value.get(), 4294967295));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto key_pair, GetStrongRsaKeys2048());
  std::string input1 = "ro1";
  std::string input2 = "ro2";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> output1,
      internal::PublicMetadataHashWithHKDF(input1, key_pair.first.n(),
                                           1 + input1.size()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> another_output1,
      internal::PublicMetadataHashWithHKDF(input1, key_pair.first.n(),
                                           1 + input1.size()));
  EXPECT_EQ(BN_cmp(output1.get(), another_output1.get()), 0);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> output2,
      internal::PublicMetadataHashWithHKDF(input2, key_pair.first.n(),
                                           1 + input2.size()));
  EXPECT_NE(BN_cmp(output1.get(), output2.get()), 0);

  EXPECT_LE(BN_cmp(output1.get(), max_value.get()), 0);
  EXPECT_LE(BN_cmp(output2.get(), max_value.get()), 0);
}

TEST(PublicMetadataCryptoUtilsTest, PublicExponentHashDifferentModulus) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto key_pair_1, GetStrongRsaKeys2048());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto key_pair_2,
                                   GetAnotherStrongRsaKeys2048());
  std::string metadata = "md";
  // Check that same metadata and different modulus result in different
  // hashes.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> rsa_modulus_1,
                                   StringToBignum(key_pair_1.first.n()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp1,
      PublicMetadataExponent(*rsa_modulus_1.get(), metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_modulus_2,
                                   StringToBignum(key_pair_2.first.n()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp2,
      PublicMetadataExponent(*rsa_modulus_2.get(), metadata));
  EXPECT_NE(BN_cmp(exp1.get(), exp2.get()), 0);
}

std::vector<IetfNewPublicExponentWithPublicMetadataTestVector>
GetIetfNewPublicExponentWithPublicMetadataTestVectors() {
  std::vector<IetfNewPublicExponentWithPublicMetadataTestVector> test_vectors;

  RSAPublicKey public_key;
  public_key.set_n(absl::HexStringToBytes(
      "d6930820f71fe517bf3259d14d40209b02a5c0d3d61991c731dd7da39f8d69821552e231"
      "8d6c9ad897e603887a476ea3162c1205da9ac96f02edf31df049bd55f142134c17d4382a"
      "0e78e275345f165fbe8e49cdca6cf5c726c599dd39e09e75e0f330a33121e73976e4facb"
      "a9cfa001c28b7c96f8134f9981db6750b43a41710f51da4240fe03106c12acb1e7bb53d7"
      "5ec7256da3fddd0718b89c365410fce61bc7c99b115fb4c3c318081fa7e1b65a37774e8e"
      "50c96e8ce2b2cc6b3b367982366a2bf9924c4bafdb3ff5e722258ab705c76d43e5f1f121"
      "b984814e98ea2b2b8725cd9bc905c0bc3d75c2a8db70a7153213c39ae371b2b5dc1dafcb"
      "19d6fae9"));
  public_key.set_e(absl::HexStringToBytes("010001"));

  // Test vector 1
  test_vectors.push_back(
      {.public_key = public_key,
       .public_metadata = absl::HexStringToBytes("6d65746164617461"),
       .new_e = absl::HexStringToBytes(
           "30584b72f5cb557085106232f051d039e23358feee9204cf30ea567620e90d79e4a"
           "7a81388b1f390e18ea5240a1d8cc296ce1325128b445c48aa5a3b34fa07c324bf17"
           "bc7f1b3efebaff81d7e032948f1477493bc183d2f8d94c947c984c6f0757527615b"
           "f2a2f0ef0db5ad80ce99905beed0440b47fa5cb9a2334fea40ad88e6ef1")});

  // Test vector 2
  test_vectors.push_back(
      {.public_key = public_key,
       .public_metadata = "",
       .new_e = absl::HexStringToBytes(
           "2ed5a8d2592a11bbeef728bb39018ef5c3cf343507dd77dd156d5eec7f06f04732e"
           "4be944c5d2443d244c59e52c9fa5e8de40f55ffd0e70fbe9093d3f7be2aafd77c14"
           "b263b71c1c6b3ca2b9629842a902128fee4878392a950906fae35d6194e0d2548e5"
           "8bbc20f841188ca2fceb20b2b1b45448da5c7d1c73fb6e83fa58867397b")});

  return test_vectors;
}

TEST(PublicMetadataCryptoUtilsTest,
     IetfNewPublicExponentWithPublicMetadataTests) {
  const auto test_vectors =
      GetIetfNewPublicExponentWithPublicMetadataTestVectors();
  for (const IetfNewPublicExponentWithPublicMetadataTestVector& test_vector :
       test_vectors) {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        bssl::UniquePtr<BIGNUM> rsa_modulus,
        StringToBignum(test_vector.public_key.n()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        bssl::UniquePtr<BIGNUM> rsa_e,
        StringToBignum(test_vector.public_key.e()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> expected_new_e,
                                     StringToBignum(test_vector.new_e));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        bssl::UniquePtr<BIGNUM> modified_e,
        ComputeFinalExponentUnderPublicMetadata(
            *rsa_modulus.get(), *rsa_e.get(), test_vector.public_metadata));

    EXPECT_EQ(BN_cmp(modified_e.get(), expected_new_e.get()), 0);
  }
}

// copybara:strip_begin(internal comment)
// The input public key and the expected DER encoding are taken from the
// following Goa test:
// http://google3/privacy/net/boq/common/tokens/token_types_test.go;l=21;rcl=528885322
// copybara:strip_end
TEST(AnonymousTokensCryptoUtilsTest, RsaPssDerEncoding) {
  RSAPublicKey public_key_e_not_padded;
  RSAPublicKey public_key_e_padded;

  public_key_e_not_padded.set_n(absl::HexStringToBytes(
      "b259758bb02bc75b68b17612c9bf68c5fa05958a334c61e167bc20bcc75757c126e892"
      "10b9df3989072cf6260e6883c7cd4af4d31dde9915b69b301fbef962de8c71bd2db5ec62"
      "5da259712f86a8dc3d241e9688c82391b7bf1ebc358311f55c26be910b76f61fea408ed6"
      "92f1a9578a622c82c0fcf6f69ef3670e38bfc90f63da4f3bbbd088c8ae7a3c5a55e66f64"
      "74d562d32cce7b7edd7cf0149ca0e96cb6525e81fbba815a8f12748e34e5135f572b2e17"
      "b7ba430081597e6fb9033c005884d5935118c60d75b010f6fece7ecdcc1cb7d58d138969"
      "3d43377f4f3de949cb1e4105e792b96d7f04b0cd262ac33cffc5a890d267425e61c19e93"
      "63550f2285"));
  // A hex string of 3 bytes in length is passed.
  public_key_e_not_padded.set_e(absl::HexStringToBytes("010001"));

  public_key_e_padded.set_n(public_key_e_not_padded.n());
  // A hex string of 4 bytes in length is passed.
  public_key_e_padded.set_e(absl::HexStringToBytes("00010001"));

  // Convert both padded and not padded rsa public keys to rsa structs.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_e_not_padded,
      AnonymousTokensRSAPublicKeyToRSA(public_key_e_not_padded));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa_e_padded,
      AnonymousTokensRSAPublicKeyToRSA(public_key_e_padded));
  // Encode both padded and not padded rsa structs to DER.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string result_e_not_padded,
      RsaSsaPssPublicKeyToDerEncoding(rsa_e_not_padded.get()));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::string result_e_padded,
      RsaSsaPssPublicKeyToDerEncoding(rsa_e_padded.get()));

  std::string expected_der_encoding = absl::HexStringToBytes(
      "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a"
      "301806092a864886f70d010108300b0609608648016503040202a2030201300382010f00"
      "3082010a0282010100b259758bb02bc75b68b17612c9bf68c5fa05958a334c61e167bc20"
      "bcc75757c126e89210b9df3989072cf6260e6883c7cd4af4d31dde9915b69b301fbef962"
      "de8c71bd2db5ec625da259712f86a8dc3d241e9688c82391b7bf1ebc358311f55c26be91"
      "0b76f61fea408ed692f1a9578a622c82c0fcf6f69ef3670e38bfc90f63da4f3bbbd088c8"
      "ae7a3c5a55e66f6474d562d32cce7b7edd7cf0149ca0e96cb6525e81fbba815a8f12748e"
      "34e5135f572b2e17b7ba430081597e6fb9033c005884d5935118c60d75b010f6fece7ecd"
      "cc1cb7d58d1389693d43377f4f3de949cb1e4105e792b96d7f04b0cd262ac33cffc5a890"
      "d267425e61c19e9363550f22850203010001");

  EXPECT_EQ(result_e_not_padded, expected_der_encoding);
  EXPECT_EQ(result_e_padded, expected_der_encoding);
}

// The public key used in this test is taken from the test vectors found here:
// https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-10.html#name-issuance-protocol-2-blind-rs
TEST(AnonymousTokensCryptoUtilsTest, IetfPrivacyPassBlindRsaPublicKeyToDer) {
  RSAPublicKey public_key;
  public_key.set_n(absl::HexStringToBytes(
      "cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af1"
      "2b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0"
      "cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5e794fc98a313927687"
      "9757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c7"
      "32db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbcd78a337d17b1dba9e8"
      "28bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e1"
      "09106066983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b"
      "7e225a5f"));
  public_key.set_e(absl::HexStringToBytes("010001"));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<RSA> rsa, AnonymousTokensRSAPublicKeyToRSA(public_key));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::string result,
                                   RsaSsaPssPublicKeyToDerEncoding(rsa.get()));

  std::string expected_der_encoding = absl::HexStringToBytes(
      "30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a"
      "301806092a864886f70d010108300b0609608648016503040202a2030201300382010f00"
      "3082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab"
      "43c0df3a8c12993af12b111908d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a2"
      "24d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5"
      "e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5"
      "733f7597abe44d31c732db68a181c6cbbe607d8c0e52e0655fd9996dc584eca0be87afbc"
      "d78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2"
      "073fe49740c01f00e109106066983d21e5f83f086e2e823c879cd43cef700d2a352a9bab"
      "d612d03cad02db134b7e225a5f0203010001");

  EXPECT_EQ(result, expected_der_encoding);
}

using CreateTestKeyPairFunction =
    absl::StatusOr<std::pair<RSAPublicKey, RSAPrivateKey>>();

class CryptoUtilsTest
    : public testing::TestWithParam<CreateTestKeyPairFunction*> {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto keys_pair, (*GetParam())());
    public_key_ = std::move(keys_pair.first);
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_modulus_,
                                     StringToBignum(keys_pair.second.n()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_e_,
                                     StringToBignum(keys_pair.second.e()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_p_,
                                     StringToBignum(keys_pair.second.p()));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(rsa_q_,
                                     StringToBignum(keys_pair.second.q()));
  }

  bssl::UniquePtr<BIGNUM> rsa_modulus_;
  bssl::UniquePtr<BIGNUM> rsa_e_;
  bssl::UniquePtr<BIGNUM> rsa_p_;
  bssl::UniquePtr<BIGNUM> rsa_q_;
  RSAPublicKey public_key_;
};

TEST_P(CryptoUtilsTest, PublicExponentCoprime) {
  std::string metadata = "md";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp,
      PublicMetadataExponent(*rsa_modulus_.get(), metadata));
  int rsa_mod_size_bits = BN_num_bits(rsa_modulus_.get());
  // Check that exponent is odd.
  EXPECT_EQ(BN_is_odd(exp.get()), 1);
  // Check that exponent is small enough.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> sqrt2,
                                   GetRsaSqrtTwo(rsa_mod_size_bits / 2));
  EXPECT_LT(BN_cmp(exp.get(), sqrt2.get()), 0);
  EXPECT_LT(BN_cmp(exp.get(), rsa_p_.get()), 0);
  EXPECT_LT(BN_cmp(exp.get(), rsa_q_.get()), 0);
}

TEST_P(CryptoUtilsTest, PublicExponentHash) {
  std::string metadata1 = "md1";
  std::string metadata2 = "md2";
  // Check that hash is deterministic.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp1,
      PublicMetadataExponent(*rsa_modulus_.get(), metadata1));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> another_exp1,
      PublicMetadataExponent(*rsa_modulus_.get(), metadata1));
  EXPECT_EQ(BN_cmp(exp1.get(), another_exp1.get()), 0);
  // Check that hashes are distinct for different metadata.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> exp2,
      PublicMetadataExponent(*rsa_modulus_.get(), metadata2));
  EXPECT_NE(BN_cmp(exp1.get(), exp2.get()), 0);
}

TEST_P(CryptoUtilsTest, FinalExponentCoprime) {
  std::string metadata = "md";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> final_exponent,
      ComputeFinalExponentUnderPublicMetadata(*rsa_modulus_.get(),
                                              *rsa_e_.get(), metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(BnCtxPtr ctx, GetAndStartBigNumCtx());

  // Check that exponent is odd.
  EXPECT_EQ(BN_is_odd(final_exponent.get()), 1);
  // Check that exponent is co-prime to factors of the rsa modulus.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> gcd_p_fe,
                                   NewBigNum());
  ASSERT_EQ(
      BN_gcd(gcd_p_fe.get(), rsa_p_.get(), final_exponent.get(), ctx.get()), 1);
  EXPECT_EQ(BN_cmp(gcd_p_fe.get(), BN_value_one()), 0);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> gcd_q_fe,
                                   NewBigNum());
  ASSERT_EQ(
      BN_gcd(gcd_q_fe.get(), rsa_q_.get(), final_exponent.get(), ctx.get()), 1);
  EXPECT_EQ(BN_cmp(gcd_q_fe.get(), BN_value_one()), 0);
}

TEST_P(CryptoUtilsTest, DeterministicModificationOfPublicExponentWithMetadata) {
  std::string metadata = "md";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> public_exp_1,
      ComputeFinalExponentUnderPublicMetadata(*rsa_modulus_.get(),
                                              *rsa_e_.get(), metadata));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> public_exp_2,
      ComputeFinalExponentUnderPublicMetadata(*rsa_modulus_.get(),
                                              *rsa_e_.get(), metadata));

  EXPECT_EQ(BN_cmp(public_exp_1.get(), public_exp_2.get()), 0);
}

TEST_P(CryptoUtilsTest, DifferentPublicExponentWithDifferentPublicMetadata) {
  std::string metadata_1 = "md1";
  std::string metadata_2 = "md2";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> public_exp_1,
      ComputeFinalExponentUnderPublicMetadata(*rsa_modulus_.get(),
                                              *rsa_e_.get(), metadata_1));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      bssl::UniquePtr<BIGNUM> public_exp_2,
      ComputeFinalExponentUnderPublicMetadata(*rsa_modulus_.get(),
                                              *rsa_e_.get(), metadata_2));
  // Check that exponent is different in all keys
  EXPECT_NE(BN_cmp(public_exp_1.get(), public_exp_2.get()), 0);
  EXPECT_NE(BN_cmp(public_exp_1.get(), rsa_e_.get()), 0);
  EXPECT_NE(BN_cmp(public_exp_2.get(), rsa_e_.get()), 0);
}

TEST_P(CryptoUtilsTest, ModifiedPublicExponentWithEmptyPublicMetadata) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(bssl::UniquePtr<BIGNUM> new_public_exp,
                                   ComputeFinalExponentUnderPublicMetadata(
                                       *rsa_modulus_.get(), *rsa_e_.get(), ""));

  EXPECT_NE(BN_cmp(new_public_exp.get(), rsa_e_.get()), 0);
}

INSTANTIATE_TEST_SUITE_P(CryptoUtilsTest, CryptoUtilsTest,
                         testing::Values(&GetStrongRsaKeys2048,
                                         &GetAnotherStrongRsaKeys2048,
                                         &GetStrongRsaKeys3072,
                                         &GetStrongRsaKeys4096));

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
