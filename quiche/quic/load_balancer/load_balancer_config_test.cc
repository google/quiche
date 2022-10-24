// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_config.h"

#include <cstdint>

#include "absl/types/span.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {

namespace test {

namespace {

constexpr char raw_key[] = {
    0xfd, 0xf7, 0x26, 0xa9, 0x89, 0x3e, 0xc0, 0x5c,
    0x06, 0x32, 0xd3, 0x95, 0x66, 0x80, 0xba, 0xf0,
};

class LoadBalancerConfigTest : public QuicTest {};

TEST_F(LoadBalancerConfigTest, InvalidParams) {
  // Bogus config_id.
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(3, 4, 10).has_value()),
      "Invalid LoadBalancerConfig Config ID 3 Server ID Length 4 "
      "Nonce Length 10");
  // Bad Server ID lengths.
  EXPECT_QUIC_BUG(EXPECT_FALSE(LoadBalancerConfig::Create(
                                   2, 0, 10, absl::string_view(raw_key, 16))
                                   .has_value()),
                  "Invalid LoadBalancerConfig Config ID 2 Server ID Length 0 "
                  "Nonce Length 10");
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(2, 16, 4).has_value()),
      "Invalid LoadBalancerConfig Config ID 2 Server ID Length 16 "
      "Nonce Length 4");
  // Bad Nonce lengths.
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(2, 4, 2).has_value()),
      "Invalid LoadBalancerConfig Config ID 2 Server ID Length 4 "
      "Nonce Length 2");
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(2, 1, 17).has_value()),
      "Invalid LoadBalancerConfig Config ID 2 Server ID Length 1 "
      "Nonce Length 17");
  // Bad key lengths.
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::Create(2, 3, 4, "").has_value()),
      "Invalid LoadBalancerConfig Key Length: 0");
  EXPECT_QUIC_BUG(EXPECT_FALSE(LoadBalancerConfig::Create(
                                   2, 3, 4, absl::string_view(raw_key, 10))
                                   .has_value()),
                  "Invalid LoadBalancerConfig Key Length: 10");
  EXPECT_QUIC_BUG(EXPECT_FALSE(LoadBalancerConfig::Create(
                                   0, 3, 4, absl::string_view(raw_key, 17))
                                   .has_value()),
                  "Invalid LoadBalancerConfig Key Length: 17");
}

TEST_F(LoadBalancerConfigTest, ValidParams) {
  // Test valid configurations and accessors
  auto config = LoadBalancerConfig::CreateUnencrypted(0, 3, 4);
  EXPECT_TRUE(config.has_value());
  EXPECT_EQ(config->config_id(), 0);
  EXPECT_EQ(config->server_id_len(), 3);
  EXPECT_EQ(config->nonce_len(), 4);
  EXPECT_EQ(config->plaintext_len(), 7);
  EXPECT_EQ(config->total_len(), 8);
  EXPECT_FALSE(config->IsEncrypted());
  auto config2 =
      LoadBalancerConfig::Create(2, 6, 7, absl::string_view(raw_key, 16));
  EXPECT_TRUE(config.has_value());
  EXPECT_EQ(config2->config_id(), 2);
  EXPECT_EQ(config2->server_id_len(), 6);
  EXPECT_EQ(config2->nonce_len(), 7);
  EXPECT_EQ(config2->plaintext_len(), 13);
  EXPECT_EQ(config2->total_len(), 14);
  EXPECT_TRUE(config2->IsEncrypted());
}

// Compare EncryptionPass() results to the example in
// draft-ietf-quic-load-balancers-15, Section 4.3.2.
TEST_F(LoadBalancerConfigTest, TestEncryptionPassExample) {
  auto config =
      LoadBalancerConfig::Create(0, 3, 4, absl::string_view(raw_key, 16));
  EXPECT_TRUE(config.has_value());
  EXPECT_TRUE(config->IsEncrypted());
  std::array<uint8_t, 7> bytes = {0x31, 0x44, 0x1a, 0x9c, 0x69, 0xc2, 0x75};
  std::array<uint8_t, 7> pass1 = {0x31, 0x44, 0x1a, 0x9f, 0x1a, 0x5b, 0x6b};
  std::array<uint8_t, 7> pass2 = {0x02, 0x8e, 0x1b, 0x5f, 0x1a, 0x5b, 0x6b};
  std::array<uint8_t, 7> pass3 = {0x02, 0x8e, 0x1b, 0x54, 0x94, 0x97, 0x62};
  std::array<uint8_t, 7> pass4 = {0x8e, 0x9a, 0x91, 0xf4, 0x94, 0x97, 0x62};

  // Input is too short.
  EXPECT_FALSE(config->EncryptionPass(absl::Span<uint8_t>(bytes.data(), 6), 0));
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 1));
  EXPECT_EQ(bytes, pass1);
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 2));
  EXPECT_EQ(bytes, pass2);
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 3));
  EXPECT_EQ(bytes, pass3);
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 4));
  EXPECT_EQ(bytes, pass4);
}

TEST_F(LoadBalancerConfigTest, EncryptionPassPlaintext) {
  auto config = LoadBalancerConfig::CreateUnencrypted(0, 3, 4);
  std::array<uint8_t, 7> bytes = {0x31, 0x44, 0x1a, 0x9c, 0x69, 0xc2, 0x75};
  EXPECT_FALSE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 1));
}

// Check that the encryption pass code can decode its own ciphertext. Various
// pointer errors could cause the code to overwrite bits that contain
// important information.
TEST_F(LoadBalancerConfigTest, EncryptionPassesAreReversible) {
  auto config =
      LoadBalancerConfig::Create(0, 3, 4, absl::string_view(raw_key, 16));
  std::array<uint8_t, 7> bytes = {
      0x31, 0x44, 0x1a, 0x9c, 0x69, 0xc2, 0x75,
  };
  std::array<uint8_t, 7> orig_bytes;
  memcpy(orig_bytes.data(), bytes.data(), bytes.size());
  // Work left->right and right->left passes.
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 1));
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 2));
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 2));
  EXPECT_TRUE(config->EncryptionPass(absl::Span<uint8_t>(bytes), 1));
  EXPECT_EQ(bytes, orig_bytes);
}

TEST_F(LoadBalancerConfigTest, InvalidBlockEncryption) {
  uint8_t pt[kLoadBalancerBlockSize], ct[kLoadBalancerBlockSize];
  auto pt_config = LoadBalancerConfig::CreateUnencrypted(0, 8, 8);
  EXPECT_FALSE(pt_config->BlockEncrypt(pt, ct));
  EXPECT_FALSE(pt_config->BlockDecrypt(ct, pt));
  EXPECT_FALSE(pt_config->EncryptionPass(absl::Span<uint8_t>(pt), 0));
  auto small_cid_config =
      LoadBalancerConfig::Create(0, 3, 4, absl::string_view(raw_key, 16));
  EXPECT_TRUE(small_cid_config->BlockEncrypt(pt, ct));
  EXPECT_FALSE(small_cid_config->BlockDecrypt(ct, pt));
  auto block_config =
      LoadBalancerConfig::Create(0, 8, 8, absl::string_view(raw_key, 16));
  EXPECT_TRUE(block_config->BlockEncrypt(pt, ct));
  EXPECT_TRUE(block_config->BlockDecrypt(ct, pt));
}

// Block decrypt test from the Test Vector in
// draft-ietf-quic-load-balancers-15, Appendix B.
TEST_F(LoadBalancerConfigTest, BlockEncryptionExample) {
  const uint8_t ptext[] = {0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f,
                           0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5};
  const uint8_t ctext[] = {0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2,
                           0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3};
  const char key[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                      0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
  uint8_t result[sizeof(ptext)];
  auto config = LoadBalancerConfig::Create(0, 8, 8, absl::string_view(key, 16));
  EXPECT_TRUE(config->BlockEncrypt(ptext, result));
  EXPECT_EQ(memcmp(result, ctext, sizeof(ctext)), 0);
  EXPECT_TRUE(config->BlockDecrypt(ctext, result));
  EXPECT_EQ(memcmp(result, ptext, sizeof(ptext)), 0);
}

TEST_F(LoadBalancerConfigTest, ConfigIsCopyable) {
  const uint8_t ptext[] = {0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f,
                           0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5};
  const uint8_t ctext[] = {0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2,
                           0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3};
  const char key[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                      0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
  uint8_t result[sizeof(ptext)];
  auto config = LoadBalancerConfig::Create(0, 8, 8, absl::string_view(key, 16));
  auto config2 = config;
  EXPECT_TRUE(config->BlockEncrypt(ptext, result));
  EXPECT_EQ(memcmp(result, ctext, sizeof(ctext)), 0);
  EXPECT_TRUE(config2->BlockEncrypt(ptext, result));
  EXPECT_EQ(memcmp(result, ctext, sizeof(ctext)), 0);
}

}  // namespace

}  // namespace test

}  // namespace quic
