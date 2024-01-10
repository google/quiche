// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_config.h"

#include <cstdint>
#include <cstring>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/load_balancer/load_balancer_server_id.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"

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
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(7, 4, 10).has_value()),
      "Invalid LoadBalancerConfig Config ID 7 Server ID Length 4 "
      "Nonce Length 10");
  // Bad Server ID lengths.
  EXPECT_QUIC_BUG(EXPECT_FALSE(LoadBalancerConfig::Create(
                                   2, 0, 10, absl::string_view(raw_key, 16))
                                   .has_value()),
                  "Invalid LoadBalancerConfig Config ID 2 Server ID Length 0 "
                  "Nonce Length 10");
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(6, 16, 4).has_value()),
      "Invalid LoadBalancerConfig Config ID 6 Server ID Length 16 "
      "Nonce Length 4");
  // Bad Nonce lengths.
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(6, 4, 2).has_value()),
      "Invalid LoadBalancerConfig Config ID 6 Server ID Length 4 "
      "Nonce Length 2");
  EXPECT_QUIC_BUG(
      EXPECT_FALSE(LoadBalancerConfig::CreateUnencrypted(6, 1, 17).has_value()),
      "Invalid LoadBalancerConfig Config ID 6 Server ID Length 1 "
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

// Tests for Encrypt() and Decrypt() are in LoadBalancerEncoderTest and
// LoadBalancerDecoderTest, respectively.

TEST_F(LoadBalancerConfigTest, ConfigIsCopyable) {
  const uint8_t ptext[] = {0x00, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f,
                           0xee, 0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5};
  uint8_t ctext[] = {0x00, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2,
                     0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3};
  const char key[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                      0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
  auto config = LoadBalancerConfig::Create(0, 8, 8, absl::string_view(key, 16));
  ASSERT_TRUE(config.has_value());
  auto config2 = config;
  ASSERT_TRUE(config2.has_value());
  uint8_t temp_ptext[sizeof(ptext)];  // the input will be overwritten, so copy
  memcpy(temp_ptext, ptext, sizeof(ptext));
  QuicConnectionId cid1 =
      config->Encrypt(absl::Span<uint8_t>(temp_ptext, sizeof(ptext)));
  EXPECT_EQ(cid1.length(), sizeof(ctext));
  EXPECT_EQ(memcmp(cid1.data(), ctext, sizeof(ctext)), 0);
  memcpy(temp_ptext, ptext, sizeof(ptext));
  QuicConnectionId cid2 =
      config2->Encrypt(absl::Span<uint8_t>(temp_ptext, sizeof(ptext)));
  EXPECT_EQ(cid2.length(), sizeof(ctext));
  EXPECT_EQ(memcmp(cid2.data(), ctext, sizeof(ctext)), 0);
}

TEST_F(LoadBalancerConfigTest, OnePassEncryptAndDecryptIgnoreAdditionalBytes) {
  uint8_t ptext[] = {0x00, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f, 0xee,
                     0x08, 0x0d, 0xbf, 0x48, 0xc0, 0xd1, 0xe5, 0xda, 0x41};
  uint8_t ctext[] = {0x00, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9, 0xb2, 0xb9,
                     0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c, 0xc3, 0xda, 0x41};
  const char key[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                      0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
  auto config = LoadBalancerConfig::Create(0, 8, 8, absl::string_view(key, 16));
  ASSERT_TRUE(config.has_value());
  LoadBalancerServerId original_server_id(absl::Span<uint8_t>(&ptext[1], 8));
  QuicConnectionId cid =
      config->Encrypt(absl::Span<uint8_t>(ptext, sizeof(ptext)));
  EXPECT_EQ(cid.length(), sizeof(ctext));
  EXPECT_EQ(memcmp(cid.data(), ctext, sizeof(ctext)), 0);
  LoadBalancerServerId server_id = config->Decrypt(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t *>(cid.data()), cid.length()));
  EXPECT_EQ(server_id, original_server_id);
}

TEST_F(LoadBalancerConfigTest, FourPassEncryptAndDecryptIgnoreAdditionalBytes) {
  uint8_t ptext[] = {0x00, 0xed, 0x79, 0x3a, 0xee,
                     0x08, 0x0d, 0xbf, 0xda, 0x41};
  uint8_t ctext[] = {0x00, 0x41, 0x26, 0xee, 0x38,
                     0xbf, 0x54, 0x54, 0xda, 0x41};
  const char key[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                      0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
  auto config = LoadBalancerConfig::Create(0, 3, 4, absl::string_view(key, 16));
  ASSERT_TRUE(config.has_value());
  LoadBalancerServerId original_server_id(absl::Span<uint8_t>(&ptext[1], 3));
  QuicConnectionId cid =
      config->Encrypt(absl::Span<uint8_t>(ptext, sizeof(ptext)));
  EXPECT_EQ(cid.length(), sizeof(ctext));
  EXPECT_EQ(memcmp(cid.data(), ctext, sizeof(ctext)), 0);
  LoadBalancerServerId server_id = config->Decrypt(absl::Span<const uint8_t>(
      reinterpret_cast<const uint8_t *>(cid.data()), cid.length()));
  EXPECT_EQ(server_id, original_server_id);
}

}  // namespace

}  // namespace test

}  // namespace quic
