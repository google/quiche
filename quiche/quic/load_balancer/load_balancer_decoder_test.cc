// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_decoder.h"

#include <cstdint>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/load_balancer/load_balancer_config.h"
#include "quiche/quic/load_balancer/load_balancer_server_id.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {

namespace test {

namespace {

class LoadBalancerDecoderTest : public QuicTest {};

// Convenience function to shorten the code. Does not check if |array| is long
// enough or |length| is valid for a server ID.
inline LoadBalancerServerId MakeServerId(const uint8_t array[],
                                         const uint8_t length) {
  return *LoadBalancerServerId::Create(
      absl::Span<const uint8_t>(array, length));
}

constexpr char kRawKey[] = {0x8f, 0x95, 0xf0, 0x92, 0x45, 0x76, 0x5f, 0x80,
                            0x25, 0x69, 0x34, 0xe5, 0x0c, 0x66, 0x20, 0x7f};
constexpr absl::string_view kKey(kRawKey, kLoadBalancerKeyLen);
constexpr uint8_t kServerId[] = {0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f, 0x5f,
                                 0xab, 0x65, 0xba, 0x04, 0xc3, 0x33, 0x0a};

struct LoadBalancerDecoderTestCase {
  LoadBalancerConfig config;
  QuicConnectionId connection_id;
  LoadBalancerServerId server_id;
};

TEST_F(LoadBalancerDecoderTest, UnencryptedConnectionIdTestVectors) {
  const struct LoadBalancerDecoderTestCase test_vectors[2] = {
      {
          *LoadBalancerConfig::CreateUnencrypted(0, 3, 4),
          QuicConnectionId({0x07, 0xed, 0x79, 0x3a, 0x80, 0x49, 0x71, 0x8a}),
          MakeServerId(kServerId, 3),
      },
      {
          *LoadBalancerConfig::CreateUnencrypted(1, 8, 5),
          QuicConnectionId({0x2d, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f,
                            0x5f, 0xee, 0x15, 0xda, 0x27, 0xc4}),
          MakeServerId(kServerId, 8),
      }};
  for (const auto& test : test_vectors) {
    LoadBalancerDecoder decoder;
    EXPECT_TRUE(decoder.AddConfig(test.config));
    EXPECT_EQ(decoder.GetServerId(test.connection_id), test.server_id);
  }
}

// Compare test vectors from Appendix B of draft-ietf-quic-load-balancers-15.
TEST_F(LoadBalancerDecoderTest, DecoderTestVectors) {
  // Try (1) the "standard" CID length of 8
  // (2) server_id_len > nonce_len, so there is a fourth decryption pass
  // (3) the single-pass encryption case
  // (4) An even total length.
  const struct LoadBalancerDecoderTestCase test_vectors[4] = {
      {
          *LoadBalancerConfig::Create(0, 3, 4, kKey),
          QuicConnectionId({0x07, 0x41, 0x26, 0xee, 0x38, 0xbf, 0x54, 0x54}),
          MakeServerId(kServerId, 3),
      },
      {
          *LoadBalancerConfig::Create(1, 10, 5, kKey),
          QuicConnectionId({0x2f, 0xcd, 0x3f, 0x57, 0x2d, 0x4e, 0xef, 0xb0,
                            0x46, 0xfd, 0xb5, 0x1d, 0x16, 0x4e, 0xfc, 0xcc}),
          MakeServerId(kServerId, 10),
      },
      {
          *LoadBalancerConfig::Create(2, 8, 8, kKey),
          QuicConnectionId({0x50, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9,
                            0xb2, 0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c,
                            0xc3}),
          MakeServerId(kServerId, 8),
      },
      {
          *LoadBalancerConfig::Create(3, 9, 9, kKey),
          QuicConnectionId({0x72, 0x12, 0x4d, 0x1e, 0xb8, 0xfb, 0xb2, 0x1e,
                            0x4a, 0x49, 0x0c, 0xa5, 0x3c, 0xfe, 0x21, 0xd0,
                            0x4a, 0xe6, 0x3a}),
          MakeServerId(kServerId, 9),
      },
  };
  for (const auto& test : test_vectors) {
    LoadBalancerDecoder decoder;
    EXPECT_TRUE(decoder.AddConfig(test.config));
    EXPECT_EQ(decoder.GetServerId(test.connection_id), test.server_id);
  }
}

TEST_F(LoadBalancerDecoderTest, NoServerIdEntry) {
  auto server_id = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.has_value());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  QuicConnectionId no_server_id_entry(
      {0x00, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
  EXPECT_TRUE(decoder.GetServerId(no_server_id_entry).has_value());
}

TEST_F(LoadBalancerDecoderTest, InvalidConfigId) {
  auto server_id = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.has_value());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(1, 3, 4)));
  QuicConnectionId wrong_config_id(
      {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07});
  EXPECT_FALSE(decoder
                   .GetServerId(QuicConnectionId(
                       {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
                   .has_value());
}

TEST_F(LoadBalancerDecoderTest, UnroutableCodepoint) {
  auto server_id = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.has_value());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(1, 3, 4)));
  EXPECT_FALSE(decoder
                   .GetServerId(QuicConnectionId(
                       {0xe0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
                   .has_value());
}

TEST_F(LoadBalancerDecoderTest, UnroutableCodepointAnyLength) {
  auto server_id = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.has_value());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(1, 3, 4)));
  EXPECT_FALSE(decoder.GetServerId(QuicConnectionId({0xff})).has_value());
}

TEST_F(LoadBalancerDecoderTest, ConnectionIdTooShort) {
  auto server_id = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id.has_value());
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  EXPECT_FALSE(decoder
                   .GetServerId(QuicConnectionId(
                       {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}))
                   .has_value());
}

TEST_F(LoadBalancerDecoderTest, ConnectionIdTooLongIsOK) {
  auto server_id = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  auto server_id_result = decoder.GetServerId(
      QuicConnectionId({0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}));
  EXPECT_TRUE(server_id_result.has_value());
  EXPECT_EQ(server_id_result, server_id);
}

TEST_F(LoadBalancerDecoderTest, DeleteConfigBadId) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));
  decoder.DeleteConfig(0);
  EXPECT_QUIC_BUG(decoder.DeleteConfig(7),
                  "Decoder deleting config with invalid config_id 7");
  EXPECT_TRUE(decoder
                  .GetServerId(QuicConnectionId(
                      {0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
                  .has_value());
}

TEST_F(LoadBalancerDecoderTest, DeleteConfigGoodId) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));
  decoder.DeleteConfig(2);
  EXPECT_FALSE(decoder
                   .GetServerId(QuicConnectionId(
                       {0x40, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
                   .has_value());
}

// Create two server IDs and make sure the decoder decodes the correct one.
TEST_F(LoadBalancerDecoderTest, TwoServerIds) {
  auto server_id1 = LoadBalancerServerId::Create({0x01, 0x02, 0x03});
  EXPECT_TRUE(server_id1.has_value());
  auto server_id2 = LoadBalancerServerId::Create({0x04, 0x05, 0x06});
  LoadBalancerDecoder decoder;
  EXPECT_TRUE(
      decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(0, 3, 4)));
  EXPECT_EQ(decoder.GetServerId(QuicConnectionId(
                {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07})),
            server_id1);
  EXPECT_EQ(decoder.GetServerId(QuicConnectionId(
                {0x00, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a})),
            server_id2);
}

TEST_F(LoadBalancerDecoderTest, GetConfigId) {
  EXPECT_FALSE(
      LoadBalancerDecoder::GetConfigId(QuicConnectionId()).has_value());
  for (uint8_t i = 0; i < kNumLoadBalancerConfigs; i++) {
    const QuicConnectionId connection_id(
        {static_cast<unsigned char>(i << kConnectionIdLengthBits)});
    auto config_id = LoadBalancerDecoder::GetConfigId(connection_id);
    EXPECT_EQ(config_id,
              LoadBalancerDecoder::GetConfigId(connection_id.data()[0]));
    EXPECT_TRUE(config_id.has_value());
    EXPECT_EQ(*config_id, i);
  }
  EXPECT_FALSE(
      LoadBalancerDecoder::GetConfigId(QuicConnectionId({0xe0})).has_value());
}

TEST_F(LoadBalancerDecoderTest, GetConfig) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));

  EXPECT_EQ(decoder.GetConfig(0), nullptr);
  EXPECT_EQ(decoder.GetConfig(1), nullptr);
  EXPECT_EQ(decoder.GetConfig(3), nullptr);
  EXPECT_EQ(decoder.GetConfig(4), nullptr);

  const LoadBalancerConfig* config = decoder.GetConfig(2);
  ASSERT_NE(config, nullptr);
  EXPECT_EQ(config->server_id_len(), 3);
  EXPECT_EQ(config->nonce_len(), 4);
  EXPECT_FALSE(config->IsEncrypted());
}

}  // namespace

}  // namespace test

}  // namespace quic
