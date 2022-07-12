// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_decoder.h"

#include "quiche/quic/load_balancer/load_balancer_server_id.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

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
          QuicConnectionId({0x4d, 0xed, 0x79, 0x3a, 0x51, 0xd4, 0x9b, 0x8f,
                            0x5f, 0xee, 0x15, 0xda, 0x27, 0xc4}),
          MakeServerId(kServerId, 8),
      }};
  for (const auto& test : test_vectors) {
    LoadBalancerDecoder decoder;
    EXPECT_TRUE(decoder.AddConfig(test.config));
    EXPECT_EQ(decoder.GetServerId(test.connection_id), test.server_id);
  }
}

// Compare test vectors from Appendix B of draft-ietf-quic-load-balancers-14.
TEST_F(LoadBalancerDecoderTest, DecoderTestVectors) {
  // Try (1) the "standard" CID length of 8
  // (2) server_id_len > nonce_len, so there is a fourth decryption pass
  // (3) the single-pass encryption case
  // (4) An even total length.
  const struct LoadBalancerDecoderTestCase test_vectors[4] = {
      {
          *LoadBalancerConfig::Create(0, 3, 4, kKey),
          QuicConnectionId({0x07, 0x27, 0xed, 0xaa, 0x37, 0xe7, 0xfa, 0xc8}),
          MakeServerId(kServerId, 3),
      },
      {
          *LoadBalancerConfig::Create(1, 10, 5, kKey),
          QuicConnectionId({0x4f, 0x22, 0x61, 0x4a, 0x97, 0xce, 0xee, 0x84,
                            0x34, 0x1e, 0xd7, 0xfb, 0xfe, 0xb1, 0xe6, 0xe2}),
          MakeServerId(kServerId, 10),
      },
      {
          *LoadBalancerConfig::Create(2, 8, 8, kKey),
          QuicConnectionId({0x90, 0x4d, 0xd2, 0xd0, 0x5a, 0x7b, 0x0d, 0xe9,
                            0xb2, 0xb9, 0x90, 0x7a, 0xfb, 0x5e, 0xcf, 0x8c,
                            0xc3}),
          MakeServerId(kServerId, 8),
      },
      {
          *LoadBalancerConfig::Create(0, 9, 9, kKey),
          QuicConnectionId({0x12, 0x5e, 0x3b, 0x00, 0xaa, 0x5f, 0xcf, 0xd1,
                            0xa9, 0xa5, 0x81, 0x02, 0xa8, 0x9a, 0x19, 0xa1,
                            0xe4, 0xa1, 0x0e}),
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
                       {0xc0, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
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
  EXPECT_QUIC_BUG(decoder.DeleteConfig(3),
                  "Decoder deleting config with invalid config_id 3");
  EXPECT_TRUE(decoder
                  .GetServerId(QuicConnectionId(
                      {0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
                  .has_value());
}

TEST_F(LoadBalancerDecoderTest, DeleteConfigGoodId) {
  LoadBalancerDecoder decoder;
  decoder.AddConfig(*LoadBalancerConfig::CreateUnencrypted(2, 3, 4));
  decoder.DeleteConfig(2);
  EXPECT_FALSE(decoder
                   .GetServerId(QuicConnectionId(
                       {0x80, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07}))
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
  for (uint8_t i = 0; i < 3; i++) {
    auto config_id = LoadBalancerDecoder::GetConfigId(
        QuicConnectionId({static_cast<unsigned char>(i << 6)}));
    EXPECT_TRUE(config_id.has_value());
    EXPECT_EQ(*config_id, i);
  }
  EXPECT_FALSE(
      LoadBalancerDecoder::GetConfigId(QuicConnectionId({0xc0})).has_value());
}

}  // namespace

}  // namespace test

}  // namespace quic
