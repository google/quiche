// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_types.h"

#include "absl/strings/str_cat.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace {

TEST(PacketHeaderFormatTest, Stringify) {
  EXPECT_EQ(absl::StrCat(IETF_QUIC_LONG_HEADER_PACKET),
            "IETF_QUIC_LONG_HEADER_PACKET");
  EXPECT_EQ(absl::StrCat(IETF_QUIC_SHORT_HEADER_PACKET),
            "IETF_QUIC_SHORT_HEADER_PACKET");
  EXPECT_EQ(absl::StrCat(GOOGLE_QUIC_Q043_PACKET), "GOOGLE_QUIC_Q043_PACKET");
  EXPECT_EQ(absl::StrCat(static_cast<PacketHeaderFormat>(0xff)),
            "Unknown (255)");
}

TEST(QuicSSLConfigTest, Equality) {
  QuicSSLConfig config1;
  QuicSSLConfig config2;
  EXPECT_EQ(config1, config2);

  config1.reject_unusable_ech_config = true;
  EXPECT_NE(config1, config2);
  config2.reject_unusable_ech_config = true;
  EXPECT_EQ(config1, config2);
}

}  // namespace
}  // namespace quic
