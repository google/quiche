// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_version_manager.h"

#include "absl/base/macros.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"

using ::testing::ElementsAre;

namespace quic {
namespace test {
namespace {

class QuicVersionManagerTest : public QuicTest {};

TEST_F(QuicVersionManagerTest, QuicVersionManager) {
  static_assert(SupportedVersions().size() == 6u,
                "Supported versions out of sync");
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicEnableVersion(version);
  }
  QuicDisableVersion(ParsedQuicVersion::V2Draft08());
  QuicDisableVersion(ParsedQuicVersion::RFCv1());
  QuicDisableVersion(ParsedQuicVersion::Draft29());
  QuicVersionManager manager(AllSupportedVersions());

  ParsedQuicVersionVector expected_parsed_versions;
  expected_parsed_versions.push_back(ParsedQuicVersion::Q050());
  expected_parsed_versions.push_back(ParsedQuicVersion::Q046());
  expected_parsed_versions.push_back(ParsedQuicVersion::Q043());

  EXPECT_EQ(expected_parsed_versions, manager.GetSupportedVersions());

  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  EXPECT_TRUE(manager.GetSupportedVersionsWithOnlyHttp3().empty());
  EXPECT_THAT(manager.GetSupportedAlpns(),
              ElementsAre("h3-Q050", "h3-Q046", "h3-Q043"));

  QuicEnableVersion(ParsedQuicVersion::Draft29());
  expected_parsed_versions.insert(expected_parsed_versions.begin(),
                                  ParsedQuicVersion::Draft29());
  EXPECT_EQ(expected_parsed_versions, manager.GetSupportedVersions());
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  EXPECT_EQ(1u, manager.GetSupportedVersionsWithOnlyHttp3().size());
  EXPECT_EQ(CurrentSupportedHttp3Versions(),
            manager.GetSupportedVersionsWithOnlyHttp3());
  EXPECT_THAT(manager.GetSupportedAlpns(),
              ElementsAre("h3-29", "h3-Q050", "h3-Q046", "h3-Q043"));

  QuicEnableVersion(ParsedQuicVersion::RFCv1());
  expected_parsed_versions.insert(expected_parsed_versions.begin(),
                                  ParsedQuicVersion::RFCv1());
  EXPECT_EQ(expected_parsed_versions, manager.GetSupportedVersions());
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  EXPECT_EQ(2u, manager.GetSupportedVersionsWithOnlyHttp3().size());
  EXPECT_EQ(CurrentSupportedHttp3Versions(),
            manager.GetSupportedVersionsWithOnlyHttp3());
  EXPECT_THAT(manager.GetSupportedAlpns(),
              ElementsAre("h3", "h3-29", "h3-Q050", "h3-Q046", "h3-Q043"));

  QuicEnableVersion(ParsedQuicVersion::V2Draft08());
  expected_parsed_versions.insert(expected_parsed_versions.begin(),
                                  ParsedQuicVersion::V2Draft08());
  EXPECT_EQ(expected_parsed_versions, manager.GetSupportedVersions());
  EXPECT_EQ(FilterSupportedVersions(AllSupportedVersions()),
            manager.GetSupportedVersions());
  EXPECT_EQ(3u, manager.GetSupportedVersionsWithOnlyHttp3().size());
  EXPECT_EQ(CurrentSupportedHttp3Versions(),
            manager.GetSupportedVersionsWithOnlyHttp3());
  EXPECT_THAT(manager.GetSupportedAlpns(),
              ElementsAre("h3", "h3-29", "h3-Q050", "h3-Q046", "h3-Q043"));
}

}  // namespace
}  // namespace test
}  // namespace quic
