// Copyright (c) 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/crypto/crypto_utils.h"

#include <string>

#include "absl/base/macros.h"
#include "absl/strings/escaping.h"
#include "quic/core/quic_utils.h"
#include "quic/platform/api/quic_test.h"
#include "quic/test_tools/quic_test_utils.h"
#include "common/test_tools/quiche_test_utils.h"

namespace quic {
namespace test {
namespace {

class CryptoUtilsTest : public QuicTest {};

TEST_F(CryptoUtilsTest, HandshakeFailureReasonToString) {
  EXPECT_STREQ("HANDSHAKE_OK",
               CryptoUtils::HandshakeFailureReasonToString(HANDSHAKE_OK));
  EXPECT_STREQ("CLIENT_NONCE_UNKNOWN_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_UNKNOWN_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_ORBIT_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_ORBIT_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_TIMEOUT));
  EXPECT_STREQ("CLIENT_NONCE_STRIKE_REGISTER_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   CLIENT_NONCE_STRIKE_REGISTER_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_DECRYPTION_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_NOT_UNIQUE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_NOT_UNIQUE_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_INVALID_TIME_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_INVALID_TIME_FAILURE));
  EXPECT_STREQ("SERVER_NONCE_REQUIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_NONCE_REQUIRED_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_INCHOATE_HELLO_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_INCHOATE_HELLO_FAILURE));
  EXPECT_STREQ("SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SERVER_CONFIG_UNKNOWN_CONFIG_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_INVALID_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_INVALID_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DECRYPTION_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_PARSE_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_PARSE_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_DIFFERENT_IP_ADDRESS_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_CLOCK_SKEW_FAILURE));
  EXPECT_STREQ("SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE",
               CryptoUtils::HandshakeFailureReasonToString(
                   SOURCE_ADDRESS_TOKEN_EXPIRED_FAILURE));
  EXPECT_STREQ("INVALID_EXPECTED_LEAF_CERTIFICATE",
               CryptoUtils::HandshakeFailureReasonToString(
                   INVALID_EXPECTED_LEAF_CERTIFICATE));
  EXPECT_STREQ("MAX_FAILURE_REASON",
               CryptoUtils::HandshakeFailureReasonToString(MAX_FAILURE_REASON));
  EXPECT_STREQ(
      "INVALID_HANDSHAKE_FAILURE_REASON",
      CryptoUtils::HandshakeFailureReasonToString(
          static_cast<HandshakeFailureReason>(MAX_FAILURE_REASON + 1)));
}

TEST_F(CryptoUtilsTest, AuthTagLengths) {
  for (const auto& version : AllSupportedVersions()) {
    for (QuicTag algo : {kAESG, kCC20}) {
      SCOPED_TRACE(version);
      std::unique_ptr<QuicEncrypter> encrypter(
          QuicEncrypter::Create(version, algo));
      size_t auth_tag_size = 12;
      if (version.UsesInitialObfuscators()) {
        auth_tag_size = 16;
      }
      EXPECT_EQ(encrypter->GetCiphertextSize(0), auth_tag_size);
    }
  }
}

TEST_F(CryptoUtilsTest, ValidateChosenVersion) {
  for (const ParsedQuicVersion& v1 : AllSupportedVersions()) {
    for (const ParsedQuicVersion& v2 : AllSupportedVersions()) {
      std::string error_details;
      bool success = CryptoUtils::ValidateChosenVersion(
          CreateQuicVersionLabel(v1), v2, &error_details);
      EXPECT_EQ(success, v1 == v2);
      EXPECT_EQ(success, error_details.empty());
    }
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsNoVersionNegotiation) {
  QuicVersionLabelVector version_information_other_versions;
  ParsedQuicVersionVector client_original_supported_versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    std::string error_details;
    EXPECT_TRUE(CryptoUtils::ValidateServerVersions(
        version_information_other_versions, version,
        client_original_supported_versions, &error_details));
    EXPECT_TRUE(error_details.empty());
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsWithVersionNegotiation) {
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    QuicVersionLabelVector version_information_other_versions{
        CreateQuicVersionLabel(version)};
    ParsedQuicVersionVector client_original_supported_versions{
        ParsedQuicVersion::ReservedForNegotiation(), version};
    std::string error_details;
    EXPECT_TRUE(CryptoUtils::ValidateServerVersions(
        version_information_other_versions, version,
        client_original_supported_versions, &error_details));
    EXPECT_TRUE(error_details.empty());
  }
}

TEST_F(CryptoUtilsTest, ValidateServerVersionsWithDowngrade) {
  if (AllSupportedVersions().size() <= 1) {
    // We are not vulnerable to downgrade if we only support one version.
    return;
  }
  ParsedQuicVersion client_version = AllSupportedVersions().front();
  ParsedQuicVersion server_version = AllSupportedVersions().back();
  ASSERT_NE(client_version, server_version);
  QuicVersionLabelVector version_information_other_versions{
      CreateQuicVersionLabel(client_version)};
  ParsedQuicVersionVector client_original_supported_versions{
      ParsedQuicVersion::ReservedForNegotiation(), server_version};
  std::string error_details;
  EXPECT_FALSE(CryptoUtils::ValidateServerVersions(
      version_information_other_versions, server_version,
      client_original_supported_versions, &error_details));
  EXPECT_FALSE(error_details.empty());
}

}  // namespace
}  // namespace test
}  // namespace quic
