// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/str_cat.h"
#include "openssl/base.h"
#include "openssl/rsa.h"
#include "quiche/quic/masque/private_tokens.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_status_utils.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, private_key_file, "",
                                "Path to the PEM-encoded RSA private key.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, public_key_file, "",
                                "Path to the PEM-encoded RSA public key.");

namespace quic {
namespace {

absl::Status RunPrivateTokens(int argc, char* argv[]) {
  const char* usage =
      "Usage: private_tokens --private_key_file=<private-key-file> "
      "--public_key_file=<public-key-file>";
  std::vector<std::string> params =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);

  QUICHE_ASSIGN_OR_RETURN(bssl::UniquePtr<RSA> private_key,
                          ParseRsaPrivateKey(quiche::GetQuicheCommandLineFlag(
                              FLAGS_private_key_file)));
  QUICHE_ASSIGN_OR_RETURN(bssl::UniquePtr<RSA> public_key,
                          ParseRsaPublicKey(quiche::GetQuicheCommandLineFlag(
                              FLAGS_public_key_file)));
  QUICHE_ASSIGN_OR_RETURN(std::string encoded_public_key,
                          EncodePrivacyPassPublicKey(public_key.get()));

  std::string issuer_config = absl::StrCat(
      "{\n  \"issuer-request-uri\": \"https://issuer.example.net/request\",\n",
      "  \"token-keys\": [\n    {\n      \"token-type\": 2,\n",
      "      \"token-key\": \"", encoded_public_key, "\",\n    }\n  ]\n}");

  QUICHE_LOG(INFO) << "The issuer config could look like:\n" << issuer_config;

  QUICHE_ASSIGN_OR_RETURN(
      std::string token,
      CreateTokenLocally(private_key.get(), public_key.get()));

  std::string auth_header =
      absl::StrCat("Authorization: PrivateToken token=\"", token, "\"");

  QUICHE_LOG(INFO) << "The auth header would look like:\n" << auth_header;

  QUICHE_RETURN_IF_ERROR(ValidateToken(encoded_public_key, token));
  QUICHE_LOG(INFO) << "Token validation succeeded";
  return absl::OkStatus();
}

}  // namespace
}  // namespace quic

int main(int argc, char* argv[]) {
  absl::Status status = quic::RunPrivateTokens(argc, argv);
  if (!status.ok()) {
    QUICHE_LOG(ERROR) << status.message();
    return 1;
  }
  return 0;
}
