// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdbool.h>

#include <memory>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/masque/masque_connection_pool.h"
#include "quiche/quic/masque/masque_ohttp_client.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, disable_certificate_verification, false,
    "If true, don't verify the server certificate.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int, address_family, 0,
                                "IP address family to use. Must be 0, 4 or 6. "
                                "Defaults to 0 which means any.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, client_cert_file, "",
                                "Path to the client certificate chain.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, client_cert_key_file, "",
    "Path to the pkcs8 client certificate private key.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, post_data, "",
    "When set, the client will send a POST request with this data.");

namespace quic {
namespace {
int RunMasqueOhttpClient(int argc, char* argv[]) {
  const char* usage =
      "Usage: masque_ohttp_client <key-url> <relay-url> <url>...";
  std::vector<std::string> urls =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);

  quiche::QuicheSystemEventLoop system_event_loop("masque_ohttp_client");
  const bool disable_certificate_verification =
      quiche::GetQuicheCommandLineFlag(FLAGS_disable_certificate_verification);

  absl::StatusOr<bssl::UniquePtr<SSL_CTX>> ssl_ctx =
      MasqueConnectionPool::CreateSslCtx(
          quiche::GetQuicheCommandLineFlag(FLAGS_client_cert_file),
          quiche::GetQuicheCommandLineFlag(FLAGS_client_cert_key_file));
  if (!ssl_ctx.ok()) {
    QUICHE_LOG(ERROR) << "Failed to create SSL context: " << ssl_ctx.status();
    return 1;
  }
  const int address_family =
      quiche::GetQuicheCommandLineFlag(FLAGS_address_family);
  int address_family_for_lookup;
  if (address_family == 0) {
    address_family_for_lookup = AF_UNSPEC;
  } else if (address_family == 4) {
    address_family_for_lookup = AF_INET;
  } else if (address_family == 6) {
    address_family_for_lookup = AF_INET6;
  } else {
    QUICHE_LOG(ERROR) << "Invalid address_family " << address_family;
    return 1;
  }
  std::unique_ptr<QuicEventLoop> event_loop =
      GetDefaultEventLoop()->Create(QuicDefaultClock::Get());
  std::string post_data = quiche::GetQuicheCommandLineFlag(FLAGS_post_data);

  MasqueOhttpClient masque_ohttp_client(event_loop.get(), ssl_ctx->get(), urls,
                                        disable_certificate_verification,
                                        address_family_for_lookup, post_data);
  if (!masque_ohttp_client.Start().ok()) {
    return 1;
  }
  while (!masque_ohttp_client.IsDone()) {
    event_loop->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(50));
  }
  return 0;
}

}  // namespace
}  // namespace quic

int main(int argc, char* argv[]) {
  return quic::RunMasqueOhttpClient(argc, argv);
}
