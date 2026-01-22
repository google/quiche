// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdbool.h>

#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
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

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, use_mtls_for_key_fetch, false,
    "If true, use mTLS when fetching the OHTTP/HPKE keys.");

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
  const bool use_mtls_for_key_fetch =
      quiche::GetQuicheCommandLineFlag(FLAGS_use_mtls_for_key_fetch);
  const std::string client_cert_file =
      quiche::GetQuicheCommandLineFlag(FLAGS_client_cert_file);
  const std::string client_cert_key_file =
      quiche::GetQuicheCommandLineFlag(FLAGS_client_cert_key_file);

  absl::StatusOr<bssl::UniquePtr<SSL_CTX>> key_fetch_ssl_ctx;
  if (use_mtls_for_key_fetch) {
    key_fetch_ssl_ctx = MasqueConnectionPool::CreateSslCtx(
        client_cert_file, client_cert_key_file);
  } else {
    key_fetch_ssl_ctx = MasqueConnectionPool::CreateSslCtx("", "");
  }
  if (!key_fetch_ssl_ctx.ok()) {
    QUICHE_LOG(ERROR) << "Failed to create key fetch SSL context: "
                      << key_fetch_ssl_ctx.status();
    return 1;
  }
  absl::StatusOr<bssl::UniquePtr<SSL_CTX>> ohttp_ssl_ctx =
      MasqueConnectionPool::CreateSslCtx(client_cert_file,
                                         client_cert_key_file);
  if (!ohttp_ssl_ctx.ok()) {
    QUICHE_LOG(ERROR) << "Failed to create OHTTP SSL context: "
                      << ohttp_ssl_ctx.status();
    return 1;
  }
  MasqueConnectionPool::DnsConfig dns_config;
  absl::Status address_family_status = dns_config.SetAddressFamily(
      quiche::GetQuicheCommandLineFlag(FLAGS_address_family));
  if (!address_family_status.ok()) {
    QUICHE_LOG(ERROR) << address_family_status;
    return 1;
  }
  std::unique_ptr<QuicEventLoop> event_loop =
      GetDefaultEventLoop()->Create(QuicDefaultClock::Get());
  std::string post_data = quiche::GetQuicheCommandLineFlag(FLAGS_post_data);

  MasqueOhttpClient masque_ohttp_client(
      event_loop.get(), key_fetch_ssl_ctx->get(), ohttp_ssl_ctx->get(), urls,
      disable_certificate_verification, dns_config, post_data);
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
