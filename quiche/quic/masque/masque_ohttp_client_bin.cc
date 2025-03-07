// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <stdbool.h>

#include <memory>
#include <optional>
#include <ostream>
#include <string>
#include <vector>

#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/str_cat.h"
#include "openssl/base.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/masque/masque_connection_pool.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_system_event_loop.h"
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"

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

using quiche::ObliviousHttpKeyConfigs;

namespace quic {
namespace {

class MasqueOhttpClient : public MasqueConnectionPool::Visitor {
 public:
  using RequestId = MasqueConnectionPool::RequestId;
  using Message = MasqueConnectionPool::Message;
  explicit MasqueOhttpClient(QuicEventLoop *event_loop, SSL_CTX *ssl_ctx,
                             std::vector<std::string> urls,
                             bool disable_certificate_verification,
                             int address_family_for_lookup)
      : urls_(urls),
        connection_pool_(event_loop, ssl_ctx, disable_certificate_verification,
                         address_family_for_lookup, this) {}

  bool Start() {
    if (urls_.empty()) {
      QUICHE_LOG(ERROR) << "No URLs to request";
      Abort();
      return false;
    }
    if (!StartKeyFetch(urls_[0])) {
      Abort();
      return false;
    }
    return true;
  }
  bool IsDone() { return done_; }

  // From MasqueConnectionPool::Visitor.
  void OnResponse(MasqueConnectionPool * /*pool*/, RequestId request_id,
                  const absl::StatusOr<Message> &response) override {
    if (key_fetch_request_id_.has_value() &&
        *key_fetch_request_id_ == request_id) {
      key_fetch_request_id_ = std::nullopt;
      HandleKeyResponse(response);
    }
  }

 private:
  bool StartKeyFetch(const std::string &url_string) {
    QuicUrl url(url_string, "https");
    if (url.host().empty() && !absl::StrContains(url_string, "://")) {
      url = QuicUrl(absl::StrCat("https://", url_string));
    }
    if (url.host().empty()) {
      QUICHE_LOG(ERROR) << "Failed to parse key URL \"" << url_string << "\"";
      return false;
    }
    Message request;
    request.headers[":method"] = "GET";
    request.headers[":scheme"] = url.scheme();
    request.headers[":authority"] = url.HostPort();
    request.headers[":path"] = url.path();
    request.headers["host"] = url.HostPort();
    request.headers["accept"] = "application/ohttp-keys";
    request.headers["content-type"] = "application/ohttp-keys";
    absl::StatusOr<RequestId> request_id =
        connection_pool_.SendRequest(request);
    if (!request_id.ok()) {
      QUICHE_LOG(ERROR) << "Failed to send request: " << request_id.status();
      return false;
    }
    key_fetch_request_id_ = *request_id;
    return true;
  }

  void HandleKeyResponse(const absl::StatusOr<Message> &response) {
    if (!response.ok()) {
      QUICHE_LOG(ERROR) << "Failed to fetch key: " << response.status();
      return;
    }
    QUICHE_LOG(INFO) << "Received key response: "
                     << response->headers.DebugString();
    absl::StatusOr<ObliviousHttpKeyConfigs> key_configs =
        ObliviousHttpKeyConfigs::ParseConcatenatedKeys(response->body);
    if (!key_configs.ok()) {
      QUICHE_LOG(ERROR) << "Failed to parse OHTTP keys: "
                        << key_configs.status();
      Abort();
      return;
    }
    QUICHE_LOG(INFO) << "Successfully got " << key_configs->NumKeys()
                     << " OHTTP keys: " << std::endl
                     << key_configs->DebugString();
    // TODO(dschinazi): Use the keys to send requests.
    Abort();
  }

  void Abort() { done_ = true; }

  std::vector<std::string> urls_;
  MasqueConnectionPool connection_pool_;
  std::optional<RequestId> key_fetch_request_id_;
  bool done_ = false;
};

int RunMasqueOhttpClient(int argc, char *argv[]) {
  const char *usage = "Usage: masque_ohttp_client <url>";
  std::vector<std::string> urls =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);

  quiche::QuicheSystemEventLoop system_event_loop("masque_client");
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

  MasqueOhttpClient masque_ohttp_client(event_loop.get(), ssl_ctx->get(), urls,
                                        disable_certificate_verification,
                                        address_family_for_lookup);
  if (!masque_ohttp_client.Start()) {
    return 1;
  }
  while (!masque_ohttp_client.IsDone()) {
    event_loop->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(50));
  }
  return 0;
}

}  // namespace
}  // namespace quic

int main(int argc, char *argv[]) {
  return quic::RunMasqueOhttpClient(argc, argv);
}
