// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_OHTTP_CLIENT_H_
#define QUICHE_QUIC_MASQUE_MASQUE_OHTTP_CLIENT_H_

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "openssl/base.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/masque/masque_connection_pool.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/binary_http/binary_http_message.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/oblivious_http/buffers/oblivious_http_request.h"
#include "quiche/oblivious_http/oblivious_http_client.h"

namespace quic {

// A client that sends OHTTP requests through a relay/gateway to target URLs.
class QUICHE_EXPORT MasqueOhttpClient
    : public quic::MasqueConnectionPool::Visitor {
 public:
  using RequestId = quic::MasqueConnectionPool::RequestId;
  using Message = quic::MasqueConnectionPool::Message;

  explicit MasqueOhttpClient(quic::QuicEventLoop* event_loop, SSL_CTX* ssl_ctx,
                             std::vector<std::string> urls,
                             bool disable_certificate_verification,
                             int address_family_for_lookup,
                             const std::string& post_data)
      : urls_(urls),
        post_data_(post_data),
        connection_pool_(event_loop, ssl_ctx, disable_certificate_verification,
                         address_family_for_lookup, this) {}

  explicit MasqueOhttpClient(
      quic::QuicEventLoop* event_loop, SSL_CTX* ssl_ctx,
      std::vector<std::string> urls, bool disable_certificate_verification,
      int address_family_for_lookup, const std::string& post_data,
      std::shared_ptr<MasqueConnectionPool::DnsResolver> dns_resolver)
      : urls_(urls),
        post_data_(post_data),
        connection_pool_(event_loop, ssl_ctx, disable_certificate_verification,
                         address_family_for_lookup, this, dns_resolver) {}

  // Starts fetching for the key and sends the OHTTP request.
  absl::Status Start();

  // Returns true if the client has completed all requests.
  bool IsDone();

 protected:
  // From quic::MasqueConnectionPool::Visitor.
  void OnResponse(quic::MasqueConnectionPool* /*pool*/, RequestId request_id,
                  const absl::StatusOr<Message>& response) override;

  // Fetch key from the key URL.
  absl::Status StartKeyFetch(const std::string& url_string);

  // Handles the key response and starts the OHTTP request.
  absl::Status HandleKeyResponse(const absl::StatusOr<Message>& response);

  // Sends the OHTTP request for the given URL.
  absl::Status SendOhttpRequestForUrl(const std::string& url_string);

  // Signals the client to abort.
  void Abort() {
    QUICHE_LOG(INFO) << "Aborting";
    aborted_ = true;
  }
  absl::StatusOr<quiche::BinaryHttpResponse> TryExtractBinaryResponse(
      RequestId request_id, quiche::ObliviousHttpRequest::Context& context,
      const absl::StatusOr<Message>& response);
  virtual absl::Status HandleOhttpResponse(
      RequestId request_id, const absl::StatusOr<Message>& response);
  virtual absl::Status HandleBinaryResponse(
      const absl::StatusOr<quiche::BinaryHttpResponse>& binary_response) {
    return binary_response.status();
  }

 private:
  std::vector<std::string> urls_;
  std::string post_data_;
  quic::MasqueConnectionPool connection_pool_;
  std::optional<RequestId> key_fetch_request_id_;
  bool aborted_ = false;
  std::optional<quiche::ObliviousHttpClient> ohttp_client_;
  quic::QuicUrl relay_url_;
  absl::flat_hash_map<RequestId, quiche::ObliviousHttpRequest::Context>
      pending_ohttp_requests_;
};
}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_OHTTP_CLIENT_H_
