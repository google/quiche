// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_OHTTP_CLIENT_H_
#define QUICHE_QUIC_MASQUE_MASQUE_OHTTP_CLIENT_H_

#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/masque/masque_connection_pool.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/binary_http/binary_http_message.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/oblivious_http/buffers/oblivious_http_request.h"
#include "quiche/oblivious_http/common/oblivious_http_chunk_handler.h"
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"
#include "quiche/oblivious_http/oblivious_http_client.h"

namespace quic {

// A client that sends OHTTP requests through a relay/gateway to target URLs.
class QUICHE_EXPORT MasqueOhttpClient
    : public quic::MasqueConnectionPool::Visitor {
 public:
  using RequestId = quic::MasqueConnectionPool::RequestId;
  using Message = quic::MasqueConnectionPool::Message;

  explicit MasqueOhttpClient(quic::QuicEventLoop* event_loop,
                             SSL_CTX* key_fetch_ssl_ctx, SSL_CTX* ohttp_ssl_ctx,
                             std::vector<std::string> urls,
                             bool disable_certificate_verification,
                             bool use_chunked_ohttp,
                             const MasqueConnectionPool::DnsConfig& dns_config,
                             const std::string& post_data)
      : urls_(urls),
        use_chunked_ohttp_(use_chunked_ohttp),
        post_data_(post_data),
        connection_pool_(event_loop, key_fetch_ssl_ctx,
                         disable_certificate_verification, dns_config, this) {
    connection_pool_.SetMtlsSslCtx(ohttp_ssl_ctx);
  }

  // Starts fetching for the key and sends the OHTTP request.
  absl::Status Start();

  // Returns true if the client has completed all requests.
  bool IsDone();

  // Returns the status of the client.
  absl::Status status() const { return status_; }

 protected:
  // From quic::MasqueConnectionPool::Visitor.
  void OnPoolResponse(quic::MasqueConnectionPool* /*pool*/,
                      RequestId request_id,
                      absl::StatusOr<Message>&& response) override;

  // Fetch key from the key URL.
  absl::Status StartKeyFetch(const std::string& url_string);

  // Handles the key response and starts the OHTTP request.
  absl::Status HandleKeyResponse(const absl::StatusOr<Message>& response);

  // Sends the OHTTP request for the given URL.
  absl::Status SendOhttpRequestForUrl(const std::string& url_string);

  // Signals the client to abort.
  void Abort(absl::Status status);

  // Can be overridden by subclasses to check responses.
  virtual absl::Status CheckGatewayResponse(const Message& response) {
    return absl::OkStatus();
  }
  virtual absl::Status CheckEncapsulatedResponse(const Message& response) {
    return absl::OkStatus();
  }

 private:
  class QUICHE_NO_EXPORT ChunkHandler
      : public quiche::ObliviousHttpChunkHandler,
        public quiche::BinaryHttpResponse::IndeterminateLengthDecoder::
            MessageSectionHandler {
   public:
    explicit ChunkHandler();
    // Neither copyable nor movable to ensure pointer stability as required for
    // quiche::ObliviousHttpChunkHandler.
    ChunkHandler(const ChunkHandler& other) = delete;
    ChunkHandler& operator=(const ChunkHandler& other) = delete;
    ChunkHandler(ChunkHandler&& other) = delete;
    ChunkHandler& operator=(ChunkHandler&& other) = delete;

    // Decrypts the full chunked response and returns the encapsulated response.
    absl::StatusOr<Message> DecryptFullResponse(
        absl::string_view encrypted_response);

    void SetChunkedClient(quiche::ChunkedObliviousHttpClient chunked_client) {
      chunked_client_.emplace(std::move(chunked_client));
    }

    // From quiche::ObliviousHttpChunkHandler.
    absl::Status OnDecryptedChunk(absl::string_view decrypted_chunk) override;
    absl::Status OnChunksDone() override;

    // From quiche::BinaryHttpResponse::
    // IndeterminateLengthDecoder::MessageSectionHandler.
    absl::Status OnInformationalResponseStatusCode(
        uint16_t status_code) override;
    absl::Status OnInformationalResponseHeader(
        absl::string_view name, absl::string_view value) override;
    absl::Status OnInformationalResponseDone() override;
    absl::Status OnInformationalResponsesSectionDone() override;
    absl::Status OnFinalResponseStatusCode(uint16_t status_code) override;
    absl::Status OnFinalResponseHeader(absl::string_view name,
                                       absl::string_view value) override;
    absl::Status OnFinalResponseHeadersDone() override;
    absl::Status OnBodyChunk(absl::string_view body_chunk) override;
    absl::Status OnBodyChunksDone() override;
    absl::Status OnTrailer(absl::string_view name,
                           absl::string_view value) override;
    absl::Status OnTrailersDone() override;

   private:
    std::optional<quiche::ChunkedObliviousHttpClient> chunked_client_;
    quiche::BinaryHttpResponse::IndeterminateLengthDecoder decoder_;
    Message response_;
  };

  struct PendingRequest {
    // `context` is only used for non-chunked OHTTP requests.
    std::optional<quiche::ObliviousHttpRequest::Context> context;
    // `chunk_handler` is only used for chunked OHTTP requests. We use
    // std::unique_ptr to ensure pointer stability since this object is used as
    // a callback target.
    std::unique_ptr<ChunkHandler> chunk_handler;
  };

  absl::StatusOr<Message> TryExtractEncapsulatedResponse(
      RequestId request_id, quiche::ObliviousHttpRequest::Context& context,
      const Message& response);
  absl::Status ProcessOhttpResponse(RequestId request_id,
                                    const absl::StatusOr<Message>& response);
  absl::Status CheckStatusAndContentType(const Message& response,
                                         const std::string& content_type);

  std::vector<std::string> urls_;
  bool use_chunked_ohttp_;
  std::string post_data_;
  quic::MasqueConnectionPool connection_pool_;
  std::optional<RequestId> key_fetch_request_id_;
  bool aborted_ = false;
  absl::Status status_ = absl::OkStatus();
  std::optional<quiche::ObliviousHttpClient> ohttp_client_;
  std::optional<std::string> chunked_public_key_;
  std::optional<quiche::ObliviousHttpHeaderKeyConfig> chunked_key_config_;
  quic::QuicUrl relay_url_;
  absl::flat_hash_map<RequestId, PendingRequest> pending_ohttp_requests_;
};
}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_OHTTP_CLIENT_H_
