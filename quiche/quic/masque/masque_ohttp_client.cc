// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/masque/masque_ohttp_client.h"

#include <optional>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "absl/cleanup/cleanup.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/match.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "openssl/base.h"
#include "quiche/quic/masque/masque_connection_pool.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/binary_http/binary_http_message.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_status_utils.h"
#include "quiche/common/quiche_text_utils.h"
#include "quiche/oblivious_http/buffers/oblivious_http_request.h"
#include "quiche/oblivious_http/buffers/oblivious_http_response.h"
#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"
#include "quiche/oblivious_http/oblivious_http_client.h"

namespace quic {

using ::quic::MasqueConnectionPool;
using ::quic::QuicUrl;
using ::quiche::BinaryHttpRequest;
using ::quiche::BinaryHttpResponse;
using ::quiche::ObliviousHttpClient;
using ::quiche::ObliviousHttpHeaderKeyConfig;
using ::quiche::ObliviousHttpKeyConfigs;
using ::quiche::ObliviousHttpRequest;
using ::quiche::ObliviousHttpResponse;
using RequestId = ::quic::MasqueConnectionPool::RequestId;
using Message = ::quic::MasqueConnectionPool::Message;

absl::Status MasqueOhttpClient::Start() {
  if (urls_.empty()) {
    QUICHE_LOG(ERROR) << "No URLs to request";
    Abort(absl::InvalidArgumentError("No URLs to request"));
    return status();
  }
  absl::Status status = StartKeyFetch(urls_[0]);
  if (!status.ok()) {
    Abort(status);
    return status;
  }
  return absl::OkStatus();
}
bool MasqueOhttpClient::IsDone() {
  if (aborted_) {
    return true;
  }
  if (!ohttp_client_.has_value()) {
    // Key fetch request is still pending.
    return false;
  }
  return pending_ohttp_requests_.empty();
}

void MasqueOhttpClient::Abort(absl::Status status) {
  QUICHE_CHECK(!status.ok());
  QUICHE_LOG(ERROR) << "Aborting: " << status;
  aborted_ = true;
  if (status_.ok()) {  // Only keep the first abort status.
    status_ = status;
  }
}

absl::StatusOr<QuicUrl> ParseUrl(const std::string& url_string) {
  QuicUrl url(url_string, "https");
  if (url.host().empty() && !absl::StrContains(url_string, "://")) {
    url = QuicUrl(absl::StrCat("https://", url_string));
  }
  if (url.host().empty()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse key URL ", url_string));
  }
  return url;
}

absl::Status MasqueOhttpClient::StartKeyFetch(const std::string& url_string) {
  QuicUrl url(url_string, "https");
  if (url.host().empty() && !absl::StrContains(url_string, "://")) {
    url = QuicUrl(absl::StrCat("https://", url_string));
  }
  if (url.host().empty()) {
    QUICHE_LOG(ERROR) << "Failed to parse key URL \"" << url_string << "\"";
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse key URL ", url_string));
  }
  Message request;
  request.headers[":method"] = "GET";
  request.headers[":scheme"] = url.scheme();
  request.headers[":authority"] = url.HostPort();
  request.headers[":path"] = url.PathParamsQuery();
  request.headers["accept"] = "application/ohttp-keys";

  QUICHE_ASSIGN_OR_RETURN(key_fetch_request_id_,
                          connection_pool_.SendRequest(request, /*mtls=*/false),
                          [](const absl::Status& status) {
                            QUICHE_LOG(ERROR)
                                << "Failed to send request: " << status;
                            return status;
                          });
  return absl::OkStatus();
}

absl::Status MasqueOhttpClient::CheckStatusAndContentType(
    const Message& response, const std::string& content_type) {
  auto status_it = response.headers.find(":status");
  if (status_it == response.headers.end()) {
    return absl::InvalidArgumentError(
        absl::StrCat("No :status header in ", content_type, " response."));
  }
  int status_code;
  if (!absl::SimpleAtoi(status_it->second, &status_code)) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse ", content_type, " status code."));
  }
  if (status_code < 200 || status_code >= 300) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unexpected status in ", content_type,
                     " response: ", status_it->second));
  }
  auto content_type_it = response.headers.find("content-type");
  if (content_type_it == response.headers.end()) {
    return absl::InvalidArgumentError(
        absl::StrCat("No content-type header in ", content_type, " response."));
  }
  std::vector<absl::string_view> content_type_split =
      absl::StrSplit(content_type_it->second, absl::MaxSplits(';', 1));
  absl::string_view content_type_without_params = content_type_split[0];
  quiche::QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(
      &content_type_without_params);
  if (content_type_without_params != content_type) {
    return absl::InvalidArgumentError(
        absl::StrCat("Unexpected content-type in ", content_type,
                     " response: ", content_type_it->second));
  }
  return absl::OkStatus();
}

absl::Status MasqueOhttpClient::HandleKeyResponse(
    const absl::StatusOr<Message>& response) {
  key_fetch_request_id_ = std::nullopt;

  if (!response.ok()) {
    QUICHE_LOG(ERROR) << "Failed to fetch key: " << response.status();
    return response.status();
  }
  QUICHE_LOG(INFO) << "Received key response: "
                   << response->headers.DebugString();
  QUICHE_RETURN_IF_ERROR(
      CheckStatusAndContentType(*response, "application/ohttp-keys"));
  absl::StatusOr<ObliviousHttpKeyConfigs> key_configs =
      ObliviousHttpKeyConfigs::ParseConcatenatedKeys(response->body);
  if (!key_configs.ok()) {
    QUICHE_LOG(ERROR) << "Failed to parse OHTTP keys: " << key_configs.status();
    return key_configs.status();
  }
  QUICHE_LOG(INFO) << "Successfully got " << key_configs->NumKeys()
                   << " OHTTP keys: " << std::endl
                   << key_configs->DebugString();
  if (urls_.size() <= 2) {
    return absl::InvalidArgumentError("No OHTTP URLs to request, exiting.");
  }
  relay_url_ = QuicUrl(urls_[1], "https");
  if (relay_url_.host().empty() && !absl::StrContains(urls_[1], "://")) {
    relay_url_ = QuicUrl(absl::StrCat("https://", urls_[1]));
  }
  QUICHE_LOG(INFO) << "Using relay URL: " << relay_url_.ToString();
  ObliviousHttpHeaderKeyConfig key_config = key_configs->PreferredConfig();
  absl::StatusOr<absl::string_view> public_key =
      key_configs->GetPublicKeyForId(key_config.GetKeyId());
  if (!public_key.ok()) {
    QUICHE_LOG(ERROR) << "Failed to get public key for key ID "
                      << static_cast<int>(key_config.GetKeyId()) << ": "
                      << public_key.status();
    return public_key.status();
  }
  absl::StatusOr<ObliviousHttpClient> ohttp_client =
      ObliviousHttpClient::Create(*public_key, key_config);
  if (!ohttp_client.ok()) {
    QUICHE_LOG(ERROR) << "Failed to create OHTTP client: "
                      << ohttp_client.status();
    return ohttp_client.status();
  }
  ohttp_client_.emplace(std::move(*ohttp_client));
  for (size_t i = 2; i < urls_.size(); ++i) {
    QUICHE_RETURN_IF_ERROR(SendOhttpRequestForUrl(urls_[i]));
  }
  return absl::OkStatus();
}

absl::Status MasqueOhttpClient::SendOhttpRequestForUrl(
    const std::string& url_string) {
  QuicUrl url(url_string, "https");
  if (url.host().empty() && !absl::StrContains(url_string, "://")) {
    url = QuicUrl(absl::StrCat("https://", url_string));
  }
  if (url.host().empty()) {
    return absl::InvalidArgumentError(
        absl::StrCat("Failed to parse key URL ", url_string));
  }
  BinaryHttpRequest::ControlData control_data;
  control_data.method = post_data_.empty() ? "GET" : "POST";
  control_data.scheme = url.scheme();
  control_data.authority = url.HostPort();
  control_data.path = url.PathParamsQuery();
  BinaryHttpRequest binary_request(control_data);
  binary_request.set_body(post_data_);
  absl::StatusOr<std::string> encoded_request = binary_request.Serialize();
  if (!encoded_request.ok()) {
    return encoded_request.status();
  }
  if (!ohttp_client_.has_value()) {
    QUICHE_LOG(FATAL) << "Cannot send OHTTP request without OHTTP client";
    return absl::InternalError(
        "Cannot send OHTTP request without OHTTP client");
  }
  absl::StatusOr<ObliviousHttpRequest> ohttp_request =
      ohttp_client_->CreateObliviousHttpRequest(*encoded_request);
  if (!ohttp_request.ok()) {
    QUICHE_LOG(ERROR) << "Failed to create OHTTP request: "
                      << ohttp_request.status();
    return ohttp_request.status();
  }
  Message request;
  request.headers[":method"] = "POST";
  request.headers[":scheme"] = relay_url_.scheme();
  request.headers[":authority"] = relay_url_.HostPort();
  request.headers[":path"] = relay_url_.PathParamsQuery();
  request.headers["content-type"] = "message/ohttp-req";
  request.body = ohttp_request->EncapsulateAndSerialize();
  absl::StatusOr<RequestId> request_id =
      connection_pool_.SendRequest(request, /*mtls=*/true);
  if (!request_id.ok()) {
    QUICHE_LOG(ERROR) << "Failed to send request: " << request_id.status();
    return request_id.status();
  }
  QUICHE_LOG(INFO) << "Sent OHTTP request for " << url_string;
  auto context = std::move(*ohttp_request).ReleaseContext();
  pending_ohttp_requests_.insert({*request_id, std::move(context)});
  return absl::OkStatus();
}

absl::StatusOr<BinaryHttpResponse> MasqueOhttpClient::TryExtractBinaryResponse(
    const RequestId request_id, quiche::ObliviousHttpRequest::Context& context,
    const Message& response) {
  if (!ohttp_client_.has_value()) {
    QUICHE_LOG(FATAL) << "Received OHTTP response without OHTTP client";
    return absl::InternalError("Received OHTTP response without OHTTP client");
  }
  absl::StatusOr<ObliviousHttpResponse> ohttp_response =
      ohttp_client_->DecryptObliviousHttpResponse(response.body, context);
  if (ohttp_response.ok()) {
    QUICHE_LOG(INFO) << "Received OHTTP response for " << request_id;
    absl::StatusOr<BinaryHttpResponse> binary_response =
        BinaryHttpResponse::Create(ohttp_response->GetPlaintextData());
    if (binary_response.ok()) {
      QUICHE_LOG(INFO) << "Successfully decoded OHTTP response:";
      QUICHE_LOG(INFO) << "Status: " << binary_response->status_code();
      for (const quiche::BinaryHttpMessage::Field& field :
           binary_response->GetHeaderFields()) {
        QUICHE_LOG(INFO) << field.name << ": " << field.value;
      }
      QUICHE_LOG(INFO) << "Body:" << std::endl << binary_response->body();
      return binary_response;
    } else {
      QUICHE_LOG(ERROR) << "Failed to parse binary response: "
                        << binary_response.status();
      return binary_response;
    }
  } else {
    QUICHE_LOG(ERROR) << "Failed to decrypt OHTTP response: "
                      << ohttp_response.status();
    return ohttp_response.status();
  }
}

absl::Status MasqueOhttpClient::ProcessOhttpResponse(
    RequestId request_id, const absl::StatusOr<Message>& response) {
  auto it = pending_ohttp_requests_.find(request_id);
  if (it == pending_ohttp_requests_.end()) {
    QUICHE_LOG(ERROR) << "Received unexpected response for unknown request "
                      << request_id;
    return absl::InternalError(
        "Received unexpected response for unknown request");
  }
  auto cleanup =
      absl::MakeCleanup([this, it]() { pending_ohttp_requests_.erase(it); });
  QUICHE_RETURN_IF_ERROR(response.status());
  QUICHE_RETURN_IF_ERROR(
      CheckStatusAndContentType(*response, "message/ohttp-res"));
  QUICHE_RETURN_IF_ERROR(CheckGatewayResponse(*response));
  absl::StatusOr<BinaryHttpResponse> binary_response =
      TryExtractBinaryResponse(request_id, it->second, *response);
  QUICHE_RETURN_IF_ERROR(binary_response.status());
  QUICHE_RETURN_IF_ERROR(CheckEncapsulatedResponse(*binary_response));
  return absl::OkStatus();
}

void MasqueOhttpClient::OnPoolResponse(MasqueConnectionPool* /*pool*/,
                                       RequestId request_id,
                                       absl::StatusOr<Message>&& response) {
  if (key_fetch_request_id_.has_value() &&
      *key_fetch_request_id_ == request_id) {
    auto status = HandleKeyResponse(response);
    if (!status.ok()) {
      QUICHE_LOG(ERROR) << "Failed to handle key response: " << status;
      Abort(status);
    }
  } else {
    auto status = ProcessOhttpResponse(request_id, response);
    if (!status.ok()) {
      QUICHE_LOG(ERROR) << "Failed to handle OHTTP response: " << status;
      Abort(status);
    }
  }
}
}  // namespace quic
