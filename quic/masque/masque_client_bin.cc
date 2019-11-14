// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <memory>
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/masque/masque_encapsulated_epoll_client.h"
#include "net/third_party/quiche/src/quic/masque/masque_epoll_client.h"
#include "net/third_party/quiche/src/quic/masque/masque_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quiche/src/quic/tools/fake_proof_verifier.h"
#include "net/third_party/quiche/src/quic/tools/quic_url.h"

DEFINE_QUIC_COMMAND_LINE_FLAG(bool,
                              disable_certificate_verification,
                              false,
                              "If true, don't verify the server certificate.");

namespace quic {

namespace {

bool SendRequest(MasqueEpollClient* masque_client,
                 QuicEpollServer* epoll_server,
                 std::string url_string,
                 bool disable_certificate_verification) {
  QuicUrl url(url_string, "https");
  std::unique_ptr<ProofVerifier> proof_verifier;
  if (disable_certificate_verification) {
    proof_verifier = std::make_unique<FakeProofVerifier>();
  } else {
    proof_verifier = CreateDefaultProofVerifier(url.host());
  }

  // Build the client, and try to connect.
  QuicSocketAddress addr =
      tools::LookupAddress(url.host(), QuicStrCat(url.port()));
  if (!addr.IsInitialized()) {
    QUIC_LOG(ERROR) << "Unable to resolve address: " << url.host();
    return false;
  }
  QuicServerId server_id(url.host(), url.port(),
                         /*privacy_mode_enabled=*/false);
  auto client = std::make_unique<MasqueEncapsulatedEpollClient>(
      addr, server_id, epoll_server, std::move(proof_verifier), masque_client);

  if (client == nullptr) {
    QUIC_LOG(ERROR) << "Failed to create MasqueEncapsulatedEpollClient for "
                    << url_string;
    return false;
  }

  client->set_initial_max_packet_length(kMasqueMaxEncapsulatedPacketSize);
  client->set_drop_response_body(false);
  if (!client->Initialize()) {
    QUIC_LOG(ERROR) << "Failed to initialize MasqueEncapsulatedEpollClient for "
                    << url_string;
    return false;
  }

  if (!client->Connect()) {
    QuicErrorCode error = client->session()->error();
    QUIC_LOG(ERROR) << "Failed to connect with client "
                    << client->session()->connection()->client_connection_id()
                    << " server " << client->session()->connection_id()
                    << " to " << url.HostPort()
                    << ". Error: " << QuicErrorCodeToString(error);
    return false;
  }

  std::cerr << "Connected client "
            << client->session()->connection()->client_connection_id()
            << " server " << client->session()->connection_id() << " for "
            << url_string << std::endl;

  // Construct the string body from flags, if provided.
  std::string body = "foo";

  // Construct a GET or POST request for supplied URL.
  spdy::SpdyHeaderBlock header_block;
  header_block[":method"] = "GET";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.HostPort();
  header_block[":path"] = url.PathParamsQuery();

  // Make sure to store the response, for later output.
  client->set_store_response(true);

  // Send the MASQUE init request.
  client->SendRequestAndWaitForResponse(header_block, body,
                                        /*fin=*/true);

  if (!client->connected()) {
    QUIC_LOG(ERROR) << "Request for " << url_string
                    << " caused connection failure. Error: "
                    << QuicErrorCodeToString(client->session()->error());
    return false;
  }

  const int response_code = client->latest_response_code();
  if (response_code < 200 || response_code >= 300) {
    QUIC_LOG(ERROR) << "Request for " << url_string
                    << " failed with HTTP response code " << response_code;
    return false;
  }

  std::string response_body = client->latest_response_body();
  std::cerr << "Request succeeded for " << url_string << std::endl
            << response_body << std::endl;

  return true;
}

int RunMasqueClient(int argc, char* argv[]) {
  QuicSystemEventLoop event_loop("masque_client");
  const char* usage = "Usage: masque_client [options] <url>";

  // All non-flag arguments should be interpreted as URLs to fetch.
  std::vector<std::string> urls = QuicParseCommandLineFlags(usage, argc, argv);
  if (urls.empty()) {
    QuicPrintCommandLineFlagHelp(usage);
    return 1;
  }

  const bool disable_certificate_verification =
      GetQuicFlag(FLAGS_disable_certificate_verification);
  QuicEpollServer epoll_server;

  QuicUrl masque_url(urls[0], "https");
  if (masque_url.host().empty()) {
    masque_url = QuicUrl(QuicStrCat("https://", urls[0]), "https");
  }
  if (masque_url.host().empty()) {
    QUIC_LOG(ERROR) << "Failed to parse MASQUE server address " << urls[0];
    return 1;
  }
  std::unique_ptr<ProofVerifier> proof_verifier;
  if (disable_certificate_verification) {
    proof_verifier = std::make_unique<FakeProofVerifier>();
  } else {
    proof_verifier = CreateDefaultProofVerifier(masque_url.host());
  }
  std::unique_ptr<MasqueEpollClient> masque_client =
      MasqueEpollClient::Create(masque_url.host(), masque_url.port(),
                                &epoll_server, std::move(proof_verifier));
  if (masque_client == nullptr) {
    return 1;
  }

  std::cerr << "MASQUE is connected " << masque_client->connection_id()
            << std::endl;

  for (size_t i = 1; i < urls.size(); ++i) {
    if (!SendRequest(masque_client.get(), &epoll_server, urls[i],
                     disable_certificate_verification)) {
      return 1;
    }
  }

  return 0;
}

}  // namespace

}  // namespace quic

int main(int argc, char* argv[]) {
  return quic::RunMasqueClient(argc, argv);
}
