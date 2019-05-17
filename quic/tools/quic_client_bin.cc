// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
// Standard request/response:
//   quic_client www.google.com
//   quic_client www.google.com --quiet
//   quic_client www.google.com --port=443
//
// Use a specific version:
//   quic_client www.google.com --quic_version=23
//
// Send a POST instead of a GET:
//   quic_client www.google.com --body="this is a POST body"
//
// Append additional headers to the request:
//   quic_client www.google.com --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   quic_client mail.google.com --host=www.google.com
//
// Connect to a specific IP:
//   IP=`dig www.google.com +short | head -1`
//   quic_client www.google.com --host=${IP}
//
// Send repeated requests and change ephemeral port between requests
//   quic_client www.google.com --num_requests=10
//
// Try to connect to a host which does not speak QUIC:
//   quic_client www.example.com
//
// This tool is available as a built binary at:
// /google/data/ro/teams/quic/tools/quic_client
// After submitting changes to this file, you will need to follow the
// instructions at go/quic_client_binary_update

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_system_event_loop.h"
#include "net/third_party/quiche/src/quic/tools/quic_client.h"
#include "net/third_party/quiche/src/quic/tools/quic_toy_client.h"

namespace {

using quic::QuicSocketAddress;
using quic::QuicStringPiece;

QuicSocketAddress LookupAddress(std::string host, std::string port) {
  addrinfo hint;
  memset(&hint, 0, sizeof(hint));
  hint.ai_protocol = IPPROTO_UDP;

  addrinfo* info_list = nullptr;
  int result = getaddrinfo(host.c_str(), port.c_str(), &hint, &info_list);
  if (result != 0) {
    QUIC_LOG(ERROR) << "Failed to look up " << host << ": "
                    << gai_strerror(result);
    return QuicSocketAddress();
  }

  CHECK(info_list != nullptr);
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> info_list_owned(info_list,
                                                                 freeaddrinfo);
  return QuicSocketAddress(*info_list->ai_addr);
}

class QuicEpollClientFactory : public quic::QuicToyClient::ClientFactory {
 public:
  std::unique_ptr<quic::QuicSpdyClientBase> CreateClient(
      std::string host,
      uint16_t port,
      quic::ParsedQuicVersionVector versions,
      std::unique_ptr<quic::ProofVerifier> verifier) {
    quic::QuicSocketAddress addr = LookupAddress(host, quic::QuicStrCat(port));
    if (!addr.IsInitialized()) {
      QUIC_LOG(ERROR) << "Unable to resolve address: " << host;
      return nullptr;
    }
    quic::QuicServerId server_id(host, port, false);
    return quic::QuicMakeUnique<quic::QuicClient>(
        addr, server_id, versions, &epoll_server_, std::move(verifier));
  }

 private:
  quic::QuicEpollServer epoll_server_;
};

}  // namespace

int main(int argc, char* argv[]) {
  QuicSystemEventLoop event_loop("quic_client");
  const char* usage = "Usage: quic_client [options] <url>";

  // All non-flag arguments should be interpreted as URLs to fetch.
  std::vector<std::string> urls =
      quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (urls.size() != 1) {
    quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }

  QuicEpollClientFactory factory;
  quic::QuicToyClient client(&factory);
  return client.SendRequestsAndPrintResponses(urls);
}
