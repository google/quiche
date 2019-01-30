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
// Try to connect to a host which does not speak QUIC:
//   quic_client www.example.com
//
// A built binary of this tool lives at:
// /google/data/ro/teams/quic/tools/quic_client
//
// To update the above binary, run:
// $ /google/data/ro/projects/build_copier/build_copier \
//     --config=quic quic_client

#include <iostream>

#include "base/commandlineflags.h"
#include "base/init_google.h"
#include "net/base/ipaddress.h"
#include "net/dns/hostlookup.h"
#include "third_party/absl/flags/flag.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_verifier_google3.h"
#include "net/third_party/quiche/src/quic/core/quic_packets.h"
#include "net/third_party/quiche/src/quic/core/quic_server_id.h"
#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_str_cat.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quiche/src/quic/tools/quic_client.h"
#include "net/third_party/quiche/src/quic/tools/quic_url.h"

class FakeProofVerifier : public quic::ProofVerifier {
 public:
  ~FakeProofVerifier() override {}
  quic::QuicAsyncStatus VerifyProof(
      const string& /*hostname*/,
      const uint16_t /*port*/,
      const string& /*server_config*/,
      quic::QuicTransportVersion /*quic_version*/,
      quic::QuicStringPiece /*chlo_hash*/,
      const std::vector<string>& /*certs*/,
      const string& /*cert_sct*/,
      const string& /*signature*/,
      const quic::ProofVerifyContext* /*context*/,
      string* /*error_details*/,
      std::unique_ptr<quic::ProofVerifyDetails>* /*details*/,
      std::unique_ptr<quic::ProofVerifierCallback> /*callback*/) override {
    return quic::QUIC_SUCCESS;
  }
  quic::QuicAsyncStatus VerifyCertChain(
      const string& /*hostname*/,
      const std::vector<string>& /*certs*/,
      const quic::ProofVerifyContext* /*context*/,
      string* /*error_details*/,
      std::unique_ptr<quic::ProofVerifyDetails>* /*details*/,
      std::unique_ptr<quic::ProofVerifierCallback> /*callback*/) override {
    return quic::QUIC_SUCCESS;
  }
  std::unique_ptr<quic::ProofVerifyContext> CreateDefaultContext() override {
    return nullptr;
  }
};

DEFINE_string(host,
              "",
              "The IP or hostname to connect to. If not provided, the host "
              "will be derived from the provided URL.");
DEFINE_int32(port, 0, "The port to connect to.");
DEFINE_string(body, "", "If set, send a POST with this body.");
DEFINE_string(body_hex,
              "",
              "If set, contents are converted from hex to ascii, before "
              "sending as body of a POST. e.g. --body_hex=\"68656c6c6f\"");
DEFINE_string(headers,
              "",
              "A semicolon separated list of key:value pairs to "
              "add to request headers.");
DEFINE_bool(quiet, false, "Set to true for a quieter output experience.");
DEFINE_int32(quic_version,
             -1,
             "QUIC version to speak, e.g. 21. If not set, then all available "
             "versions are offered in the handshake.");
DEFINE_bool(version_mismatch_ok,
            false,
            "If true, a version mismatch in the handshake is not considered a "
            "failure. Useful for probing a server to determine if it speaks "
            "any version of QUIC.");
DEFINE_bool(redirect_is_success,
            true,
            "If true, an HTTP response code of 3xx is considered to be a "
            "successful response, otherwise a failure.");
DEFINE_int32(initial_mtu, 0, "Initial MTU of the connection.");
DEFINE_string(root_certificate_file,
              "/google/src/head/depot/google3/security/cacerts/"
              "for_connecting_to_google/roots.pem",
              "Path to the root certificate which the server's certificate is "
              "required to chain to.");
ABSL_FLAG(bool,
          disable_certificate_verification,
          false,
          "If true, don't verify the server certificate.");
ABSL_FLAG(bool,
          drop_response_body,
          false,
          "If true, drop response body immediately after it is received.");

using quic::QuicStringPiece;
using quic::QuicTextUtils;
using quic::QuicUrl;
using std::cerr;
using std::cout;
using std::endl;

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, true);

  // All non-flag arguments should be interpreted as URLs to fetch.
  if (argc != 2) {
    cerr << "Usage: " << argv[0] << " [optional flags] url" << endl;
    return 1;
  }

  QuicUrl url(argv[1], "https");
  string host = FLAGS_host;
  if (host.empty()) {
    host = url.host();
  }
  int port = FLAGS_port;
  if (port == 0) {
    port = url.port();
  }

  // Determine IP address to connect to from supplied hostname.
  std::vector<net_base::IPAddress> ipvec;
  if (!net_dns::HostLookup::GetIPAddrInfo(host, &ipvec, nullptr, nullptr,
                                          nullptr)) {
    cerr << "Failed to resolve '" << host << "'" << endl;
    return 1;
  }
  CHECK(!ipvec.empty()) << "HostLookup::GetIPAddrInfo returned no IP address";
  quic::QuicIpAddress ip_addr = quic::QuicIpAddress(
      (quic::QuicIpAddressImpl(ipvec[0])));  // Choose first DNS result.
  string host_port = quic::QuicStrCat(ip_addr.ToString(), ":", port);
  cout << "Resolved " << host << " to " << host_port << endl;

  // Build the client, and try to connect.
  quic::QuicEpollServer epoll_server;
  quic::QuicServerId server_id(url.host(), port, false);
  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();
  if (FLAGS_quic_version != -1) {
    versions.clear();
    versions.push_back(quic::ParsedQuicVersion(
        quic::PROTOCOL_QUIC_CRYPTO,
        static_cast<quic::QuicTransportVersion>(FLAGS_quic_version)));
  }
  std::unique_ptr<quic::ProofVerifier> proof_verifier;
  if (GetQuicFlag(FLAGS_disable_certificate_verification)) {
    proof_verifier = quic::QuicMakeUnique<FakeProofVerifier>();
  } else {
    proof_verifier = quic::QuicMakeUnique<quic::ProofVerifierGoogle3>(
        FLAGS_root_certificate_file);
  }
  quic::QuicClient client(quic::QuicSocketAddress(ip_addr, port), server_id,
                          versions, &epoll_server, std::move(proof_verifier));
  client.set_initial_max_packet_length(
      FLAGS_initial_mtu != 0 ? FLAGS_initial_mtu : quic::kDefaultMaxPacketSize);
  client.set_drop_response_body(GetQuicFlag(FLAGS_drop_response_body));
  if (!client.Initialize()) {
    cerr << "Failed to initialize client." << endl;
    return 1;
  }
  if (!client.Connect()) {
    quic::QuicErrorCode error = client.session()->error();
    if (error == quic::QUIC_INVALID_VERSION) {
      cout << "Server talks QUIC, but none of the versions supported by "
           << "this client: " << ParsedQuicVersionVectorToString(versions)
           << endl;
      // 0: No error.
      // 20: Failed to connect due to QUIC_INVALID_VERSION.
      return FLAGS_version_mismatch_ok ? 0 : 20;
    }
    cerr << "Failed to connect to " << host_port
         << ". Error: " << quic::QuicErrorCodeToString(error) << endl;
    return 1;
  }
  cout << "Connected to " << host_port << endl;

  // Construct the string body from flags, if provided.
  string body = FLAGS_body;
  if (!FLAGS_body_hex.empty()) {
    DCHECK(FLAGS_body.empty()) << "Only set one of --body and --body_hex.";
    body = QuicTextUtils::HexDecode(FLAGS_body_hex);
  }

  // Construct a GET or POST request for supplied URL.
  spdy::SpdyHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.HostPort();
  header_block[":path"] = url.PathParamsQuery();

  // Append any additional headers supplied on the command line.
  for (QuicStringPiece sp : QuicTextUtils::Split(FLAGS_headers, ';')) {
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<QuicStringPiece> kv = QuicTextUtils::Split(sp, ':');
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client.set_store_response(true);

  // Send the request.
  client.SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);

  // Print request and response details.
  if (!FLAGS_quiet) {
    cout << "Request:" << endl;
    cout << "headers:" << header_block.DebugString();
    if (!FLAGS_body_hex.empty()) {
      // Print the user provided hex, rather than binary body.
      cout << "body:\n"
           << QuicTextUtils::HexDump(QuicTextUtils::HexDecode(FLAGS_body_hex))
           << endl;
    } else {
      cout << "body: " << body << endl;
    }
    cout << endl;

    if (!client.preliminary_response_headers().empty()) {
      cout << "Preliminary response headers: "
           << client.preliminary_response_headers() << endl;
      cout << endl;
    }

    cout << "Response:" << endl;
    cout << "headers: " << client.latest_response_headers() << endl;
    string response_body = client.latest_response_body();
    if (!FLAGS_body_hex.empty()) {
      // Assume response is binary data.
      cout << "body:\n" << QuicTextUtils::HexDump(response_body) << endl;
    } else {
      cout << "body: " << response_body << endl;
    }
    cout << "trailers: " << client.latest_response_trailers() << endl;
  }

  size_t response_code = client.latest_response_code();
  if (response_code >= 200 && response_code < 300) {
    cout << "Request succeeded (" << response_code << ")." << endl;
    return 0;
  } else if (response_code >= 300 && response_code < 400) {
    if (FLAGS_redirect_is_success) {
      cout << "Request succeeded (redirect " << response_code << ")." << endl;
      return 0;
    } else {
      cout << "Request failed (redirect " << response_code << ")." << endl;
      return 1;
    }
  } else {
    cerr << "Request failed (" << response_code << ")." << endl;
    return 1;
  }
}
