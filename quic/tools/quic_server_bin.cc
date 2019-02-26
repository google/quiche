// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#include <vector>

#include "base/commandlineflags.h"
#include "base/init_google.h"
#include "net/httpsconnection/certificates.proto.h"
#include "net/httpsconnection/sslcontext.h"
#include "net/third_party/quiche/src/quic/core/crypto/proof_source_google3.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/tools/quic_memory_cache_backend.h"
#include "net/third_party/quiche/src/quic/tools/quic_server.h"

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t,
                              port,
                              6121,
                              "The port the quic server will listen on.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    string,
    certificate_dir,
    "/google/src/head/depot/google3/net/third_party/quiche/src/quic/core/crypto/testdata",
    "The directory containing certificate files.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    string,
    intermediate_certificate_name,
    "intermediate.crt",
    "The name of the file containing the intermediate certificate.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    string,
    leaf_certificate_name,
    "test.example.com",
    "The name of the file containing the leaf certificate.");

std::unique_ptr<quic::ProofSource> CreateProofSource(
    const string& base_directory,
    const string& intermediate_cert_name,
    const string& leaf_cert_name) {
  SetQuicFlag(&FLAGS_disable_permission_validation, true);

  httpsconnection::CertificateConfig config;
  config.set_base_directory(base_directory);
  config.set_issuing_certificates_file(intermediate_cert_name);
  config.add_cert()->set_name(leaf_cert_name);

  auto ssl_ctx = std::make_shared<SSLContext>(
      SSLContext::SSL_SERVER_CONTEXT,
      SSLContext::SESSION_CACHE_SERVER |
          SSLContext::SESSION_CACHE_NO_INTERNAL_STORE);
  CHECK_OK(ssl_ctx->Initialize(config));

  return std::unique_ptr<quic::ProofSource>(
      new quic::ProofSourceGoogle3(ssl_ctx, "unused_cert_mpm_version"));
}

int main(int argc, char* argv[]) {
  const char* usage = "Usage: quic_server [options]";
  std::vector<quic::QuicString> non_option_args =
      quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }

  quic::QuicMemoryCacheBackend memory_cache_backend;
  if (!GetQuicFlag(FLAGS_quic_response_cache_dir).empty()) {
    memory_cache_backend.InitializeBackend(
        GetQuicFlag(FLAGS_quic_response_cache_dir));
  }

  quic::QuicServer server(
      CreateProofSource(GetQuicFlag(FLAGS_certificate_dir),
                        GetQuicFlag(FLAGS_intermediate_certificate_name),
                        GetQuicFlag(FLAGS_leaf_certificate_name)),
      &memory_cache_backend);

  if (!server.CreateUDPSocketAndListen(quic::QuicSocketAddress(
          quic::QuicIpAddress::Any6(), GetQuicFlag(FLAGS_port)))) {
    return 1;
  }

  while (true) {
    server.WaitForEvents();
  }
}
