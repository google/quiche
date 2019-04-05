// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#include <vector>

#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_default_proof_providers.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_socket_address.h"
#include "net/third_party/quiche/src/quic/tools/quic_memory_cache_backend.h"
#include "net/third_party/quiche/src/quic/tools/quic_server.h"

DEFINE_QUIC_COMMAND_LINE_FLAG(int32_t,
                              port,
                              6121,
                              "The port the quic server will listen on.");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    std::string,
    quic_response_cache_dir,
    "",
    "Specifies the directory used during QuicHttpResponseCache "
    "construction to seed the cache. Cache directory can be "
    "generated using `wget -p --save-headers <url>`");

DEFINE_QUIC_COMMAND_LINE_FLAG(
    int32_t,
    quic_ietf_draft,
    0,
    "QUIC IETF draft number to use over the wire, e.g. 18. "
    "This also enables required internal QUIC flags.");

int main(int argc, char* argv[]) {
  const char* usage = "Usage: quic_server [options]";
  std::vector<std::string> non_option_args =
      quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }

  const int32_t quic_ietf_draft = GetQuicFlag(FLAGS_quic_ietf_draft);
  if (quic_ietf_draft > 0) {
    quic::QuicVersionInitializeSupportForIetfDraft(quic_ietf_draft);
    quic::QuicEnableVersion(
        quic::ParsedQuicVersion(quic::PROTOCOL_TLS1_3, quic::QUIC_VERSION_99));
  }

  quic::QuicMemoryCacheBackend memory_cache_backend;
  if (!GetQuicFlag(FLAGS_quic_response_cache_dir).empty()) {
    memory_cache_backend.InitializeBackend(
        GetQuicFlag(FLAGS_quic_response_cache_dir));
  }

  quic::QuicServer server(quic::CreateDefaultProofSource(),
                          &memory_cache_backend);

  if (!server.CreateUDPSocketAndListen(quic::QuicSocketAddress(
          quic::QuicIpAddress::Any6(), GetQuicFlag(FLAGS_port)))) {
    return 1;
  }

  while (true) {
    server.WaitForEvents();
  }
}
