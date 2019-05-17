// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicServer.  It listens forever on --port
// (default 6121) until it's killed or ctrl-cd to death.

#include <vector>

#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_flags.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/tools/quic_server.h"
#include "net/third_party/quiche/src/quic/tools/quic_simple_server_backend.h"
#include "net/third_party/quiche/src/quic/tools/quic_toy_server.h"

class SimpleServerFactory : public quic::QuicToyServer::ServerFactory {
 public:
  std::unique_ptr<quic::QuicSpdyServerBase> CreateServer(
      quic::QuicSimpleServerBackend* backend,
      std::unique_ptr<quic::ProofSource> proof_source) override {
    return quic::QuicMakeUnique<quic::QuicServer>(std::move(proof_source),
                                                  backend);
  }
};

int main(int argc, char* argv[]) {
  const char* usage = "Usage: quic_server [options]";
  std::vector<std::string> non_option_args =
      quic::QuicParseCommandLineFlags(usage, argc, argv);
  if (!non_option_args.empty()) {
    quic::QuicPrintCommandLineFlagHelp(usage);
    exit(0);
  }

  quic::QuicToyServer::MemoryCacheBackendFactory backend_factory;
  SimpleServerFactory server_factory;
  quic::QuicToyServer server(&backend_factory, &server_factory);
  return server.Start();
}
