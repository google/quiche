// Copyright (c) 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/tools/quic_client.h"

#include <memory>

#include "file/base/path.h"
#include "file/util/linux_fileops.h"
#include "gfe/gfe2/base/epoll_server.h"
#include "net/util/netutil.h"
#include "testing/base/public/test_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test_loopback.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"
#include "net/third_party/quiche/src/quic/test_tools/crypto_test_utils.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_client_peer.h"

namespace quic {
namespace test {
namespace {

const char* kPathToFds = "/proc/self/fd";

// Counts the number of open sockets for the current process.
size_t NumOpenSocketFDs() {
  std::vector<QuicString> fd_entries;
  QuicString error_message;

  CHECK(file_util::LinuxFileOps::ListDirectoryEntries(kPathToFds, &fd_entries,
                                                      &error_message));

  size_t socket_count = 0;
  for (const QuicString& entry : fd_entries) {
    if (entry == "." || entry == "..") {
      continue;
    }

    QuicString fd_path =
        file_util::LinuxFileOps::ReadLink(file::JoinPath(kPathToFds, entry));
    if (QuicTextUtils::StartsWith(fd_path, "socket:")) {
      socket_count++;
    }
  }

  return socket_count;
}

// Creates a new QuicClient and Initializes it. Caller is responsible for
// deletion.
QuicClient* CreateAndInitializeQuicClient(QuicEpollServer* eps, uint16_t port) {
  QuicSocketAddress server_address(QuicSocketAddress(TestLoopback(), port));
  QuicServerId server_id("hostname", server_address.port(), false);
  ParsedQuicVersionVector versions = AllSupportedVersions();
  QuicClient* client =
      new QuicClient(server_address, server_id, versions, eps,
                     crypto_test_utils::ProofVerifierForTesting());
  EXPECT_TRUE(client->Initialize());
  return client;
}

class QuicClientTest : public QuicTest {};

TEST_F(QuicClientTest, DoNotLeakSocketFDs) {
  // Make sure that the QuicClient doesn't leak socket FDs. Doing so could cause
  // port exhaustion in long running processes which repeatedly create clients.

  // Record initial number of FDs, after creation of EpollServer.
  QuicEpollServer eps;
  size_t number_of_open_fds = NumOpenSocketFDs();

  // Create a number of clients, initialize them, and verify this has resulted
  // in additional FDs being opened.
  const int kNumClients = 50;
  for (int i = 0; i < kNumClients; ++i) {
    std::unique_ptr<QuicClient> client(
        CreateAndInitializeQuicClient(&eps, net_util::PickUnusedPortOrDie()));

    // Initializing the client will create a new FD.
    EXPECT_LT(number_of_open_fds, NumOpenSocketFDs());
  }

  // The FDs created by the QuicClients should now be closed.
  EXPECT_EQ(number_of_open_fds, NumOpenSocketFDs());
}

TEST_F(QuicClientTest, CreateAndCleanUpUDPSockets) {
  QuicEpollServer eps;
  size_t number_of_open_fds = NumOpenSocketFDs();

  std::unique_ptr<QuicClient> client(
      CreateAndInitializeQuicClient(&eps, net_util::PickUnusedPortOrDie()));
  EXPECT_EQ(number_of_open_fds + 1, NumOpenSocketFDs());
  // Create more UDP sockets.
  EXPECT_TRUE(QuicClientPeer::CreateUDPSocketAndBind(client.get()));
  EXPECT_EQ(number_of_open_fds + 2, NumOpenSocketFDs());
  EXPECT_TRUE(QuicClientPeer::CreateUDPSocketAndBind(client.get()));
  EXPECT_EQ(number_of_open_fds + 3, NumOpenSocketFDs());

  // Clean up UDP sockets.
  QuicClientPeer::CleanUpUDPSocket(client.get(), client->GetLatestFD());
  EXPECT_EQ(number_of_open_fds + 2, NumOpenSocketFDs());
  QuicClientPeer::CleanUpUDPSocket(client.get(), client->GetLatestFD());
  EXPECT_EQ(number_of_open_fds + 1, NumOpenSocketFDs());
}

}  // namespace
}  // namespace test
}  // namespace quic
