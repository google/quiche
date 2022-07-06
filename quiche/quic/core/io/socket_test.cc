// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/socket.h"

#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/platform/api/quiche_test_loopback.h"

namespace quic {
namespace {

using quiche::test::QuicheTest;
using testing::Lt;
using testing::SizeIs;

SocketFd CreateTestSocket(socket_api::SocketProtocol protocol,
                          bool blocking = true) {
  absl::StatusOr<SocketFd> socket = socket_api::CreateSocket(
      quiche::TestLoopback().address_family(), protocol, blocking);

  if (socket.ok()) {
    return socket.value();
  } else {
    QUICHE_CHECK(false);
    return kInvalidSocketFd;
  }
}

TEST(SocketTest, CreateAndCloseSocket) {
  QuicIpAddress localhost_address = quiche::TestLoopback();
  absl::StatusOr<SocketFd> created_socket = socket_api::CreateSocket(
      localhost_address.address_family(), socket_api::SocketProtocol::kUdp);

  EXPECT_TRUE(created_socket.ok());

  EXPECT_TRUE(socket_api::Close(created_socket.value()).ok());
}

TEST(SocketTest, SetSocketBlocking) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  EXPECT_TRUE(socket_api::SetSocketBlocking(socket, /*blocking=*/false).ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, SetReceiveBufferSize) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  EXPECT_TRUE(socket_api::SetReceiveBufferSize(socket, /*size=*/100).ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, SetSendBufferSize) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  EXPECT_TRUE(socket_api::SetSendBufferSize(socket, /*size=*/100).ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Connect) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  // UDP, so "connecting" should succeed without any listening sockets.
  EXPECT_TRUE(socket_api::Connect(
                  socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0))
                  .ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, GetSocketError) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  absl::Status error = socket_api::GetSocketError(socket);
  EXPECT_TRUE(error.ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Bind) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  EXPECT_TRUE(socket_api::Bind(
                  socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0))
                  .ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, GetSocketAddress) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  ASSERT_TRUE(socket_api::Bind(
                  socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0))
                  .ok());

  absl::StatusOr<QuicSocketAddress> address =
      socket_api::GetSocketAddress(socket);
  EXPECT_TRUE(address.ok());
  EXPECT_TRUE(address.value().IsInitialized());
  EXPECT_EQ(address.value().host(), quiche::TestLoopback());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Listen) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kTcp);
  ASSERT_TRUE(socket_api::Bind(
                  socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0))
                  .ok());

  EXPECT_TRUE(socket_api::Listen(socket, /*backlog=*/5).ok());

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Accept) {
  // Need a non-blocking socket to avoid waiting when no connection comes.
  SocketFd socket =
      CreateTestSocket(socket_api::SocketProtocol::kTcp, /*blocking=*/false);
  ASSERT_TRUE(socket_api::Bind(
                  socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0))
                  .ok());
  ASSERT_TRUE(socket_api::Listen(socket, /*backlog=*/5).ok());

  // Nothing set up to connect, so expect kUnavailable.
  absl::StatusOr<socket_api::AcceptResult> result = socket_api::Accept(socket);
  ASSERT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsUnavailable(result.status()));

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Receive) {
  // Non-blocking to avoid waiting when no data to receive.
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/false);

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> result =
      socket_api::Receive(socket, absl::MakeSpan(buffer));
  ASSERT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsUnavailable(result.status()));

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Peek) {
  // Non-blocking to avoid waiting when no data to receive.
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/false);

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> result =
      socket_api::Receive(socket, absl::MakeSpan(buffer), /*peek=*/true);
  ASSERT_FALSE(result.ok());
  EXPECT_TRUE(absl::IsUnavailable(result.status()));

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

TEST(SocketTest, Send) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  // UDP, so "connecting" should succeed without any listening sockets.
  ASSERT_TRUE(socket_api::Connect(
                  socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0))
                  .ok());

  char buffer[] = {12, 34, 56, 78};
  // Expect at least some data to be sent successfully.
  absl::StatusOr<absl::string_view> result =
      socket_api::Send(socket, absl::string_view(buffer, sizeof(buffer)));
  ASSERT_TRUE(result.ok());
  EXPECT_THAT(result.value(), SizeIs(Lt(4)));

  EXPECT_TRUE(socket_api::Close(socket).ok());
}

}  // namespace
}  // namespace quic
