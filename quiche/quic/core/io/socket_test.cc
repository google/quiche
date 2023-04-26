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
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic {
namespace {

using quiche::test::QuicheTest;
using quiche::test::StatusIs;
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

  QUICHE_EXPECT_OK(created_socket.status());

  QUICHE_EXPECT_OK(socket_api::Close(created_socket.value()));
}

TEST(SocketTest, SetSocketBlocking) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  QUICHE_EXPECT_OK(socket_api::SetSocketBlocking(socket, /*blocking=*/false));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetReceiveBufferSize) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  QUICHE_EXPECT_OK(socket_api::SetReceiveBufferSize(socket, /*size=*/100));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, SetSendBufferSize) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  QUICHE_EXPECT_OK(socket_api::SetSendBufferSize(socket, /*size=*/100));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Connect) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  // UDP, so "connecting" should succeed without any listening sockets.
  QUICHE_EXPECT_OK(socket_api::Connect(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, GetSocketError) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/true);

  absl::Status error = socket_api::GetSocketError(socket);
  QUICHE_EXPECT_OK(error);

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Bind) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);

  QUICHE_EXPECT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, GetSocketAddress) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  absl::StatusOr<QuicSocketAddress> address =
      socket_api::GetSocketAddress(socket);
  QUICHE_EXPECT_OK(address);
  EXPECT_TRUE(address.value().IsInitialized());
  EXPECT_EQ(address.value().host(), quiche::TestLoopback());

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Listen) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kTcp);
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  QUICHE_EXPECT_OK(socket_api::Listen(socket, /*backlog=*/5));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Accept) {
  // Need a non-blocking socket to avoid waiting when no connection comes.
  SocketFd socket =
      CreateTestSocket(socket_api::SocketProtocol::kTcp, /*blocking=*/false);
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));
  QUICHE_ASSERT_OK(socket_api::Listen(socket, /*backlog=*/5));

  // Nothing set up to connect, so expect kUnavailable.
  absl::StatusOr<socket_api::AcceptResult> result = socket_api::Accept(socket);
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnavailable));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Receive) {
  // Non-blocking to avoid waiting when no data to receive.
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/false);

  // On Windows, recv() fails on a socket that is connectionless and not bound.
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> result =
      socket_api::Receive(socket, absl::MakeSpan(buffer));
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnavailable));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Peek) {
  // Non-blocking to avoid waiting when no data to receive.
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp,
                                     /*blocking=*/false);

  // On Windows, recv() fails on a socket that is connectionless and not bound.
  QUICHE_ASSERT_OK(socket_api::Bind(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> result =
      socket_api::Receive(socket, absl::MakeSpan(buffer), /*peek=*/true);
  EXPECT_THAT(result, StatusIs(absl::StatusCode::kUnavailable));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

TEST(SocketTest, Send) {
  SocketFd socket = CreateTestSocket(socket_api::SocketProtocol::kUdp);
  // UDP, so "connecting" should succeed without any listening sockets.
  QUICHE_ASSERT_OK(socket_api::Connect(
      socket, QuicSocketAddress(quiche::TestLoopback(), /*port=*/0)));

  char buffer[] = {12, 34, 56, 78};
  // Expect at least some data to be sent successfully.
  absl::StatusOr<absl::string_view> result =
      socket_api::Send(socket, absl::string_view(buffer, sizeof(buffer)));
  QUICHE_ASSERT_OK(result.status());
  EXPECT_THAT(result.value(), SizeIs(Lt(4)));

  QUICHE_EXPECT_OK(socket_api::Close(socket));
}

}  // namespace
}  // namespace quic
