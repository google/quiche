// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/quic_server_io_harness.h"

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/platform/api/quiche_test_loopback.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quic::test {
namespace {

using quiche::test::QuicheTest;
using quiche::test::StatusIs;

class QuicServerIoHarnessTest : public QuicheTest {};

TEST_F(QuicServerIoHarnessTest, CreateAndBindServerSocketSucceeds) {
  absl::StatusOr<OwnedSocketFd> fd = CreateAndBindServerSocket(
      QuicSocketAddress(quiche::TestLoopback(), /*port=*/0));
  QUICHE_ASSERT_OK(fd);
  ASSERT_TRUE(fd->valid());

  absl::StatusOr<QuicSocketAddress> bound_address =
      socket_api::GetSocketAddress(fd->get());
  QUICHE_ASSERT_OK(bound_address);
  EXPECT_EQ(bound_address->host(), quiche::TestLoopback());
  EXPECT_NE(bound_address->port(), 0);
}

TEST_F(QuicServerIoHarnessTest,
       CreateAndBindServerSocketAddressInUseReturnsError) {
  absl::StatusOr<OwnedSocketFd> fd = CreateAndBindServerSocket(
      QuicSocketAddress(quiche::TestLoopback(), /*port=*/0));
  QUICHE_ASSERT_OK(fd);
  ASSERT_TRUE(fd->valid());

  absl::StatusOr<QuicSocketAddress> bound_address =
      socket_api::GetSocketAddress(fd->get());
  QUICHE_ASSERT_OK(bound_address);
  ASSERT_NE(bound_address->port(), 0);

  // socket_api::Bind does not normalize status codes for address-in-use.
#if defined(_WIN32)
  constexpr absl::StatusCode kExpectedError = absl::StatusCode::kAlreadyExists;
#else
  constexpr absl::StatusCode kExpectedError =
      absl::StatusCode::kFailedPrecondition;
#endif
  EXPECT_THAT(CreateAndBindServerSocket(*bound_address),
              StatusIs(kExpectedError));
}

#if !defined(_WIN32)
// Exercises the socket-creation failure path; skipped on Windows where
// WSASocket() accepts AF_UNSPEC and reaches socket_api::Bind's QUICHE_DCHECK.
TEST_F(QuicServerIoHarnessTest,
       CreateAndBindServerSocketUninitializedAddressReturnsError) {
  EXPECT_THAT(CreateAndBindServerSocket(QuicSocketAddress()),
              StatusIs(absl::StatusCode::kInternal));
}
#endif  // !defined(_WIN32)

}  // namespace
}  // namespace quic::test
