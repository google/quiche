// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/event_loop_tcp_client_socket.h"

#include <functional>
#include <memory>
#include <utility>
#include <vector>

#include "absl/functional/bind_front.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "absl/types/span.h"
#include "quiche/quic/core/io/event_loop_socket_factory.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/io/stream_client_socket.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/platform/api/quiche_mutex.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/platform/api/quiche_test_loopback.h"
#include "quiche/common/platform/api/quiche_thread.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quic::test {
namespace {

bool CreateListeningServerSocket(SocketFd* out_socket_descriptor,
                                 QuicSocketAddress* out_socket_address) {
  QUICHE_CHECK(out_socket_descriptor);
  QUICHE_CHECK(out_socket_address);

  absl::StatusOr<SocketFd> socket = socket_api::CreateSocket(
      quiche::TestLoopback().address_family(), socket_api::SocketProtocol::kTcp,
      /*blocking=*/true);
  QUICHE_CHECK(socket.ok());

  // Set an extremely small receive buffer size to increase the odds of buffers
  // filling up when testing asynchronous writes.
  static const QuicByteCount kReceiveBufferSize = 2;
  absl::Status result =
      socket_api::SetReceiveBufferSize(socket.value(), kReceiveBufferSize);
  QUICHE_CHECK(result.ok());

  QuicSocketAddress bind_address(quiche::TestLoopback(), /*port=*/0);
  result = socket_api::Bind(socket.value(), bind_address);
  QUICHE_CHECK(result.ok());

  absl::StatusOr<QuicSocketAddress> socket_address =
      socket_api::GetSocketAddress(socket.value());
  QUICHE_CHECK(socket_address.ok());

  result = socket_api::Listen(socket.value(), /*backlog=*/1);
  QUICHE_CHECK(result.ok());

  *out_socket_descriptor = socket.value();
  *out_socket_address = std::move(socket_address).value();
  return true;
}

class TestTcpServerSocketRunner : public quiche::QuicheThread {
 public:
  using SocketBehavior = std::function<void(SocketFd connected_socket)>;

  // On construction, spins a separate thread to accept a connection from
  // `server_socket_descriptor`, runs `behavior` with that connection, and then
  // closes the accepted connection socket. If `allow_accept_failure` is true,
  // will silently stop if an error is encountered accepting the connection.
  TestTcpServerSocketRunner(SocketFd server_socket_descriptor,
                            SocketBehavior behavior,
                            bool allow_accept_failure = false)
      : QuicheThread("TestTcpServerSocketRunner"),
        server_socket_descriptor_(server_socket_descriptor),
        behavior_(std::move(behavior)),
        allow_accept_failure_(allow_accept_failure) {
    Start();
  }

  ~TestTcpServerSocketRunner() override { WaitForCompletion(); }

  void WaitForCompletion() { completion_notification_.WaitForNotification(); }

 protected:
  void Run() override {
    if (AcceptSocket()) {
      behavior_(connection_socket_descriptor_);
      CloseSocket();
    } else {
      QUICHE_CHECK(allow_accept_failure_);
    }

    completion_notification_.Notify();
  }

 private:
  bool AcceptSocket() {
    absl::StatusOr<socket_api::AcceptResult> connection_socket =
        socket_api::Accept(server_socket_descriptor_, /*blocking=*/true);
    if (connection_socket.ok()) {
      connection_socket_descriptor_ = connection_socket.value().fd;
    }
    return connection_socket.ok();
  }

  void CloseSocket() {
    QUICHE_CHECK(socket_api::Close(connection_socket_descriptor_).ok());
  }

  const SocketFd server_socket_descriptor_;
  const SocketBehavior behavior_;
  const bool allow_accept_failure_;

  SocketFd connection_socket_descriptor_;

  quiche::QuicheNotification completion_notification_;
};

class EventLoopTcpClientSocketTest
    : public quiche::test::QuicheTestWithParam<QuicEventLoopFactory*>,
      public StreamClientSocket::AsyncVisitor {
 public:
  void SetUp() override {
    QUICHE_CHECK(CreateListeningServerSocket(&server_socket_descriptor_,
                                             &server_socket_address_));
  }

  void TearDown() override {
    if (server_socket_descriptor_ != kInvalidSocketFd) {
      QUICHE_CHECK(socket_api::Close(server_socket_descriptor_).ok());
    }
  }

  void ConnectComplete(absl::Status status) override {
    QUICHE_CHECK(!connect_result_.has_value());
    connect_result_ = std::move(status);
  }

  void ReceiveComplete(absl::StatusOr<quiche::QuicheMemSlice> data) override {
    QUICHE_CHECK(!receive_result_.has_value());
    receive_result_ = std::move(data);
  }

  void SendComplete(absl::Status status) override {
    QUICHE_CHECK(!send_result_.has_value());
    send_result_ = std::move(status);
  }

 protected:
  SocketFd server_socket_descriptor_ = kInvalidSocketFd;
  QuicSocketAddress server_socket_address_;

  MockClock clock_;
  std::unique_ptr<QuicEventLoop> event_loop_ = GetParam()->Create(&clock_);
  EventLoopSocketFactory socket_factory_{event_loop_.get(),
                                         quiche::SimpleBufferAllocator::Get()};

  absl::optional<absl::Status> connect_result_;
  absl::optional<absl::StatusOr<quiche::QuicheMemSlice>> receive_result_;
  absl::optional<absl::Status> send_result_;
};

std::string GetTestParamName(
    ::testing::TestParamInfo<QuicEventLoopFactory*> info) {
  return EscapeTestParamName(info.param->GetName());
}

INSTANTIATE_TEST_SUITE_P(EventLoopTcpClientSocketTests,
                         EventLoopTcpClientSocketTest,
                         ::testing::ValuesIn(GetAllSupportedEventLoops()),
                         &GetTestParamName);

TEST_P(EventLoopTcpClientSocketTest, Connect) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/nullptr);

  // No socket runner to accept the connection for the server, but that is not
  // expected to be necessary for the connection to complete from the client.
  EXPECT_TRUE(socket->ConnectBlocking().ok());

  socket->Disconnect();
}

TEST_P(EventLoopTcpClientSocketTest, ConnectAsync) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/this);

  socket->ConnectAsync();

  // Synchronous completion not normally expected, but since there is no known
  // way to delay the server side of the connection (the OS does not wait for
  // an accept() call), cannot be gauranteed that the connection will always
  // complete asynchronously. If connecting asynchronously (normal behavior),
  // expect completion once signalled by the event loop.
  if (!connect_result_.has_value()) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
    ASSERT_TRUE(connect_result_.has_value());
  }
  EXPECT_TRUE(connect_result_.value().ok());

  connect_result_.reset();
  socket->Disconnect();
  EXPECT_FALSE(connect_result_.has_value());
}

TEST_P(EventLoopTcpClientSocketTest, ErrorBeforeConnectAsync) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/this);

  // Close the server socket.
  EXPECT_TRUE(socket_api::Close(server_socket_descriptor_).ok());
  server_socket_descriptor_ = kInvalidSocketFd;

  socket->ConnectAsync();
  if (!connect_result_.has_value()) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
    ASSERT_TRUE(connect_result_.has_value());
  }

  // Expect an error because server socket was closed before connection.
  EXPECT_FALSE(connect_result_.value().ok());
}

TEST_P(EventLoopTcpClientSocketTest, ErrorDuringConnectAsync) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/this);

  socket->ConnectAsync();

  if (connect_result_.has_value()) {
    // Not typical, but theoretically nothing to stop the connection from
    // completing before the server socket is closed to trigger the error.
    EXPECT_TRUE(connect_result_.value().ok());
    return;
  }

  // Close the server socket.
  EXPECT_TRUE(socket_api::Close(server_socket_descriptor_).ok());
  server_socket_descriptor_ = kInvalidSocketFd;

  // Expect an error once signalled.
  EXPECT_FALSE(connect_result_.has_value());
  event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
  ASSERT_TRUE(connect_result_.has_value());
  EXPECT_FALSE(connect_result_.value().ok());
}

TEST_P(EventLoopTcpClientSocketTest, Disconnect) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/nullptr);

  ASSERT_TRUE(socket->ConnectBlocking().ok());
  socket->Disconnect();
}

TEST_P(EventLoopTcpClientSocketTest, DisconnectCancelsConnectAsync) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/this);

  socket->ConnectAsync();

  if (connect_result_.has_value()) {
    // Not typical, but theoretically nothing to stop the connection from
    // completing before the server socket is closed to trigger the error.
    EXPECT_TRUE(connect_result_.value().ok());
    return;
  }

  socket->Disconnect();

  // Expect immediate cancelled error.
  ASSERT_TRUE(connect_result_.has_value());
  EXPECT_TRUE(absl::IsCancelled(connect_result_.value()));
}

TEST_P(EventLoopTcpClientSocketTest, ConnectAndReconnect) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/nullptr);

  ASSERT_TRUE(socket->ConnectBlocking().ok());
  socket->Disconnect();

  // Expect `socket` can reconnect now that it has been disconnected.
  EXPECT_TRUE(socket->ConnectBlocking().ok());
  socket->Disconnect();
}

void SendDataOnSocket(absl::string_view data, SocketFd connected_socket) {
  while (!data.empty()) {
    absl::StatusOr<absl::string_view> remainder =
        socket_api::Send(connected_socket, data);
    if (!remainder.ok()) {
      return;
    }
    data = remainder.value();
  }
}

TEST_P(EventLoopTcpClientSocketTest, Receive) {
  std::string expected = {1, 2, 3, 4, 5, 6, 7, 8};
  TestTcpServerSocketRunner runner(
      server_socket_descriptor_, absl::bind_front(&SendDataOnSocket, expected));

  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/nullptr);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string received;
  absl::StatusOr<quiche::QuicheMemSlice> data;
  do {
    data = socket->ReceiveBlocking(100);
    ASSERT_TRUE(data.ok());
    received.append(data.value().data(), data.value().length());
  } while (!data.value().empty());
  EXPECT_EQ(received, expected);

  socket->Disconnect();
}

TEST_P(EventLoopTcpClientSocketTest, ReceiveAsync) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/this);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  // Start an async receive.  Expect no immediate results because runner not yet
  // setup to accept and send.
  socket->ReceiveAsync(100);
  EXPECT_FALSE(receive_result_.has_value());

  // Send data from server.
  std::string expected = {1, 2, 3, 4, 5, 6, 7, 8};
  TestTcpServerSocketRunner runner(
      server_socket_descriptor_, absl::bind_front(&SendDataOnSocket, expected));
  EXPECT_FALSE(receive_result_.has_value());
  for (int i = 0; i < 5 && !receive_result_.has_value(); ++i) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
  }

  // Expect to receive at least some of the sent data.
  ASSERT_TRUE(receive_result_.has_value());
  ASSERT_TRUE(receive_result_.value().ok());
  EXPECT_FALSE(receive_result_.value().value().empty());
  std::string received(receive_result_.value().value().data(),
                       receive_result_.value().value().length());

  // Get any remaining data via blocking calls.
  absl::StatusOr<quiche::QuicheMemSlice> data;
  do {
    data = socket->ReceiveBlocking(100);
    ASSERT_TRUE(data.ok());
    received.append(data.value().data(), data.value().length());
  } while (!data.value().empty());

  EXPECT_EQ(received, expected);

  receive_result_.reset();
  socket->Disconnect();
  EXPECT_FALSE(receive_result_.has_value());
}

TEST_P(EventLoopTcpClientSocketTest, DisconnectCancelsReceiveAsync) {
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/this);

  ASSERT_TRUE(socket->ConnectBlocking().ok());

  // Start an asynchronous read, expecting no completion because server never
  // sends any data.
  socket->ReceiveAsync(100);
  EXPECT_FALSE(receive_result_.has_value());

  // Disconnect and expect an immediate cancelled error.
  socket->Disconnect();
  ASSERT_TRUE(receive_result_.has_value());
  ASSERT_FALSE(receive_result_.value().ok());
  EXPECT_TRUE(absl::IsCancelled(receive_result_.value().status()));
}

// Receive from `connected_socket` until connection is closed, writing received
// data to `out_received`.
void ReceiveDataFromSocket(std::string* out_received,
                           SocketFd connected_socket) {
  out_received->clear();

  std::string buffer(100, 0);
  absl::StatusOr<absl::Span<char>> received;
  do {
    received = socket_api::Receive(connected_socket, absl::MakeSpan(buffer));
    QUICHE_CHECK(received.ok());
    out_received->insert(out_received->end(), received.value().begin(),
                         received.value().end());
  } while (!received.value().empty());
}

TEST_P(EventLoopTcpClientSocketTest, Send) {
  std::string sent;
  TestTcpServerSocketRunner runner(
      server_socket_descriptor_,
      absl::bind_front(&ReceiveDataFromSocket, &sent));

  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/0,
                                            /*async_visitor=*/nullptr);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string expected = {1, 2, 3, 4, 5, 6, 7, 8};
  EXPECT_TRUE(socket->SendBlocking(expected).ok());
  socket->Disconnect();

  runner.WaitForCompletion();
  EXPECT_EQ(sent, expected);
}

TEST_P(EventLoopTcpClientSocketTest, SendAsync) {
  // Use a small send buffer to improve chances of a send needing to be
  // asynchronous.
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/4,
                                            /*async_visitor=*/this);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  std::string expected;

  // Repeatedly write to socket until it does not complete synchronously.
  do {
    expected.insert(expected.end(), data.begin(), data.end());
    send_result_.reset();
    socket->SendAsync(data);
    ASSERT_TRUE(!send_result_.has_value() || send_result_.value().ok());
  } while (send_result_.has_value());

  // Begin receiving from server and expect more data to send.
  std::string sent;
  TestTcpServerSocketRunner runner(
      server_socket_descriptor_,
      absl::bind_front(&ReceiveDataFromSocket, &sent));
  EXPECT_FALSE(send_result_.has_value());
  for (int i = 0; i < 5 && !send_result_.has_value(); ++i) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromSeconds(1));
  }
  ASSERT_TRUE(send_result_.has_value());
  EXPECT_TRUE(send_result_.value().ok());

  send_result_.reset();
  socket->Disconnect();
  EXPECT_FALSE(send_result_.has_value());

  runner.WaitForCompletion();
  EXPECT_EQ(sent, expected);
}

TEST_P(EventLoopTcpClientSocketTest, DisconnectCancelsSendAsync) {
  // Use a small send buffer to improve chances of a send needing to be
  // asynchronous.
  std::unique_ptr<StreamClientSocket> socket =
      socket_factory_.CreateTcpClientSocket(server_socket_address_,
                                            /*receive_buffer_size=*/0,
                                            /*send_buffer_size=*/4,
                                            /*async_visitor=*/this);
  ASSERT_TRUE(socket->ConnectBlocking().ok());

  std::string data = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

  // Repeatedly write to socket until it does not complete synchronously.
  do {
    send_result_.reset();
    socket->SendAsync(data);
    ASSERT_TRUE(!send_result_.has_value() || send_result_.value().ok());
  } while (send_result_.has_value());

  // Disconnect and expect immediate cancelled error.
  socket->Disconnect();
  ASSERT_TRUE(send_result_.has_value());
  EXPECT_TRUE(absl::IsCancelled(send_result_.value()));
}

}  // namespace
}  // namespace quic::test
