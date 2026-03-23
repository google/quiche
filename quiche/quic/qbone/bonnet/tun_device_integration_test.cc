// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <linux/if_tun.h>

#include <cerrno>
#include <memory>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/str_format.h"
#include "absl/types/span.h"
#include "quiche/quic/core/crypto/quic_random.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/bonnet/tun_device.h"
#include "quiche/quic/qbone/bonnet/tun_device_controller.h"
#include "quiche/quic/qbone/platform/ip_range.h"
#include "quiche/quic/qbone/platform/kernel_interface.h"
#include "quiche/quic/qbone/platform/netlink.h"
#include "quiche/quic/test_tools/test_ip_packets.h"

namespace quic::test {
namespace {

// Tests for TunDevice that rely on the real kernel and bring up a real tun
// device. Mostly functions as an experimentation playground for poking at TUN.
class TunDeviceIntegrationTest : public QuicTest {
 protected:
  void SetUp() override {
    ASSERT_TRUE(local_address_.FromString("2001:db8:2026:1::"));
    ASSERT_TRUE(remote_address_.FromString("2001:db8:2026:2::"));

    std::string interface_name = absl::StrFormat(
        "qbone-test-%d",
        QuicRandom::GetInstance()->InsecureRandUint64() % 10000);
    tun_device_ = std::make_unique<TunTapDevice>(
        interface_name, /*mtu=*/1600, /*persist=*/false, /*setup_tun=*/true,
        /*is_tap=*/false, &kernel_);
    tun_device_controller_ = std::make_unique<TunDeviceController>(
        interface_name, /*setup_tun=*/true, &netlink_);
  }

  QuicIpAddress local_address_;
  QuicIpAddress remote_address_;

  Kernel kernel_;
  Netlink netlink_{&kernel_};
  std::unique_ptr<TunTapDevice> tun_device_;
  std::unique_ptr<TunDeviceController> tun_device_controller_;
};

absl::Status SetNonBlocking(SocketFd fd) {
  int flags = ::fcntl(fd, F_GETFL, 0);
  if (flags < 0) {
    return absl::ErrnoToStatus(errno, "Failed to get flags");
  }
  if (::fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
    return absl::ErrnoToStatus(errno, "Failed to set flags");
  }
  return absl::OkStatus();
}

TEST_F(TunDeviceIntegrationTest, MassiveNumWrites) {
  ASSERT_TRUE(tun_device_->Init());
  ASSERT_GT(tun_device_->GetWriteFileDescriptor(), -1);
  ASSERT_TRUE(tun_device_controller_->UpdateAddress(
      {IpRange(local_address_, /*prefix_length=*/64)}));
  ASSERT_TRUE(tun_device_->Up());

  int sndbuf = 500;
  ASSERT_GE(kernel_.ioctl(tun_device_->GetWriteFileDescriptor(), TUNSETSNDBUF,
                          &sndbuf),
            0);

  ASSERT_OK(SetNonBlocking(tun_device_->GetWriteFileDescriptor()));

  QuicSocketAddress source_endpoint(remote_address_, /*port=*/53368);
  QuicSocketAddress destination_endpoint(local_address_, /*port=*/56362);
  std::string payload(256, 'a');
  std::string packet = CreateIpPacket(
      source_endpoint.host(), destination_endpoint.host(),
      CreateUdpPacket(source_endpoint, destination_endpoint, payload));

  absl::StatusOr<SocketFd> udp_socket = socket_api::CreateSocket(
      IpAddressFamily::IP_V6, socket_api::SocketProtocol::kUdp,
      /*blocking=*/false);
  ASSERT_OK(udp_socket);
  OwnedSocketFd owned_udp_socket(udp_socket.value());

  ASSERT_OK(socket_api::Bind(udp_socket.value(), destination_endpoint));

  std::vector<char> receive_buffer(1600);
  for (int i = 0; i < 1000000; ++i) {
    ASSERT_EQ(kernel_.write(tun_device_->GetWriteFileDescriptor(),
                            packet.data(), packet.size()),
              packet.size())
        << "Write failed on iteration " << i << " with error " << errno;

    absl::StatusOr<absl::Span<char>> receive_data =
        socket_api::Receive(udp_socket.value(), absl::MakeSpan(receive_buffer));
    ASSERT_OK(receive_data)
        << "Receive failed on iteration " << i << " with error "
        << receive_data.status().message();
  }
}

TEST_F(TunDeviceIntegrationTest, MassiveWrite) {
  ASSERT_TRUE(tun_device_->Init());
  ASSERT_GT(tun_device_->GetWriteFileDescriptor(), -1);
  ASSERT_TRUE(tun_device_controller_->UpdateAddress(
      {IpRange(local_address_, /*prefix_length=*/64)}));
  ASSERT_TRUE(tun_device_->Up());

  QuicSocketAddress source_endpoint(remote_address_, /*port=*/53368);
  QuicSocketAddress destination_endpoint(local_address_, /*port=*/56362);
  std::string payload(65527, 'a');
  std::string packet = CreateIpPacket(
      source_endpoint.host(), destination_endpoint.host(),
      CreateUdpPacket(source_endpoint, destination_endpoint, payload));

  absl::StatusOr<SocketFd> udp_socket = socket_api::CreateSocket(
      IpAddressFamily::IP_V6, socket_api::SocketProtocol::kUdp,
      /*blocking=*/false);
  ASSERT_OK(udp_socket);
  OwnedSocketFd owned_udp_socket(udp_socket.value());

  ASSERT_OK(socket_api::Bind(udp_socket.value(), destination_endpoint));

  ASSERT_EQ(kernel_.write(tun_device_->GetWriteFileDescriptor(), packet.data(),
                          packet.size()),
            packet.size());

  std::vector<char> receive_buffer(payload.size() + 1000);
  absl::StatusOr<absl::Span<char>> receive_data =
      socket_api::Receive(udp_socket.value(), absl::MakeSpan(receive_buffer));
  ASSERT_OK(receive_data);
  ASSERT_EQ(receive_data->size(), payload.size());
}

}  // namespace
}  // namespace quic::test
