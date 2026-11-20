// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/tun_device.h"

#include <fcntl.h>
#include <linux/if_ether.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <cstdint>
#include <cstring>
#include <ios>
#include <optional>
#include <string>
#include <vector>

#include "absl/flags/flag.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/qbone/platform/kernel_interface.h"
#include "quiche/quic/qbone/platform/virtio_net_header.h"
#include "quiche/common/quiche_endian.h"

ABSL_FLAG(std::string, qbone_client_tun_device_path, "/dev/net/tun",
          "The path to the QBONE client's TUN device.");

namespace quic {

ethhdr CreateTapEthHdr(const uint8_t mac[ETH_ALEN]) {
  ethhdr hdr{};
  memcpy(&hdr.h_dest, mac, ETH_ALEN);
  memcpy(&hdr.h_source, mac, ETH_ALEN);
  // Assume ipv6 for now
  hdr.h_proto = quiche::QuicheEndian::HostToNet16(ETH_P_IPV6);
  return hdr;
}

const int kInvalidFd = -1;

TunTapDevice::TunTapDevice(const std::string& interface_name, int mtu,
                           int tx_queue_len, bool persist, bool setup_tun,
                           bool is_tap, KernelInterface* kernel,
                           bool use_vnet_hdr)
    : interface_name_(interface_name),
      mtu_(mtu),
      tx_queue_len_(tx_queue_len),
      persist_(persist),
      setup_tun_(setup_tun),
      is_tap_(is_tap),
      use_vnet_hdr_(use_vnet_hdr),
      kernel_(*kernel) {}

TunTapDevice::~TunTapDevice() {
  if (!persist_) {
    Down();
  }
  CloseDevice();
}

bool TunTapDevice::Init() {
  if (interface_name_.empty() || interface_name_.size() >= IFNAMSIZ) {
    QUIC_BUG(quic_bug_10995_1)
        << "interface_name must be nonempty and shorter than " << IFNAMSIZ;
    return false;
  }

  if (!OpenDevice()) {
    return false;
  }

  if (!ConfigureInterface()) {
    return false;
  }

  if (is_tap_) {
    struct ifreq if_request;
    memset(&if_request, 0, sizeof(if_request));
    interface_name_.copy(if_request.ifr_name, IFNAMSIZ);
    if (!NetdeviceIoctl(SIOCGIFHWADDR, &if_request)) {
      QUIC_LOG(ERROR) << "Failed to get hardware address for TAP device: "
                      << interface_name_;
      CloseDevice();
      return false;
    }
    eth_hdr_ = CreateTapEthHdr(
        reinterpret_cast<const uint8_t*>(if_request.ifr_hwaddr.sa_data));
  }

  return true;
}

// TODO(pengg): might be better to use netlink socket, once we have a library to
// use
bool TunTapDevice::Up() {
  if (!setup_tun_) {
    return true;
  }
  struct ifreq if_request;
  memset(&if_request, 0, sizeof(if_request));
  // copy does not zero-terminate the result string, but we've memset the
  // entire struct.
  interface_name_.copy(if_request.ifr_name, IFNAMSIZ);
  if_request.ifr_flags = IFF_UP;

  return NetdeviceIoctl(SIOCSIFFLAGS, reinterpret_cast<void*>(&if_request));
}

// TODO(pengg): might be better to use netlink socket, once we have a library to
// use
bool TunTapDevice::Down() {
  if (!setup_tun_) {
    return true;
  }
  struct ifreq if_request;
  memset(&if_request, 0, sizeof(if_request));
  // copy does not zero-terminate the result string, but we've memset the
  // entire struct.
  interface_name_.copy(if_request.ifr_name, IFNAMSIZ);
  if_request.ifr_flags = 0;

  return NetdeviceIoctl(SIOCSIFFLAGS, reinterpret_cast<void*>(&if_request));
}

int TunTapDevice::GetReadFileDescriptor() const {
  if (file_descriptors_.empty()) {
    return kInvalidFd;
  }
  return file_descriptors_[0];
}

int TunTapDevice::GetWriteFileDescriptor() const {
  if (file_descriptors_.empty()) {
    return kInvalidFd;
  }
  return file_descriptors_[0];
}

int TunTapDevice::OpenQueue() {
  struct ifreq if_request;
  memset(&if_request, 0, sizeof(if_request));
  interface_name_.copy(if_request.ifr_name, IFNAMSIZ);

  if_request.ifr_flags = IFF_MULTI_QUEUE | IFF_NO_PI;
  if (is_tap_) {
    if_request.ifr_flags |= IFF_TAP;
  } else {
    if_request.ifr_flags |= IFF_TUN;
  }
  if (use_vnet_hdr_) {
    if_request.ifr_flags |= IFF_VNET_HDR;
  }

  int new_fd = kInvalidFd;
  if (!OpenFileDescriptor(kernel_,
                          absl::GetFlag(FLAGS_qbone_client_tun_device_path),
                          if_request, O_NONBLOCK | O_RDWR, persist_, &new_fd)) {
    if (new_fd != kInvalidFd) {
      kernel_.close(new_fd);
    }
    return kInvalidFd;
  }

  if (new_fd == kInvalidFd) {
    QUIC_LOG(ERROR) << "OpenFileDescriptor succeeded with an invalid FD.";
    return kInvalidFd;
  }

  file_descriptors_.push_back(new_fd);
  return new_fd;
}

bool TunTapDevice::CheckFeatures(KernelInterface& kernel, int tun_device_fd,
                                 unsigned int extra_required_features) {
  unsigned int actual_features;
  if (kernel.ioctl(tun_device_fd, TUNGETFEATURES, &actual_features) != 0) {
    QUIC_PLOG(WARNING) << "Failed to TUNGETFEATURES";
    return false;
  }
  unsigned int required_features =
      IFF_TUN | IFF_NO_PI | extra_required_features;
  if ((required_features & actual_features) != required_features) {
    QUIC_LOG(WARNING)
        << "Required feature does not exist. required_features: 0x" << std::hex
        << required_features << " vs actual_features: 0x" << std::hex
        << actual_features;
    return false;
  }
  return true;
}

bool TunTapDevice::OpenFileDescriptor(KernelInterface& kernel,
                                      const std::string& path, ifreq if_request,
                                      int flags, bool persist, int* return_fd) {
  *return_fd = kernel.open(path.c_str(), flags);
  if (*return_fd < 0) {
    QUIC_PLOG(WARNING) << "Failed to open " << path;
    *return_fd = kInvalidFd;
    return false;
  }
  const bool use_vnet_hdr = (if_request.ifr_flags & IFF_VNET_HDR) != 0;
  if (!CheckFeatures(kernel, *return_fd, use_vnet_hdr ? IFF_VNET_HDR : 0)) {
    return false;
  }

  if (kernel.ioctl(*return_fd, TUNSETIFF,
                   reinterpret_cast<void*>(&if_request)) != 0) {
    QUIC_PLOG(WARNING) << "Failed to TUNSETIFF on fd(" << *return_fd << ")";
    return false;
  }

  // The header is a property of the device, not of the descriptor: a
  // descriptor attached to a device that already has other queues keeps the
  // device's flags, whatever it asked for. Reading or writing with the wrong
  // framing would corrupt every packet, so check that the device has the
  // header exactly when it was asked for.
  struct ifreq actual_request;
  memset(&actual_request, 0, sizeof(actual_request));
  if (kernel.ioctl(*return_fd, TUNGETIFF,
                   reinterpret_cast<void*>(&actual_request)) != 0) {
    QUIC_PLOG(WARNING) << "Failed to TUNGETIFF on fd(" << *return_fd << ")";
    return false;
  }
  const bool device_uses_vnet_hdr =
      (actual_request.ifr_flags & IFF_VNET_HDR) != 0;
  if (device_uses_vnet_hdr != use_vnet_hdr) {
    QUIC_LOG(WARNING) << "The TUN device was already in use "
                      << (device_uses_vnet_hdr ? "with" : "without")
                      << " IFF_VNET_HDR, which a new queue can't change. "
                         "Device flags: 0x"
                      << std::hex << actual_request.ifr_flags;
    return false;
  }

  if (use_vnet_hdr) {
    // Makes sure the right header size is still used, in case it was changed
    // outside of Bonnet.
    int vnet_hdr_size = sizeof(virtio_net_hdr);
    if (kernel.ioctl(*return_fd, TUNSETVNETHDRSZ, &vnet_hdr_size) != 0) {
      QUIC_PLOG(WARNING) << "Failed to TUNSETVNETHDRSZ on fd(" << *return_fd
                         << ")";
      return false;
    }
  }

  if (kernel.ioctl(*return_fd, TUNSETPERSIST,
                   persist ? reinterpret_cast<void*>(&if_request) : nullptr) !=
      0) {
    QUIC_PLOG(WARNING) << "Failed to TUNSETPERSIST on fd(" << *return_fd << ")";
    return false;
  }
  return true;
}

bool TunTapDevice::OpenDevice() {
  CloseDevice();
  return OpenQueue() != kInvalidFd;
}

// TODO(pengg): might be better to use netlink socket, once we have a library to
// use
bool TunTapDevice::ConfigureInterface() {
  if (!setup_tun_) {
    return true;
  }

  struct ifreq if_request;
  memset(&if_request, 0, sizeof(if_request));
  // copy does not zero-terminate the result string, but we've memset the entire
  // struct.
  interface_name_.copy(if_request.ifr_name, IFNAMSIZ);
  if_request.ifr_mtu = mtu_;

  if (!NetdeviceIoctl(SIOCSIFMTU, reinterpret_cast<void*>(&if_request))) {
    CloseDevice();
    return false;
  }

  if (tx_queue_len_ > 0) {
    // NOMUTANTS(SBR): Zero-initializes union before setting ifr_qlen; ifr_name
    // is already populated above.
    memset(&if_request, 0, sizeof(if_request));
    interface_name_.copy(if_request.ifr_name, IFNAMSIZ);
    if_request.ifr_qlen = tx_queue_len_;
    if (!NetdeviceIoctl(SIOCSIFTXQLEN, reinterpret_cast<void*>(&if_request))) {
      CloseDevice();
      return false;
    }
  }

  return true;
}

bool TunTapDevice::NetdeviceIoctl(int request, void* argp) {
  int fd = kernel_.socket(AF_INET6, SOCK_DGRAM, 0);
  if (fd < 0) {
    QUIC_PLOG(WARNING) << "Failed to create AF_INET6 socket.";
    return false;
  }

  if (kernel_.ioctl(fd, request, argp) != 0) {
    QUIC_PLOG(WARNING) << "Failed ioctl request: " << request;
    kernel_.close(fd);
    return false;
  }
  kernel_.close(fd);
  return true;
}

void TunTapDevice::CloseDevice() {
  for (int fd : file_descriptors_) {
    kernel_.close(fd);
  }
  file_descriptors_.clear();
  eth_hdr_ = std::nullopt;
}

}  // namespace quic
