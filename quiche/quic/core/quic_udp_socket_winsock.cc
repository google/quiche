// Port to Windows Marten Richter
// taken from quiche
// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
// note we left linux stuff in here, in case we need to port them later

#include "absl/base/optimization.h"
#include "quiche/quic/core/io/socket.h"
#include "quiche/quic/core/quic_udp_socket.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"
#include "quiche/quic/platform/api/quic_ip_address_family.h"
#include "quiche/quic/platform/api/quic_udp_socket_platform_api.h"

#define UCHAR *WSA_CMSG_DATA(LPWSACMSGHDR pcmsg);

#if defined(__linux__) && !defined(__ANDROID__)
#define QUIC_UDP_SOCKET_SUPPORT_TTL 1
#endif
namespace quic
{
  namespace
  {

#if defined(__linux__) && (!defined(__ANDROID_API__) || __ANDROID_API__ >= 21)
#define QUIC_UDP_SOCKET_SUPPORT_LINUX_TIMESTAMPING 1
    // This is the structure that SO_TIMESTAMPING fills into the cmsg header.
    // It is well-defined, but does not have a definition in a public header.
    // See https://www.kernel.org/doc/Documentation/networking/timestamping.txt
    // for more information.
    struct LinuxSoTimestamping
    {
      // The converted system time of the timestamp.
      struct timespec systime;
      // Deprecated; serves only as padding.
      struct timespec hwtimetrans;
      // The raw hardware timestamp.
      struct timespec hwtimeraw;
    };
    const size_t kCmsgSpaceForRecvTimestamp =
        CMSG_SPACE(sizeof(LinuxSoTimestamping));
#else
    const size_t kCmsgSpaceForRecvTimestamp = 0;
#endif

    const size_t kMinCmsgSpaceForRead =
        CMSG_SPACE(sizeof(uint32_t))                           // Dropped packet count
        + CMSG_SPACE(sizeof(in_pktinfo))                       // V4 Self IP
        + CMSG_SPACE(sizeof(in6_pktinfo))                      // V6 Self IP
        + kCmsgSpaceForRecvTimestamp + CMSG_SPACE(sizeof(int)) // TTL
        + kCmsgSpaceForGooglePacketHeader;

    void SetV4SelfIpInControlMessage(const QuicIpAddress &self_address,
                                     cmsghdr *cmsg)
    {
      QUICHE_DCHECK(self_address.IsIPv4());
      in_pktinfo *pktinfo = reinterpret_cast<in_pktinfo *>(WSA_CMSG_DATA(cmsg));
      memset(pktinfo, 0, sizeof(in_pktinfo));
      pktinfo->ipi_ifindex = 0;
      std::string address_string = self_address.ToPackedString();
      memcpy(&pktinfo->ipi_addr, address_string.c_str(),
             address_string.length());
    }

    void SetV6SelfIpInControlMessage(const QuicIpAddress &self_address,
                                     cmsghdr *cmsg)
    {
      QUICHE_DCHECK(self_address.IsIPv6());
      in6_pktinfo *pktinfo = reinterpret_cast<in6_pktinfo *>(WSA_CMSG_DATA(cmsg));
      memset(pktinfo, 0, sizeof(in6_pktinfo));
      std::string address_string = self_address.ToPackedString();
      memcpy(&pktinfo->ipi6_addr, address_string.c_str(), address_string.length());
    }

    void PopulatePacketInfoFromControlMessage(struct cmsghdr *cmsg,
                                              QuicUdpPacketInfo *packet_info,
                                              BitMask64 packet_info_interested)
    {
#if defined(__linux__) && defined(SO_RXQ_OVFL)
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_RXQ_OVFL)
      {
        if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::DROPPED_PACKETS))
        {
          packet_info->SetDroppedPackets(
              *(reinterpret_cast<uint32_t *> WSA_CMSG_DATA(cmsg)));
        }
        return;
      }
#endif

#if defined(QUIC_UDP_SOCKET_SUPPORT_LINUX_TIMESTAMPING)
      if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SO_TIMESTAMPING)
      {
        if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::RECV_TIMESTAMP))
        {
          LinuxSoTimestamping *linux_ts =
              reinterpret_cast<LinuxSoTimestamping *>(WSA_CMSG_DATA(cmsg));
          timespec *ts = &linux_ts->systime;
          int64_t usec = (static_cast<int64_t>(ts->tv_sec) * 1000 * 1000) +
                         (static_cast<int64_t>(ts->tv_nsec) / 1000);
          packet_info->SetReceiveTimestamp(
              QuicWallTime::FromUNIXMicroseconds(usec));
        }
        return;
      }
#endif

      if (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_PKTINFO)
      {
        if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::V6_SELF_IP))
        {
          const in6_pktinfo *info = reinterpret_cast<in6_pktinfo *>(WSA_CMSG_DATA(cmsg));
          const char *addr_data = reinterpret_cast<const char *>(&info->ipi6_addr);
          int addr_len = sizeof(in6_addr);
          QuicIpAddress self_v6_ip;
          if (self_v6_ip.FromPackedString(addr_data, addr_len))
          {
            packet_info->SetSelfV6Ip(self_v6_ip);
          }
          else
          {
            QUIC_BUG(quic_bug_10751_1) << "QuicIpAddress::FromPackedString failed";
          }
        }
        return;
      }

      if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO)
      {
        if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::V4_SELF_IP))
        {
          const in_pktinfo *info = reinterpret_cast<in_pktinfo *>(WSA_CMSG_DATA(cmsg));
          const char *addr_data = reinterpret_cast<const char *>(&info->ipi_addr);
          int addr_len = sizeof(in_addr);
          QuicIpAddress self_v4_ip;
          if (self_v4_ip.FromPackedString(addr_data, addr_len))
          {
            packet_info->SetSelfV4Ip(self_v4_ip);
          }
          else
          {
            QUIC_BUG(quic_bug_10751_2) << "QuicIpAddress::FromPackedString failed";
          }
        }
        return;
      }

      if ((cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_TTL) ||
          (cmsg->cmsg_level == IPPROTO_IPV6 && cmsg->cmsg_type == IPV6_HOPLIMIT))
      {
        if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::TTL))
        {
          packet_info->SetTtl(*(reinterpret_cast<int *>(WSA_CMSG_DATA(cmsg))));
        }
        return;
      }

      if (packet_info_interested.IsSet(
              QuicUdpPacketInfoBit::GOOGLE_PACKET_HEADER))
      {
        BufferSpan google_packet_headers;
        if (GetGooglePacketHeadersFromControlMessage(
                cmsg, &google_packet_headers.buffer,
                &google_packet_headers.buffer_len))
        {
          packet_info->SetGooglePacketHeaders(google_packet_headers);
        }
      }
    }

    bool NextCmsg(WSAMSG *hdr, char *control_buffer, size_t control_buffer_len,
                  int cmsg_level, int cmsg_type, size_t data_size,
                  cmsghdr **cmsg /*in, out*/)
    {
      // msg_controllen needs to be increased first, otherwise CMSG_NXTHDR will
      // return nullptr.
      hdr->Control.len += CMSG_SPACE(data_size);
      if (hdr->Control.len > control_buffer_len)
      {
        return false;
      }

      if ((*cmsg) == nullptr)
      {
        QUICHE_DCHECK_EQ(nullptr, hdr->Control.buf);
        memset(control_buffer, 0, control_buffer_len);
        hdr->Control.buf = control_buffer;
        (*cmsg) = CMSG_FIRSTHDR(hdr);
      }
      else
      {
        QUICHE_DCHECK_NE(nullptr, hdr->Control.buf);
        (*cmsg) = CMSG_NXTHDR(hdr, (*cmsg));
      }

      if (nullptr == (*cmsg))
      {
        return false;
      }

      (*cmsg)->cmsg_len = CMSG_LEN(data_size);
      (*cmsg)->cmsg_level = cmsg_level;
      (*cmsg)->cmsg_type = cmsg_type;

      return true;
    }
  } // namespace

  LPFN_WSARECVMSG WSARecvMsg = nullptr;
  LPFN_WSASENDMSG WSASendMsg = nullptr;

  WSADATA WSAData;

  bool initSockets()
  {
    int res;

    // Initialize Winsock
    res = WSAStartup(MAKEWORD(2, 2), &WSAData);
    if (res != 0)
    {
      QUIC_LOG_FIRST_N(ERROR, 100)
          << "WSAStartup failed: %d\n"
          << res;
      return false;
    }

    SOCKET sock = INVALID_SOCKET;
    sock = socket(AF_INET, SOCK_DGRAM, 0);

    // should we buffer this somewhere? Does it take time...
    GUID grv = WSAID_WSARECVMSG;
    DWORD dwBytesReturned = 0;
    if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &grv, sizeof(grv), &WSARecvMsg, sizeof(WSARecvMsg),
                 &dwBytesReturned, NULL, NULL) != 0)
    {
      QUIC_LOG_FIRST_N(ERROR, 100)
          << "WSARecvMsg is not available ";
      return false;
    }

    // should we buffer this somewhere? Does it take time...
    GUID gsnd = WSAID_WSASENDMSG;
    if (WSAIoctl(sock, SIO_GET_EXTENSION_FUNCTION_POINTER, &gsnd, sizeof(gsnd), &WSASendMsg, sizeof(WSASendMsg),
                 &dwBytesReturned, NULL, NULL) != 0)
    {
      QUIC_LOG_FIRST_N(ERROR, 100)
          << "WSASendMsg is not available ";
      return false;
    }
    closesocket(sock);
    return true;
  }

  bool destroySockets()
  {
    WSACleanup();
    return true;
  }

  QuicUdpSocketFd QuicUdpSocketApi::Create(int address_family,
                                           int receive_buffer_size,
                                           int send_buffer_size, bool ipv6_only)
  {
    // QUICHE_DCHECK here so the program exits early(before reading packets) in
    // debug mode. This should have been a static_assert, however it can't be done
    // on ios/osx because CMSG_SPACE isn't a constant expression there.
    QUICHE_DCHECK_GE(kDefaultUdpPacketControlBufferSize, kMinCmsgSpaceForRead);

    absl::StatusOr<SocketFd> socket =
        socket_api::CreateSocket(quiche::FromPlatformAddressFamily(address_family),
                                 socket_api::SocketProtocol::kUdp,
                                 /*blocking=*/false);

    if (!socket.ok())
    {
      QUIC_LOG_FIRST_N(ERROR, 100)
          << "UDP non-blocking socket creation for address_family="
          << address_family << " failed: " << socket.status();
      return kQuicInvalidSocketFd;
    }

    SetGoogleSocketOptions(socket.value());

    if (!SetupSocket(socket.value(), address_family, receive_buffer_size,
                     send_buffer_size, ipv6_only))
    {
      Destroy(socket.value());
      return kQuicInvalidSocketFd;
    }

    return socket.value();
  }

  bool QuicUdpSocketApi::SetupSocket(QuicUdpSocketFd fd, int address_family,
                                     int receive_buffer_size,
                                     int send_buffer_size, bool ipv6_only)
  {
    // Receive buffer size.
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, reinterpret_cast<const char *>(&receive_buffer_size),
                   sizeof(receive_buffer_size)) != 0)
    {
      QUIC_LOG_FIRST_N(ERROR, 100) << "Failed to set socket recv size";
      return false;
    }

    // Send buffer size.
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, reinterpret_cast<const char *>(&send_buffer_size),
                   sizeof(send_buffer_size)) != 0)
    {
      QUIC_LOG_FIRST_N(ERROR, 100) << "Failed to set socket send size";
      return false;
    }

    if (!(address_family == AF_INET6 && ipv6_only))
    {
      if (!EnableReceiveSelfIpAddressForV4(fd))
      {
        QUIC_LOG_FIRST_N(ERROR, 100)
            << "Failed to enable receiving of self v4 ip";
        return false;
      }
    }

    if (address_family == AF_INET6)
    {
      if (!EnableReceiveSelfIpAddressForV6(fd))
      {
        QUIC_LOG_FIRST_N(ERROR, 100)
            << "Failed to enable receiving of self v6 ip";
        return false;
      }
    }

    return true;
  }

  void QuicUdpSocketApi::Destroy(QuicUdpSocketFd fd)
  {
    if (fd != kQuicInvalidSocketFd)
    {
      absl::Status result = socket_api::Close(fd);
      if (!result.ok())
      {
        QUIC_LOG_FIRST_N(WARNING, 100)
            << "Failed to close UDP socket with error " << result;
      }
    }
  }

  bool QuicUdpSocketApi::Bind(QuicUdpSocketFd fd, QuicSocketAddress address)
  {
    sockaddr_storage addr = address.generic_address();
    int addr_len =
        address.host().IsIPv4() ? sizeof(sockaddr_in) : sizeof(sockaddr_in6);
    return 0 == bind(fd, reinterpret_cast<sockaddr *>(&addr), addr_len);
  }

  bool QuicUdpSocketApi::EnableDroppedPacketCount(QuicUdpSocketFd fd)
  {
#if defined(__linux__) && defined(SO_RXQ_OVFL)
    int get_overflow = 1;
    return 0 == setsockopt(fd, SOL_SOCKET, SO_RXQ_OVFL, &get_overflow,
                           sizeof(get_overflow));
#else
    (void)fd;
    return false;
#endif
  }

  bool QuicUdpSocketApi::EnableReceiveSelfIpAddressForV4(QuicUdpSocketFd fd)
  {
    int get_self_ip = 1;
    return 0 == setsockopt(fd, IPPROTO_IP, IP_PKTINFO, reinterpret_cast<const char *>(&get_self_ip),
                           sizeof(get_self_ip));
  }

  bool QuicUdpSocketApi::EnableReceiveSelfIpAddressForV6(QuicUdpSocketFd fd)
  {
    int get_self_ip = 1;
    // was IPV6_RECVPKTINFO
    return 0 == setsockopt(fd, IPPROTO_IPV6, IPV6_PKTINFO, reinterpret_cast<const char *>(&get_self_ip),
                           sizeof(get_self_ip));
  }

  bool QuicUdpSocketApi::EnableReceiveTimestamp(QuicUdpSocketFd fd)
  {
#if defined(__linux__) && (!defined(__ANDROID_API__) || __ANDROID_API__ >= 21)
    int timestamping = SOF_TIMESTAMPING_RX_SOFTWARE | SOF_TIMESTAMPING_SOFTWARE;
    return 0 == setsockopt(fd, SOL_SOCKET, SO_TIMESTAMPING, &timestamping,
                           sizeof(timestamping));
#else
    (void)fd;
    return false;
#endif
  }

  bool QuicUdpSocketApi::EnableReceiveTtlForV4(QuicUdpSocketFd fd)
  {
#if defined(QUIC_UDP_SOCKET_SUPPORT_TTL)
    int get_ttl = 1;
    return 0 == setsockopt(fd, IPPROTO_IP, IP_RECVTTL, &get_ttl, sizeof(get_ttl));
#else
    (void)fd;
    return false;
#endif
  }

  bool QuicUdpSocketApi::EnableReceiveTtlForV6(QuicUdpSocketFd fd)
  {
#if defined(QUIC_UDP_SOCKET_SUPPORT_TTL)
    int get_ttl = 1;
    return 0 == setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &get_ttl,
                           sizeof(get_ttl));
#else
    (void)fd;
    return false;
#endif
  }

  bool QuicUdpSocketApi::WaitUntilReadable(QuicUdpSocketFd fd,
                                           QuicTime::Delta timeout)
  {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    timeval select_timeout;
    select_timeout.tv_sec = timeout.ToSeconds();
    select_timeout.tv_usec = timeout.ToMicroseconds() % 1000000;

    return 1 == select(1 + fd, &read_fds, nullptr, nullptr, &select_timeout);
  }

  void QuicUdpSocketApi::ReadPacket(QuicUdpSocketFd fd,
                                    BitMask64 packet_info_interested,
                                    ReadPacketResult *result)
  {
    result->ok = false;
    BufferSpan &packet_buffer = result->packet_buffer;
    BufferSpan &control_buffer = result->control_buffer;
    QuicUdpPacketInfo *packet_info = &result->packet_info;

    QUICHE_DCHECK_GE(control_buffer.buffer_len, kMinCmsgSpaceForRead);

    ULONG bufferlen = packet_buffer.buffer_len;
    WSABUF iov = {bufferlen, const_cast<char *>(packet_buffer.buffer)};
    struct sockaddr_storage raw_peer_address;

    if (control_buffer.buffer_len > 0)
    {
      reinterpret_cast<struct cmsghdr *>(control_buffer.buffer)->cmsg_len =
          control_buffer.buffer_len;
    }

    WSAMSG hdr;
    hdr.name = reinterpret_cast<LPSOCKADDR>(&raw_peer_address);
    hdr.namelen = sizeof(raw_peer_address);
    hdr.lpBuffers = &iov;
    hdr.dwBufferCount = 1;
    hdr.dwFlags = 0;
    hdr.Control.buf = control_buffer.buffer;
    hdr.Control.len = control_buffer.buffer_len;

    DWORD bytes_read = 0;

    int ret = WSARecvMsg(fd, &hdr, &bytes_read, nullptr, nullptr);
    if (ret == SOCKET_ERROR)
    {
      const int error_num = WSAGetLastError();
      if (error_num != WSAEWOULDBLOCK)
      {
        QUIC_LOG_FIRST_N(ERROR, 100)
            << "Error reading packet: " << error_num;
      }
      return;
    }

    if (ABSL_PREDICT_FALSE(hdr.dwFlags & MSG_CTRUNC))
    {
      QUIC_BUG(quic_bug_10751_3)
          << "Control buffer too small. size:" << control_buffer.buffer_len;
      return;
    }

    if (ABSL_PREDICT_FALSE(hdr.dwFlags & MSG_TRUNC) ||
        // Normally "bytes_read > packet_buffer.buffer_len" implies the MSG_TRUNC
        // bit is set, but it is not the case if tested with config=android_arm64.
        static_cast<size_t>(bytes_read) > packet_buffer.buffer_len)
    {
      QUIC_LOG_FIRST_N(WARNING, 100)
          << "Received truncated QUIC packet: buffer size:"
          << packet_buffer.buffer_len << " packet size:" << bytes_read;
      return;
    }

    packet_buffer.buffer_len = bytes_read;
    if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::PEER_ADDRESS))
    {
      packet_info->SetPeerAddress(QuicSocketAddress(raw_peer_address));
    }

    if (hdr.Control.len > 0)
    {
      for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr); cmsg != nullptr;
           cmsg = CMSG_NXTHDR(&hdr, cmsg))
      {
        BitMask64 prior_bitmask = packet_info->bitmask();
        PopulatePacketInfoFromControlMessage(cmsg, packet_info,
                                             packet_info_interested);
        if (packet_info->bitmask() == prior_bitmask)
        {
          QUIC_DLOG(INFO) << "Ignored cmsg_level:" << cmsg->cmsg_level
                          << ", cmsg_type:" << cmsg->cmsg_type;
        }
      }
    }

    result->ok = true;
  }

  size_t QuicUdpSocketApi::ReadMultiplePackets(QuicUdpSocketFd fd,
                                               BitMask64 packet_info_interested,
                                               ReadPacketResults *results)
  {
    // Potential TODO WinSock supports similar stuff
#if defined(__linux__) && !defined(__ANDROID__)
    // Use recvmmsg.
    size_t hdrs_size = sizeof(mmsghdr) * results->size();
    mmsghdr *hdrs = static_cast<mmsghdr *>(alloca(hdrs_size));
    memset(hdrs, 0, hdrs_size);

    struct TempPerPacketData
    {
      iovec iov;
      sockaddr_storage raw_peer_address;
    };
    TempPerPacketData *packet_data_array = static_cast<TempPerPacketData *>(
        alloca(sizeof(TempPerPacketData) * results->size()));

    for (size_t i = 0; i < results->size(); ++i)
    {
      (*results)[i].ok = false;

      msghdr *hdr = &hdrs[i].msg_hdr;
      TempPerPacketData *packet_data = &packet_data_array[i];
      packet_data->iov.iov_base = (*results)[i].packet_buffer.buffer;
      packet_data->iov.iov_len = (*results)[i].packet_buffer.buffer_len;

      hdr->msg_name = &packet_data->raw_peer_address;
      hdr->msg_namelen = sizeof(sockaddr_storage);
      hdr->msg_iov = &packet_data->iov;
      hdr->msg_iovlen = 1;
      hdr->msg_flags = 0;
      hdr->msg_control = (*results)[i].control_buffer.buffer;
      hdr->msg_controllen = (*results)[i].control_buffer.buffer_len;

      QUICHE_DCHECK_GE(hdr->msg_controllen, kMinCmsgSpaceForRead);
    }
    // If MSG_TRUNC is set on Linux, recvmmsg will return the real packet size in
    // |hdrs[i].msg_len| even if packet buffer is too small to receive it.
    int packets_read = recvmmsg(fd, hdrs, results->size(), MSG_TRUNC, nullptr);
    if (packets_read <= 0)
    {
      const int error_num = errno;
      if (error_num != EAGAIN)
      {
        QUIC_LOG_FIRST_N(ERROR, 100)
            << "Error reading packets: " << strerror(error_num);
      }
      return 0;
    }

    for (int i = 0; i < packets_read; ++i)
    {
      if (hdrs[i].msg_len == 0)
      {
        continue;
      }

      msghdr &hdr = hdrs[i].msg_hdr;
      if (ABSL_PREDICT_FALSE(hdr.msg_flags & MSG_CTRUNC))
      {
        QUIC_BUG(quic_bug_10751_4) << "Control buffer too small. size:"
                                   << (*results)[i].control_buffer.buffer_len
                                   << ", need:" << hdr.msg_controllen;
        continue;
      }

      if (ABSL_PREDICT_FALSE(hdr.msg_flags & MSG_TRUNC))
      {
        QUIC_LOG_FIRST_N(WARNING, 100)
            << "Received truncated QUIC packet: buffer size:"
            << (*results)[i].packet_buffer.buffer_len
            << " packet size:" << hdrs[i].msg_len;
        continue;
      }

      (*results)[i].ok = true;
      (*results)[i].packet_buffer.buffer_len = hdrs[i].msg_len;

      QuicUdpPacketInfo *packet_info = &(*results)[i].packet_info;
      if (packet_info_interested.IsSet(QuicUdpPacketInfoBit::PEER_ADDRESS))
      {
        packet_info->SetPeerAddress(
            QuicSocketAddress(packet_data_array[i].raw_peer_address));
      }

      if (hdr.msg_controllen > 0)
      {
        for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&hdr); cmsg != nullptr;
             cmsg = CMSG_NXTHDR(&hdr, cmsg))
        {
          PopulatePacketInfoFromControlMessage(cmsg, packet_info,
                                               packet_info_interested);
        }
      }
    }
    return packets_read;
#else
    size_t num_packets = 0;
    for (ReadPacketResult &result : *results)
    {
      result.ok = false;
    }
    for (ReadPacketResult &result : *results)
    {
      ReadPacket(fd, packet_info_interested, &result);
      if (!result.ok && WSAGetLastError() == WSAEWOULDBLOCK)
      {
        break;
      }
      ++num_packets;
    }
    return num_packets;
#endif
  }

  WriteResult QuicUdpSocketApi::WritePacket(
      QuicUdpSocketFd fd, const char *packet_buffer, size_t packet_buffer_len,
      const QuicUdpPacketInfo &packet_info)
  {
    if (!packet_info.HasValue(QuicUdpPacketInfoBit::PEER_ADDRESS))
    {
      return WriteResult(WRITE_STATUS_ERROR, EINVAL);
    }

    char control_buffer[512];
    sockaddr_storage raw_peer_address =
        packet_info.peer_address().generic_address();
    ULONG bufferlen = packet_buffer_len;
    WSABUF iov = {bufferlen, const_cast<char *>(packet_buffer)};

    WSAMSG hdr;
    hdr.name = reinterpret_cast<LPSOCKADDR>(&raw_peer_address);
    hdr.namelen = packet_info.peer_address().host().IsIPv4()
                      ? sizeof(sockaddr_in)
                      : sizeof(sockaddr_in6);
    hdr.lpBuffers = &iov;
    hdr.dwBufferCount = 1;
    hdr.dwFlags = 0;
    hdr.Control.buf = nullptr;
    hdr.Control.len = 0;

    cmsghdr *cmsg = nullptr;

    // Set self IP.
    if (packet_info.HasValue(QuicUdpPacketInfoBit::V4_SELF_IP) &&
        packet_info.self_v4_ip().IsInitialized())
    {
      if (!NextCmsg(&hdr, control_buffer, sizeof(control_buffer), IPPROTO_IP,
                    IP_PKTINFO, sizeof(in_pktinfo), &cmsg))
      {
        QUIC_LOG_FIRST_N(ERROR, 100)
            << "Not enough buffer to set self v4 ip address.";
        return WriteResult(WRITE_STATUS_ERROR, EINVAL);
      }
      SetV4SelfIpInControlMessage(packet_info.self_v4_ip(), cmsg);
    }
    else if (packet_info.HasValue(QuicUdpPacketInfoBit::V6_SELF_IP) &&
             packet_info.self_v6_ip().IsInitialized())
    {
      if (!NextCmsg(&hdr, control_buffer, sizeof(control_buffer), IPPROTO_IPV6,
                    IPV6_PKTINFO, sizeof(in6_pktinfo), &cmsg))
      {
        QUIC_LOG_FIRST_N(ERROR, 100)
            << "Not enough buffer to set self v6 ip address.";
        return WriteResult(WRITE_STATUS_ERROR, EINVAL);
      }
      SetV6SelfIpInControlMessage(packet_info.self_v6_ip(), cmsg);
    }

#if defined(QUIC_UDP_SOCKET_SUPPORT_TTL)
    // Set ttl.
    if (packet_info.HasValue(QuicUdpPacketInfoBit::TTL))
    {
      int cmsg_level =
          packet_info.peer_address().host().IsIPv4() ? IPPROTO_IP : IPPROTO_IPV6;
      int cmsg_type =
          packet_info.peer_address().host().IsIPv4() ? IP_TTL : IPV6_HOPLIMIT;
      if (!NextCmsg(&hdr, control_buffer, sizeof(control_buffer), cmsg_level,
                    cmsg_type, sizeof(int), &cmsg))
      {
        QUIC_LOG_FIRST_N(ERROR, 100) << "Not enough buffer to set ttl.";
        return WriteResult(WRITE_STATUS_ERROR, EINVAL);
      }
      *reinterpret_cast<int *>(WSA_CMSG_DATA(cmsg)) = packet_info.ttl();
    }
#endif

    int rc;
    DWORD bytessend;
    do
    {
      rc = WSASendMsg(fd, &hdr, 0, &bytessend, nullptr, nullptr);
    } while (rc == SOCKET_ERROR && WSAGetLastError() == WSAEINTR);
    if (bytessend >= 0)
    {
      return WriteResult(WRITE_STATUS_OK, bytessend);
    }
    int error = WSAGetLastError();
    return WriteResult((error == WSAEWOULDBLOCK)
                           ? WRITE_STATUS_BLOCKED
                           : WRITE_STATUS_ERROR,
                       error);
  }

} // namespace quic
