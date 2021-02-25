// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/masque/masque_server_session.h"

#include <netdb.h>

#include "absl/strings/str_cat.h"
#include "quic/core/quic_data_reader.h"
#include "quic/core/quic_udp_socket.h"
#include "quic/tools/quic_url.h"
#include "common/platform/api/quiche_text_utils.h"

namespace quic {

namespace {
// RAII wrapper for QuicUdpSocketFd.
class FdWrapper {
 public:
  // Takes ownership of |fd| and closes the file descriptor on destruction.
  explicit FdWrapper(int address_family) {
    QuicUdpSocketApi socket_api;
    fd_ =
        socket_api.Create(address_family,
                          /*receive_buffer_size =*/kDefaultSocketReceiveBuffer,
                          /*send_buffer_size =*/kDefaultSocketReceiveBuffer);
  }

  ~FdWrapper() {
    if (fd_ == kQuicInvalidSocketFd) {
      return;
    }
    QuicUdpSocketApi socket_api;
    socket_api.Destroy(fd_);
  }

  // Hands ownership of the file descriptor to the caller.
  QuicUdpSocketFd extract_fd() {
    QuicUdpSocketFd fd = fd_;
    fd_ = kQuicInvalidSocketFd;
    return fd;
  }

  // Keeps ownership of the file descriptor.
  QuicUdpSocketFd fd() { return fd_; }

  // Disallow copy and move.
  FdWrapper(const FdWrapper&) = delete;
  FdWrapper(FdWrapper&&) = delete;
  FdWrapper& operator=(const FdWrapper&) = delete;
  FdWrapper& operator=(FdWrapper&&) = delete;

 private:
  QuicUdpSocketFd fd_;
};

std::unique_ptr<QuicBackendResponse> CreateBackendErrorResponse(
    absl::string_view status,
    absl::string_view body) {
  spdy::Http2HeaderBlock response_headers;
  response_headers[":status"] = status;
  auto response = std::make_unique<QuicBackendResponse>();
  response->set_response_type(QuicBackendResponse::REGULAR_RESPONSE);
  response->set_headers(std::move(response_headers));
  response->set_body(body);
  return response;
}

}  // namespace

MasqueServerSession::MasqueServerSession(
    MasqueMode masque_mode,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    QuicSession::Visitor* visitor,
    Visitor* owner,
    QuicEpollServer* epoll_server,
    QuicCryptoServerStreamBase::Helper* helper,
    const QuicCryptoServerConfig* crypto_config,
    QuicCompressedCertsCache* compressed_certs_cache,
    MasqueServerBackend* masque_server_backend)
    : QuicSimpleServerSession(config,
                              supported_versions,
                              connection,
                              visitor,
                              helper,
                              crypto_config,
                              compressed_certs_cache,
                              masque_server_backend),
      masque_server_backend_(masque_server_backend),
      owner_(owner),
      epoll_server_(epoll_server),
      compression_engine_(this),
      masque_mode_(masque_mode) {
  masque_server_backend_->RegisterBackendClient(connection_id(), this);
}

void MasqueServerSession::OnMessageReceived(absl::string_view message) {
  QUIC_DVLOG(1) << "Received DATAGRAM frame of length " << message.length();
  if (masque_mode_ == MasqueMode::kLegacy) {
    QuicConnectionId client_connection_id, server_connection_id;
    QuicSocketAddress target_server_address;
    std::vector<char> packet;
    bool version_present;
    if (!compression_engine_.DecompressDatagram(
            message, &client_connection_id, &server_connection_id,
            &target_server_address, &packet, &version_present)) {
      return;
    }

    QUIC_DVLOG(1) << "Received packet of length " << packet.size() << " for "
                  << target_server_address << " client "
                  << client_connection_id;

    if (version_present) {
      if (client_connection_id.length() != kQuicDefaultConnectionIdLength) {
        QUIC_DLOG(ERROR)
            << "Dropping long header with invalid client_connection_id "
            << client_connection_id;
        return;
      }
      owner_->RegisterClientConnectionId(client_connection_id, this);
    }

    WriteResult write_result = connection()->writer()->WritePacket(
        packet.data(), packet.size(), connection()->self_address().host(),
        target_server_address, nullptr);
    QUIC_DVLOG(1) << "Got " << write_result << " for " << packet.size()
                  << " bytes to " << target_server_address;
    return;
  }
  QUICHE_DCHECK_EQ(masque_mode_, MasqueMode::kOpen);
  QuicDataReader reader(message);
  QuicDatagramFlowId flow_id;
  if (!reader.ReadVarInt62(&flow_id)) {
    QUIC_DLOG(ERROR) << "Failed to read flow_id";
    return;
  }

  auto it =
      absl::c_find_if(connect_udp_server_states_,
                      [flow_id](const ConnectUdpServerState& connect_udp) {
                        return connect_udp.flow_id() == flow_id;
                      });
  if (it == connect_udp_server_states_.end()) {
    QUIC_DLOG(ERROR) << "Received unknown flow_id " << flow_id;
    return;
  }
  QuicSocketAddress target_server_address = it->target_server_address();
  QUICHE_DCHECK(target_server_address.IsInitialized());
  QuicUdpSocketFd fd = it->fd();
  QUICHE_DCHECK_NE(fd, kQuicInvalidSocketFd);
  absl::string_view packet = reader.ReadRemainingPayload();
  QuicUdpSocketApi socket_api;
  QuicUdpPacketInfo packet_info;
  packet_info.SetPeerAddress(target_server_address);
  WriteResult write_result =
      socket_api.WritePacket(fd, packet.data(), packet.length(), packet_info);
  QUIC_DVLOG(1) << "Wrote packet to server with result " << write_result;
}

void MasqueServerSession::OnMessageAcked(QuicMessageId message_id,
                                         QuicTime /*receive_timestamp*/) {
  QUIC_DVLOG(1) << "Received ack for DATAGRAM frame " << message_id;
}

void MasqueServerSession::OnMessageLost(QuicMessageId message_id) {
  QUIC_DVLOG(1) << "We believe DATAGRAM frame " << message_id << " was lost";
}

void MasqueServerSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame,
    ConnectionCloseSource source) {
  QuicSimpleServerSession::OnConnectionClosed(frame, source);
  QUIC_DLOG(INFO) << "Closing connection for " << connection_id();
  masque_server_backend_->RemoveBackendClient(connection_id());
  // Clearing this state will close all sockets.
  connect_udp_server_states_.clear();
}

void MasqueServerSession::OnStreamClosed(QuicStreamId stream_id) {
  connect_udp_server_states_.remove_if(
      [stream_id](const ConnectUdpServerState& connect_udp) {
        return connect_udp.stream_id() == stream_id;
      });

  QuicSimpleServerSession::OnStreamClosed(stream_id);
}

std::unique_ptr<QuicBackendResponse> MasqueServerSession::HandleMasqueRequest(
    const std::string& masque_path,
    const spdy::Http2HeaderBlock& request_headers,
    const std::string& request_body,
    QuicSimpleServerBackend::RequestHandler* request_handler) {
  if (masque_mode_ != MasqueMode::kLegacy) {
    auto path_pair = request_headers.find(":path");
    auto scheme_pair = request_headers.find(":scheme");
    auto method_pair = request_headers.find(":method");
    auto flow_id_pair = request_headers.find("datagram-flow-id");
    auto authority_pair = request_headers.find(":authority");
    if (path_pair == request_headers.end() ||
        scheme_pair == request_headers.end() ||
        method_pair == request_headers.end() ||
        flow_id_pair == request_headers.end() ||
        authority_pair == request_headers.end()) {
      QUIC_DLOG(ERROR) << "MASQUE request is missing required headers";
      return CreateBackendErrorResponse("400", "Missing required headers");
    }
    absl::string_view path = path_pair->second;
    absl::string_view scheme = scheme_pair->second;
    absl::string_view method = method_pair->second;
    absl::string_view flow_id_str = flow_id_pair->second;
    absl::string_view authority = authority_pair->second;
    if (path.empty()) {
      QUIC_DLOG(ERROR) << "MASQUE request with empty path";
      return CreateBackendErrorResponse("400", "Empty path");
    }
    if (scheme.empty()) {
      return CreateBackendErrorResponse("400", "Empty scheme");
      return nullptr;
    }
    if (method != "CONNECT-UDP") {
      QUIC_DLOG(ERROR) << "MASQUE request with bad method \"" << method << "\"";
      return CreateBackendErrorResponse("400", "Bad method");
    }
    QuicDatagramFlowId flow_id;
    if (!absl::SimpleAtoi(flow_id_str, &flow_id)) {
      QUIC_DLOG(ERROR) << "MASQUE request with bad flow_id \"" << flow_id_str
                       << "\"";
      return CreateBackendErrorResponse("400", "Bad flow ID");
    }
    QuicUrl url(absl::StrCat("https://", authority));
    if (!url.IsValid() || url.PathParamsQuery() != "/") {
      QUIC_DLOG(ERROR) << "MASQUE request with bad authority \"" << authority
                       << "\"";
      return CreateBackendErrorResponse("400", "Bad authority");
    }

    std::string port = absl::StrCat(url.port());
    addrinfo hint = {};
    hint.ai_protocol = IPPROTO_UDP;

    addrinfo* info_list = nullptr;
    int result =
        getaddrinfo(url.host().c_str(), port.c_str(), &hint, &info_list);
    if (result != 0) {
      QUIC_DLOG(ERROR) << "Failed to resolve " << authority << ": "
                       << gai_strerror(result);
      return CreateBackendErrorResponse("500", "DNS resolution failed");
    }

    QUICHE_CHECK_NE(info_list, nullptr);
    std::unique_ptr<addrinfo, void (*)(addrinfo*)> info_list_owned(
        info_list, freeaddrinfo);
    QuicSocketAddress target_server_address(info_list->ai_addr,
                                            info_list->ai_addrlen);
    QUIC_DLOG(INFO) << "Got CONNECT_UDP request flow_id=" << flow_id
                    << " target_server_address=\"" << target_server_address
                    << "\"";

    FdWrapper fd_wrapper(target_server_address.host().AddressFamilyToInt());
    if (fd_wrapper.fd() == kQuicInvalidSocketFd) {
      QUIC_DLOG(ERROR) << "Socket creation failed";
      return CreateBackendErrorResponse("500", "Socket creation failed");
    }
    QuicSocketAddress any_v6_address(QuicIpAddress::Any6(), 0);
    QuicUdpSocketApi socket_api;
    if (!socket_api.Bind(fd_wrapper.fd(), any_v6_address)) {
      QUIC_DLOG(ERROR) << "Socket bind failed";
      return CreateBackendErrorResponse("500", "Socket bind failed");
    }
    epoll_server_->RegisterFDForRead(fd_wrapper.fd(), this);

    connect_udp_server_states_.emplace_back(ConnectUdpServerState(
        flow_id, request_handler->stream_id(), target_server_address,
        fd_wrapper.extract_fd(), epoll_server_));

    spdy::Http2HeaderBlock response_headers;
    response_headers[":status"] = "200";
    response_headers["datagram-flow-id"] = absl::StrCat(flow_id);
    auto response = std::make_unique<QuicBackendResponse>();
    response->set_response_type(QuicBackendResponse::INCOMPLETE_RESPONSE);
    response->set_headers(std::move(response_headers));
    response->set_body("");

    return response;
  }

  QUIC_DLOG(INFO) << "MasqueServerSession handling MASQUE request";

  if (masque_path == "init") {
    if (masque_initialized_) {
      QUIC_DLOG(ERROR) << "Got second MASQUE init request";
      return nullptr;
    }
    masque_initialized_ = true;
  } else if (masque_path == "unregister") {
    QuicConnectionId connection_id(request_body.data(), request_body.length());
    QUIC_DLOG(INFO) << "Received MASQUE request to unregister "
                    << connection_id;
    owner_->UnregisterClientConnectionId(connection_id);
    compression_engine_.UnregisterClientConnectionId(connection_id);
  } else {
    if (!masque_initialized_) {
      QUIC_DLOG(ERROR) << "Got MASQUE request before init";
      return nullptr;
    }
  }

  // TODO(dschinazi) implement binary protocol sent in response body.
  const std::string response_body = "";
  spdy::Http2HeaderBlock response_headers;
  response_headers[":status"] = "200";
  auto response = std::make_unique<QuicBackendResponse>();
  response->set_response_type(QuicBackendResponse::REGULAR_RESPONSE);
  response->set_headers(std::move(response_headers));
  response->set_body(response_body);

  return response;
}

void MasqueServerSession::HandlePacketFromServer(
    const ReceivedPacketInfo& packet_info) {
  QUIC_DVLOG(1) << "MasqueServerSession received " << packet_info;
  if (masque_mode_ == MasqueMode::kLegacy) {
    compression_engine_.CompressAndSendPacket(
        packet_info.packet.AsStringPiece(),
        packet_info.destination_connection_id, packet_info.source_connection_id,
        packet_info.peer_address);
    return;
  }
  QUIC_LOG(ERROR) << "Ignoring packet from server in " << masque_mode_
                  << " mode";
}

void MasqueServerSession::OnRegistration(QuicEpollServer* /*eps*/,
                                         QuicUdpSocketFd fd,
                                         int event_mask) {
  QUIC_DVLOG(1) << "OnRegistration " << fd << " event_mask " << event_mask;
}

void MasqueServerSession::OnModification(QuicUdpSocketFd fd, int event_mask) {
  QUIC_DVLOG(1) << "OnModification " << fd << " event_mask " << event_mask;
}

void MasqueServerSession::OnEvent(QuicUdpSocketFd fd, QuicEpollEvent* event) {
  if ((event->in_events & EPOLLIN) == 0) {
    QUIC_DVLOG(1) << "Ignoring OnEvent fd " << fd << " event mask "
                  << event->in_events;
    return;
  }
  auto it = absl::c_find_if(connect_udp_server_states_,
                            [fd](const ConnectUdpServerState& connect_udp) {
                              return connect_udp.fd() == fd;
                            });
  if (it == connect_udp_server_states_.end()) {
    QUIC_BUG << "Got unexpected event mask " << event->in_events
             << " on unknown fd " << fd;
    return;
  }
  QuicDatagramFlowId flow_id = it->flow_id();
  QuicSocketAddress expected_target_server_address =
      it->target_server_address();
  QUICHE_DCHECK(expected_target_server_address.IsInitialized());
  QUIC_DVLOG(1) << "Received readable event on fd " << fd << " (mask "
                << event->in_events << ") flow_id " << flow_id << " server "
                << expected_target_server_address;
  QuicUdpSocketApi socket_api;
  BitMask64 packet_info_interested(QuicUdpPacketInfoBit::PEER_ADDRESS);
  char packet_buffer[kMaxIncomingPacketSize];
  char control_buffer[kDefaultUdpPacketControlBufferSize];
  while (true) {
    QuicUdpSocketApi::ReadPacketResult read_result;
    read_result.packet_buffer = {packet_buffer, sizeof(packet_buffer)};
    read_result.control_buffer = {control_buffer, sizeof(control_buffer)};
    socket_api.ReadPacket(fd, packet_info_interested, &read_result);
    if (!read_result.ok) {
      // Most likely there is nothing left to read, break out of read loop.
      break;
    }
    if (!read_result.packet_info.HasValue(QuicUdpPacketInfoBit::PEER_ADDRESS)) {
      QUIC_BUG << "Missing peer address when reading from fd " << fd;
      continue;
    }
    if (read_result.packet_info.peer_address() !=
        expected_target_server_address) {
      QUIC_DLOG(ERROR) << "Ignoring UDP packet on fd " << fd
                       << " from unexpected server address "
                       << read_result.packet_info.peer_address()
                       << " (expected " << expected_target_server_address
                       << ")";
      continue;
    }
    if (!connection()->connected()) {
      QUIC_BUG << "Unexpected incoming UDP packet on fd " << fd << " from "
               << expected_target_server_address
               << " because MASQUE connection is closed";
      return;
    }
    // The packet is valid, send it to the client in a DATAGRAM frame.
    size_t slice_length = QuicDataWriter::GetVarInt62Len(flow_id) +
                          read_result.packet_buffer.buffer_len;
    QuicUniqueBufferPtr buffer = MakeUniqueBuffer(
        connection()->helper()->GetStreamSendBufferAllocator(), slice_length);
    QuicDataWriter writer(slice_length, buffer.get());
    if (!writer.WriteVarInt62(flow_id)) {
      QUIC_BUG << "Failed to write flow_id";
      continue;
    }
    if (!writer.WriteBytes(read_result.packet_buffer.buffer,
                           read_result.packet_buffer.buffer_len)) {
      QUIC_BUG << "Failed to write packet";
      continue;
    }
    QUICHE_DCHECK_EQ(writer.remaining(), 0u);
    QuicMemSlice slice(std::move(buffer), slice_length);
    MessageResult message_result = SendMessage(QuicMemSliceSpan(&slice));
    QUIC_DVLOG(1) << "Sent UDP packet from target server of length "
                  << read_result.packet_buffer.buffer_len << " with flow ID "
                  << flow_id << " and got message result " << message_result;
  }
}

void MasqueServerSession::OnUnregistration(QuicUdpSocketFd fd, bool replaced) {
  QUIC_DVLOG(1) << "OnUnregistration " << fd << " " << (replaced ? "" : "!")
                << " replaced";
}

void MasqueServerSession::OnShutdown(QuicEpollServer* /*eps*/,
                                     QuicUdpSocketFd fd) {
  QUIC_DVLOG(1) << "OnShutdown " << fd;
}

std::string MasqueServerSession::Name() const {
  return std::string("MasqueServerSession-") + connection_id().ToString();
}

MasqueServerSession::ConnectUdpServerState::ConnectUdpServerState(
    QuicDatagramFlowId flow_id,
    QuicStreamId stream_id,
    const QuicSocketAddress& target_server_address,
    QuicUdpSocketFd fd,
    QuicEpollServer* epoll_server)
    : flow_id_(flow_id),
      stream_id_(stream_id),
      target_server_address_(target_server_address),
      fd_(fd),
      epoll_server_(epoll_server) {
  QUICHE_DCHECK_NE(fd_, kQuicInvalidSocketFd);
  QUICHE_DCHECK_NE(epoll_server_, nullptr);
}

MasqueServerSession::ConnectUdpServerState::~ConnectUdpServerState() {
  if (fd_ == kQuicInvalidSocketFd) {
    return;
  }
  QuicUdpSocketApi socket_api;
  QUIC_DLOG(INFO) << "Closing fd " << fd_;
  epoll_server_->UnregisterFD(fd_);
  socket_api.Destroy(fd_);
}

MasqueServerSession::ConnectUdpServerState::ConnectUdpServerState(
    MasqueServerSession::ConnectUdpServerState&& other) {
  fd_ = kQuicInvalidSocketFd;
  *this = std::move(other);
}

MasqueServerSession::ConnectUdpServerState&
MasqueServerSession::ConnectUdpServerState::operator=(
    MasqueServerSession::ConnectUdpServerState&& other) {
  if (fd_ != kQuicInvalidSocketFd) {
    QuicUdpSocketApi socket_api;
    QUIC_DLOG(INFO) << "Closing fd " << fd_;
    epoll_server_->UnregisterFD(fd_);
    socket_api.Destroy(fd_);
  }
  flow_id_ = other.flow_id_;
  stream_id_ = other.stream_id_;
  target_server_address_ = other.target_server_address_;
  fd_ = other.fd_;
  epoll_server_ = other.epoll_server_;
  other.fd_ = kQuicInvalidSocketFd;
  return *this;
}

}  // namespace quic
