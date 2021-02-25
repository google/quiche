// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/masque/masque_client_session.h"
#include "absl/algorithm/container.h"
#include "quic/core/quic_data_reader.h"
#include "common/platform/api/quiche_text_utils.h"

namespace quic {

MasqueClientSession::MasqueClientSession(
    MasqueMode masque_mode,
    const QuicConfig& config,
    const ParsedQuicVersionVector& supported_versions,
    QuicConnection* connection,
    const QuicServerId& server_id,
    QuicCryptoClientConfig* crypto_config,
    QuicClientPushPromiseIndex* push_promise_index,
    Owner* owner)
    : QuicSpdyClientSession(config,
                            supported_versions,
                            connection,
                            server_id,
                            crypto_config,
                            push_promise_index),
      masque_mode_(masque_mode),
      owner_(owner),
      compression_engine_(this) {}

void MasqueClientSession::OnMessageReceived(absl::string_view message) {
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

    auto connection_id_registration =
        client_connection_id_registrations_.find(client_connection_id);
    if (connection_id_registration ==
        client_connection_id_registrations_.end()) {
      QUIC_DLOG(ERROR) << "MasqueClientSession failed to dispatch "
                       << client_connection_id;
      return;
    }
    EncapsulatedClientSession* encapsulated_client_session =
        connection_id_registration->second;
    encapsulated_client_session->ProcessPacket(
        absl::string_view(packet.data(), packet.size()), target_server_address);

    QUIC_DVLOG(1) << "Sent " << packet.size() << " bytes to connection for "
                  << client_connection_id;
    return;
  }
  QuicDataReader reader(message);
  QuicDatagramFlowId flow_id;
  if (!reader.ReadVarInt62(&flow_id)) {
    QUIC_DLOG(ERROR) << "Failed to parse flow_id";
    return;
  }
  auto it =
      absl::c_find_if(connect_udp_client_states_,
                      [flow_id](const ConnectUdpClientState& connect_udp) {
                        return connect_udp.flow_id() == flow_id;
                      });
  if (it == connect_udp_client_states_.end()) {
    QUIC_DLOG(ERROR) << "Received unknown flow_id " << flow_id;
    return;
  }
  EncapsulatedClientSession* encapsulated_client_session =
      it->encapsulated_client_session();
  QuicSocketAddress target_server_address = it->target_server_address();
  QUICHE_DCHECK_NE(encapsulated_client_session, nullptr);
  QUICHE_DCHECK(target_server_address.IsInitialized());
  absl::string_view packet = reader.ReadRemainingPayload();
  encapsulated_client_session->ProcessPacket(packet, target_server_address);

  QUIC_DVLOG(1) << "Sent " << packet.size()
                << " bytes to connection for flow_id " << flow_id;
}

void MasqueClientSession::OnMessageAcked(QuicMessageId message_id,
                                         QuicTime /*receive_timestamp*/) {
  QUIC_DVLOG(1) << "Received ack for DATAGRAM frame " << message_id;
}

void MasqueClientSession::OnMessageLost(QuicMessageId message_id) {
  QUIC_DVLOG(1) << "We believe DATAGRAM frame " << message_id << " was lost";
}

const MasqueClientSession::ConnectUdpClientState*
MasqueClientSession::GetOrCreateConnectUdpClientState(
    const QuicSocketAddress& target_server_address,
    EncapsulatedClientSession* encapsulated_client_session) {
  for (const ConnectUdpClientState& client_state : connect_udp_client_states_) {
    if (client_state.target_server_address() == target_server_address &&
        client_state.encapsulated_client_session() ==
            encapsulated_client_session) {
      // Found existing CONNECT-UDP request.
      return &client_state;
    }
  }
  // No CONNECT-UDP request found, create a new one.
  QuicSpdyClientStream* stream = CreateOutgoingBidirectionalStream();
  if (stream == nullptr) {
    // Stream flow control limits prevented us from opening a new stream.
    QUIC_DLOG(ERROR) << "Failed to open CONNECT-UDP stream";
    return nullptr;
  }

  QuicDatagramFlowId flow_id = GetNextDatagramFlowId();

  // Send the request.
  spdy::Http2HeaderBlock headers;
  headers[":method"] = "CONNECT-UDP";
  headers[":scheme"] = "masque";
  headers[":path"] = "/";
  headers[":authority"] = target_server_address.ToString();
  headers["datagram-flow-id"] = absl::StrCat(flow_id);
  size_t bytes_sent =
      stream->SendRequest(std::move(headers), /*body=*/"", /*fin=*/false);
  if (bytes_sent == 0) {
    QUIC_DLOG(ERROR) << "Failed to send CONNECT-UDP request";
    return nullptr;
  }

  connect_udp_client_states_.push_back(ConnectUdpClientState(
      stream, encapsulated_client_session, flow_id, target_server_address));
  return &connect_udp_client_states_.back();
}

void MasqueClientSession::SendPacket(
    QuicConnectionId client_connection_id,
    QuicConnectionId server_connection_id,
    absl::string_view packet,
    const QuicSocketAddress& target_server_address,
    EncapsulatedClientSession* encapsulated_client_session) {
  if (masque_mode_ == MasqueMode::kLegacy) {
    compression_engine_.CompressAndSendPacket(packet, client_connection_id,
                                              server_connection_id,
                                              target_server_address);
    return;
  }
  const ConnectUdpClientState* connect_udp = GetOrCreateConnectUdpClientState(
      target_server_address, encapsulated_client_session);
  if (connect_udp == nullptr) {
    QUIC_DLOG(ERROR) << "Failed to create CONNECT-UDP request";
    return;
  }

  QuicDatagramFlowId flow_id = connect_udp->flow_id();
  size_t slice_length =
      QuicDataWriter::GetVarInt62Len(flow_id) + packet.length();
  QuicUniqueBufferPtr buffer = MakeUniqueBuffer(
      connection()->helper()->GetStreamSendBufferAllocator(), slice_length);
  QuicDataWriter writer(slice_length, buffer.get());
  if (!writer.WriteVarInt62(flow_id)) {
    QUIC_BUG << "Failed to write flow_id";
    return;
  }
  if (!writer.WriteBytes(packet.data(), packet.length())) {
    QUIC_BUG << "Failed to write packet";
    return;
  }

  QuicMemSlice slice(std::move(buffer), slice_length);
  MessageResult message_result = SendMessage(QuicMemSliceSpan(&slice));

  QUIC_DVLOG(1) << "Sent packet to " << target_server_address
                << " compressed with flow ID " << flow_id
                << " and got message result " << message_result;
}

void MasqueClientSession::RegisterConnectionId(
    QuicConnectionId client_connection_id,
    EncapsulatedClientSession* encapsulated_client_session) {
  QUIC_DLOG(INFO) << "Registering " << client_connection_id
                  << " to encapsulated client";
  QUICHE_DCHECK(
      client_connection_id_registrations_.find(client_connection_id) ==
          client_connection_id_registrations_.end() ||
      client_connection_id_registrations_[client_connection_id] ==
          encapsulated_client_session);
  client_connection_id_registrations_[client_connection_id] =
      encapsulated_client_session;
}

void MasqueClientSession::UnregisterConnectionId(
    QuicConnectionId client_connection_id,
    EncapsulatedClientSession* encapsulated_client_session) {
  QUIC_DLOG(INFO) << "Unregistering " << client_connection_id;
  if (masque_mode_ == MasqueMode::kLegacy) {
    if (client_connection_id_registrations_.find(client_connection_id) !=
        client_connection_id_registrations_.end()) {
      client_connection_id_registrations_.erase(client_connection_id);
      owner_->UnregisterClientConnectionId(client_connection_id);
      compression_engine_.UnregisterClientConnectionId(client_connection_id);
    }
    return;
  }

  for (auto it = connect_udp_client_states_.begin();
       it != connect_udp_client_states_.end();) {
    if (it->encapsulated_client_session() == encapsulated_client_session) {
      QUIC_DLOG(INFO) << "Removing state for flow_id " << it->flow_id();
      auto* stream = it->stream();
      it = connect_udp_client_states_.erase(it);
      if (!stream->write_side_closed()) {
        stream->Reset(QUIC_STREAM_CANCELLED);
      }
    } else {
      ++it;
    }
  }
}

void MasqueClientSession::OnConnectionClosed(
    const QuicConnectionCloseFrame& frame,
    ConnectionCloseSource source) {
  QuicSpdyClientSession::OnConnectionClosed(frame, source);
  // Close all encapsulated sessions.
  for (auto client_state : connect_udp_client_states_) {
    client_state.encapsulated_client_session()->CloseConnection(
        QUIC_CONNECTION_CANCELLED, "Underlying MASQUE connection was closed",
        ConnectionCloseBehavior::SILENT_CLOSE);
  }
}

void MasqueClientSession::OnStreamClosed(QuicStreamId stream_id) {
  for (auto it = connect_udp_client_states_.begin();
       it != connect_udp_client_states_.end();) {
    if (it->stream()->id() == stream_id) {
      QUIC_DLOG(INFO) << "Stream " << stream_id
                      << " was closed, removing state for flow_id "
                      << it->flow_id();
      auto* encapsulated_client_session = it->encapsulated_client_session();
      it = connect_udp_client_states_.erase(it);
      encapsulated_client_session->CloseConnection(
          QUIC_CONNECTION_CANCELLED,
          "Underlying MASQUE CONNECT-UDP stream was closed",
          ConnectionCloseBehavior::SILENT_CLOSE);
    } else {
      ++it;
    }
  }

  QuicSpdyClientSession::OnStreamClosed(stream_id);
}

}  // namespace quic
