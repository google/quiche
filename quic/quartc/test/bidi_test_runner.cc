// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/quartc/test/bidi_test_runner.h"

#include "net/third_party/quiche/src/quic/quartc/test/quartc_peer.h"

namespace quic {
namespace test {

namespace {

bool ContainsSequenceNumbers(const std::vector<ReceivedMessage>& messages,
                             IdToSequenceNumberMap id_to_sequence_number) {
  for (const auto& message : messages) {
    auto it = id_to_sequence_number.find(message.frame.source_id);
    if (it != id_to_sequence_number.end() &&
        it->second == message.frame.sequence_number) {
      id_to_sequence_number.erase(it);
    }
  }
  return id_to_sequence_number.empty();
}

void LogResults(const std::vector<ReceivedMessage>& messages) {
  QuicTime::Delta max_delay = QuicTime::Delta::Zero();
  QuicTime::Delta total_delay = QuicTime::Delta::Zero();
  QuicByteCount total_throughput = 0;
  for (const auto& message : messages) {
    QuicTime::Delta one_way_delay =
        message.receive_time - message.frame.send_time;
    QUIC_VLOG(1) << "Frame details: source_id=" << message.frame.source_id
                 << ", sequence_number=" << message.frame.sequence_number
                 << ", one_way_delay (ms)=" << one_way_delay.ToMilliseconds();
    max_delay = std::max(max_delay, one_way_delay);
    total_delay = total_delay + one_way_delay;
    total_throughput += message.frame.size;
  }
  QuicBandwidth total_bandwidth = QuicBandwidth::FromBytesAndTimeDelta(
      total_throughput,
      messages.back().receive_time - messages.front().receive_time);
  QUIC_LOG(INFO) << "Summary:\n  max_delay (ms)=" << max_delay.ToMilliseconds()
                 << "\n  average_delay (ms)="
                 << total_delay.ToMilliseconds() / messages.size()
                 << "\n  total_throughput (bytes)=" << total_throughput
                 << "\n  total_bandwidth (bps)="
                 << total_bandwidth.ToBitsPerSecond();
}

}  // namespace

BidiTestRunner::BidiTestRunner(simulator::Simulator* simulator,
                               QuartcPacketTransport* client_transport,
                               QuartcPacketTransport* server_transport)
    : simulator_(simulator),
      client_transport_(client_transport),
      server_transport_(server_transport) {
  // Set up default data source configs.
  // Emulates an audio source with a 20 ms ptime.
  QuartcDataSource::Config audio;
  audio.id = 1;
  audio.frame_interval = QuicTime::Delta::FromMilliseconds(20);
  audio.min_bandwidth = QuicBandwidth::FromKBitsPerSecond(8);
  audio.max_bandwidth = QuicBandwidth::FromKBitsPerSecond(64);

  // Emulates a video source at 30 fps.
  QuartcDataSource::Config video;
  video.id = 2;
  video.frame_interval = QuicTime::Delta::FromMicroseconds(33333);
  video.min_bandwidth = QuicBandwidth::FromKBitsPerSecond(25);
  video.max_bandwidth = QuicBandwidth::FromKBitsPerSecond(5000);

  // Note: by placing audio first, it takes priority in bandwidth allocations.
  client_configs_.push_back(audio);
  client_configs_.push_back(video);
  server_configs_.push_back(audio);
  server_configs_.push_back(video);
}

BidiTestRunner::~BidiTestRunner() {
  // Note that peers must be deleted before endpoints.  Peers close the
  // connection when deleted.
  client_peer_.reset();
  server_peer_.reset();
}

bool BidiTestRunner::RunTest(QuicTime::Delta test_duration) {
  client_peer_ = QuicMakeUnique<QuartcPeer>(
      simulator_->GetClock(), simulator_->GetAlarmFactory(),
      simulator_->GetRandomGenerator(), client_configs_);
  server_peer_ = QuicMakeUnique<QuartcPeer>(
      simulator_->GetClock(), simulator_->GetAlarmFactory(),
      simulator_->GetRandomGenerator(), server_configs_);

  QuartcEndpoint::Delegate* server_delegate = server_peer_.get();
  if (server_interceptor_) {
    server_interceptor_->SetDelegate(server_delegate);
    server_delegate = server_interceptor_;
  }
  server_endpoint_ = QuicMakeUnique<QuartcServerEndpoint>(
      simulator_->GetAlarmFactory(), simulator_->GetClock(), server_delegate,
      QuartcSessionConfig());

  QuartcEndpoint::Delegate* client_delegate = client_peer_.get();
  if (client_interceptor_) {
    client_interceptor_->SetDelegate(client_delegate);
    client_delegate = client_interceptor_;
  }
  client_endpoint_ = QuicMakeUnique<QuartcClientEndpoint>(
      simulator_->GetAlarmFactory(), simulator_->GetClock(), client_delegate,
      QuartcSessionConfig(), server_endpoint_->server_crypto_config());

  QuicTime start_time = simulator_->GetClock()->Now();
  server_endpoint_->Connect(server_transport_);
  client_endpoint_->Connect(client_transport_);

  // Measure connect latency.
  if (!simulator_->RunUntil([this] { return client_peer_->Enabled(); })) {
    return false;
  }
  QuicTime client_connected = simulator_->GetClock()->Now();
  QuicTime::Delta client_connect_latency = client_connected - start_time;

  if (!simulator_->RunUntil([this] { return server_peer_->Enabled(); })) {
    return false;
  }
  QuicTime server_connected = simulator_->GetClock()->Now();
  QuicTime::Delta server_connect_latency = server_connected - start_time;

  QUIC_LOG(INFO) << "Connect latencies (ms): client=" << client_connect_latency
                 << ", server=" << server_connect_latency;

  // Run the test.
  simulator_->RunFor(test_duration);

  // Disable sending and drain.
  // Note that draining by waiting for the last sequence number sent may be
  // flaky if packet loss is enabled.  However, simulator-based tests don't
  // currently have any loss.
  server_peer_->SetEnabled(false);
  client_peer_->SetEnabled(false);

  IdToSequenceNumberMap sent_by_server = server_peer_->GetLastSequenceNumbers();
  if (!simulator_->RunUntil([this, &sent_by_server] {
        return ContainsSequenceNumbers(client_peer_->received_messages(),
                                       sent_by_server);
      })) {
    return false;
  }

  IdToSequenceNumberMap sent_by_client = client_peer_->GetLastSequenceNumbers();
  if (!simulator_->RunUntil([this, &sent_by_client] {
        return ContainsSequenceNumbers(server_peer_->received_messages(),
                                       sent_by_client);
      })) {
    return false;
  }

  // Compute results.
  QUIC_LOG(INFO) << "Printing client->server results:";
  LogResults(server_peer_->received_messages());

  QUIC_LOG(INFO) << "Printing server->client results:";
  LogResults(client_peer_->received_messages());
  return true;
}

}  // namespace test
}  // namespace quic
