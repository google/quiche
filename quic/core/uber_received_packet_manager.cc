// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/uber_received_packet_manager.h"

namespace quic {

UberReceivedPacketManager::UberReceivedPacketManager(QuicConnectionStats* stats)
    : received_packet_manager_(stats) {}

UberReceivedPacketManager::~UberReceivedPacketManager() {}

void UberReceivedPacketManager::SetFromConfig(const QuicConfig& config,
                                              Perspective perspective) {
  received_packet_manager_.SetFromConfig(config, perspective);
}

bool UberReceivedPacketManager::IsAwaitingPacket(
    QuicPacketNumber packet_number) const {
  return received_packet_manager_.IsAwaitingPacket(packet_number);
}

const QuicFrame UberReceivedPacketManager::GetUpdatedAckFrame(
    QuicTime approximate_now) {
  return received_packet_manager_.GetUpdatedAckFrame(approximate_now);
}

void UberReceivedPacketManager::RecordPacketReceived(
    const QuicPacketHeader& header,
    QuicTime receipt_time) {
  received_packet_manager_.RecordPacketReceived(header, receipt_time);
}

void UberReceivedPacketManager::DontWaitForPacketsBefore(
    QuicPacketNumber least_unacked) {
  received_packet_manager_.DontWaitForPacketsBefore(least_unacked);
}

void UberReceivedPacketManager::MaybeUpdateAckTimeout(
    bool should_last_packet_instigate_acks,
    QuicPacketNumber last_received_packet_number,
    QuicTime time_of_last_received_packet,
    QuicTime now,
    const RttStats* rtt_stats,
    QuicTime::Delta delayed_ack_time) {
  received_packet_manager_.MaybeUpdateAckTimeout(
      should_last_packet_instigate_acks, last_received_packet_number,
      time_of_last_received_packet, now, rtt_stats, delayed_ack_time);
}

void UberReceivedPacketManager::ResetAckStates() {
  received_packet_manager_.ResetAckStates();
}

bool UberReceivedPacketManager::AckFrameUpdated() const {
  return received_packet_manager_.ack_frame_updated();
}

QuicPacketNumber UberReceivedPacketManager::GetLargestObserved() const {
  return received_packet_manager_.GetLargestObserved();
}

QuicTime UberReceivedPacketManager::GetAckTimeout() const {
  return received_packet_manager_.ack_timeout();
}

QuicPacketNumber UberReceivedPacketManager::PeerFirstSendingPacketNumber()
    const {
  return received_packet_manager_.PeerFirstSendingPacketNumber();
}

QuicPacketNumber UberReceivedPacketManager::peer_least_packet_awaiting_ack()
    const {
  return received_packet_manager_.peer_least_packet_awaiting_ack();
}

size_t UberReceivedPacketManager::min_received_before_ack_decimation() const {
  return received_packet_manager_.min_received_before_ack_decimation();
}

void UberReceivedPacketManager::set_min_received_before_ack_decimation(
    size_t new_value) {
  received_packet_manager_.set_min_received_before_ack_decimation(new_value);
}

size_t UberReceivedPacketManager::ack_frequency_before_ack_decimation() const {
  return received_packet_manager_.ack_frequency_before_ack_decimation();
}

void UberReceivedPacketManager::set_ack_frequency_before_ack_decimation(
    size_t new_value) {
  received_packet_manager_.set_ack_frequency_before_ack_decimation(new_value);
}

const QuicAckFrame& UberReceivedPacketManager::ack_frame() const {
  return received_packet_manager_.ack_frame();
}

void UberReceivedPacketManager::set_max_ack_ranges(size_t max_ack_ranges) {
  received_packet_manager_.set_max_ack_ranges(max_ack_ranges);
}

void UberReceivedPacketManager::set_save_timestamps(bool save_timestamps) {
  received_packet_manager_.set_save_timestamps(save_timestamps);
}

}  // namespace quic
