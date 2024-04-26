// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_CONNECTION_ALARMS_H_
#define QUICHE_QUIC_CORE_QUIC_CONNECTION_ALARMS_H_

#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_arena_scoped_ptr.h"
#include "quiche/quic/core/quic_one_block_arena.h"

namespace quic {

class QuicConnection;

class QUICHE_EXPORT QuicConnectionAlarms {
 public:
  QuicConnectionAlarms(QuicConnection* connection,
                       QuicAlarmFactory& alarm_factory,
                       QuicConnectionArena& arena);

  QuicAlarm& ack_alarm() { return *ack_alarm_; }
  QuicAlarm& retransmission_alarm() { return *retransmission_alarm_; }
  QuicAlarm& send_alarm() { return *send_alarm_; }
  QuicAlarm& mtu_discovery_alarm() { return *mtu_discovery_alarm_; }
  QuicAlarm& process_undecryptable_packets_alarm() {
    return *process_undecryptable_packets_alarm_;
  }
  QuicAlarm& discard_previous_one_rtt_keys_alarm() {
    return *discard_previous_one_rtt_keys_alarm_;
  }
  QuicAlarm& discard_zero_rtt_decryption_keys_alarm() {
    return *discard_zero_rtt_decryption_keys_alarm_;
  }
  QuicAlarm& multi_port_probing_alarm() { return *multi_port_probing_alarm_; }

  const QuicAlarm& ack_alarm() const { return *ack_alarm_; }
  const QuicAlarm& retransmission_alarm() const {
    return *retransmission_alarm_;
  }
  const QuicAlarm& send_alarm() const { return *send_alarm_; }
  const QuicAlarm& mtu_discovery_alarm() const { return *mtu_discovery_alarm_; }
  const QuicAlarm& process_undecryptable_packets_alarm() const {
    return *process_undecryptable_packets_alarm_;
  }
  const QuicAlarm& discard_previous_one_rtt_keys_alarm() const {
    return *discard_previous_one_rtt_keys_alarm_;
  }
  const QuicAlarm& discard_zero_rtt_decryption_keys_alarm() const {
    return *discard_zero_rtt_decryption_keys_alarm_;
  }
  const QuicAlarm& multi_port_probing_alarm() const {
    return *multi_port_probing_alarm_;
  }

 private:
  // An alarm that fires when an ACK should be sent to the peer.
  QuicArenaScopedPtr<QuicAlarm> ack_alarm_;
  // An alarm that fires when a packet needs to be retransmitted.
  QuicArenaScopedPtr<QuicAlarm> retransmission_alarm_;
  // An alarm that is scheduled when the SentPacketManager requires a delay
  // before sending packets and fires when the packet may be sent.
  QuicArenaScopedPtr<QuicAlarm> send_alarm_;
  // An alarm that fires when an MTU probe should be sent.
  QuicArenaScopedPtr<QuicAlarm> mtu_discovery_alarm_;
  // An alarm that fires to process undecryptable packets when new decryption
  // keys are available.
  QuicArenaScopedPtr<QuicAlarm> process_undecryptable_packets_alarm_;
  // An alarm that fires to discard keys for the previous key phase some time
  // after a key update has completed.
  QuicArenaScopedPtr<QuicAlarm> discard_previous_one_rtt_keys_alarm_;
  // An alarm that fires to discard 0-RTT decryption keys some time after the
  // first 1-RTT packet has been decrypted. Only used on server connections with
  // TLS handshaker.
  QuicArenaScopedPtr<QuicAlarm> discard_zero_rtt_decryption_keys_alarm_;
  // An alarm that fires to keep probing the multi-port path.
  QuicArenaScopedPtr<QuicAlarm> multi_port_probing_alarm_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_CONNECTION_ALARMS_H_