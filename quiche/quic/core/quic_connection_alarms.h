// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_CONNECTION_ALARMS_H_
#define QUICHE_QUIC_CORE_QUIC_CONNECTION_ALARMS_H_

#include "absl/base/nullability.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_arena_scoped_ptr.h"
#include "quiche/quic/core/quic_connection_context.h"
#include "quiche/quic/core/quic_one_block_arena.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quic {

class QUICHE_EXPORT QuicConnectionAlarmsDelegate {
 public:
  virtual ~QuicConnectionAlarmsDelegate() = default;

  virtual void OnSendAlarm() = 0;
  virtual void OnAckAlarm() = 0;
  virtual void OnRetransmissionAlarm() = 0;
  virtual void OnMtuDiscoveryAlarm() = 0;
  virtual void OnProcessUndecryptablePacketsAlarm() = 0;
  virtual void OnDiscardPreviousOneRttKeysAlarm() = 0;
  virtual void OnDiscardZeroRttDecryptionKeysAlarm() = 0;
  virtual void MaybeProbeMultiPortPath() = 0;
  virtual void OnIdleDetectorAlarm() = 0;
  virtual void OnNetworkBlackholeDetectorAlarm() = 0;
  virtual void OnPingAlarm() = 0;

  virtual QuicConnectionContext* context() = 0;
};

namespace test {
class QuicConnectionAlarmsPeer;
}

class QUICHE_EXPORT QuicConnectionAlarms {
 public:
  // Provides a QuicAlarm-like interface to an alarm contained within
  // QuicConnectionAlarms.
  class AlarmProxy {
   public:
    explicit AlarmProxy(absl::Nonnull<QuicAlarm*> alarm) : alarm_(alarm) {}

    bool IsSet() const { return alarm_->IsSet(); }
    QuicTime deadline() const { return alarm_->deadline(); }
    bool IsPermanentlyCancelled() const {
      return alarm_->IsPermanentlyCancelled();
    }

    void Set(QuicTime new_deadline) { alarm_->Set(new_deadline); }
    void Update(QuicTime new_deadline, QuicTime::Delta granularity) {
      alarm_->Update(new_deadline, granularity);
    }
    void Cancel() { alarm_->Cancel(); }
    void PermanentCancel() { alarm_->PermanentCancel(); }

   private:
    friend class ::quic::test::QuicConnectionAlarmsPeer;

    absl::Nonnull<QuicAlarm*> alarm_;
  };
  class ConstAlarmProxy {
   public:
    explicit ConstAlarmProxy(const QuicAlarm* alarm) : alarm_(alarm) {}

    bool IsSet() const { return alarm_->IsSet(); }
    QuicTime deadline() const { return alarm_->deadline(); }
    bool IsPermanentlyCancelled() const {
      return alarm_->IsPermanentlyCancelled();
    }

   private:
    friend class ::quic::test::QuicConnectionAlarmsPeer;

    const QuicAlarm* alarm_;
  };

  QuicConnectionAlarms(QuicConnectionAlarmsDelegate* delegate,
                       QuicAlarmFactory& alarm_factory,
                       QuicConnectionArena& arena);

  AlarmProxy ack_alarm() { return AlarmProxy(ack_alarm_.get()); }
  AlarmProxy retransmission_alarm() {
    return AlarmProxy(retransmission_alarm_.get());
  }
  AlarmProxy send_alarm() { return AlarmProxy(send_alarm_.get()); }
  AlarmProxy mtu_discovery_alarm() {
    return AlarmProxy(mtu_discovery_alarm_.get());
  }
  AlarmProxy process_undecryptable_packets_alarm() {
    return AlarmProxy(process_undecryptable_packets_alarm_.get());
  }
  AlarmProxy discard_previous_one_rtt_keys_alarm() {
    return AlarmProxy(discard_previous_one_rtt_keys_alarm_.get());
  }
  AlarmProxy discard_zero_rtt_decryption_keys_alarm() {
    return AlarmProxy(discard_zero_rtt_decryption_keys_alarm_.get());
  }
  AlarmProxy multi_port_probing_alarm() {
    return AlarmProxy(multi_port_probing_alarm_.get());
  }
  AlarmProxy idle_network_detector_alarm() {
    return AlarmProxy(idle_network_detector_alarm_.get());
  }
  AlarmProxy network_blackhole_detector_alarm() {
    return AlarmProxy(network_blackhole_detector_alarm_.get());
  }
  AlarmProxy ping_alarm() { return AlarmProxy(ping_alarm_.get()); }

  ConstAlarmProxy ack_alarm() const {
    return ConstAlarmProxy(ack_alarm_.get());
  }
  ConstAlarmProxy retransmission_alarm() const {
    return ConstAlarmProxy(retransmission_alarm_.get());
  }
  ConstAlarmProxy send_alarm() const {
    return ConstAlarmProxy(send_alarm_.get());
  }
  ConstAlarmProxy mtu_discovery_alarm() const {
    return ConstAlarmProxy(mtu_discovery_alarm_.get());
  }
  ConstAlarmProxy process_undecryptable_packets_alarm() const {
    return ConstAlarmProxy(process_undecryptable_packets_alarm_.get());
  }
  ConstAlarmProxy discard_previous_one_rtt_keys_alarm() const {
    return ConstAlarmProxy(discard_previous_one_rtt_keys_alarm_.get());
  }
  ConstAlarmProxy discard_zero_rtt_decryption_keys_alarm() const {
    return ConstAlarmProxy(discard_zero_rtt_decryption_keys_alarm_.get());
  }
  ConstAlarmProxy multi_port_probing_alarm() const {
    return ConstAlarmProxy(multi_port_probing_alarm_.get());
  }
  ConstAlarmProxy idle_network_detector_alarm() const {
    return ConstAlarmProxy(idle_network_detector_alarm_.get());
  }
  ConstAlarmProxy network_blackhole_detector_alarm() const {
    return ConstAlarmProxy(network_blackhole_detector_alarm_.get());
  }
  ConstAlarmProxy ping_alarm() const {
    return ConstAlarmProxy(ping_alarm_.get());
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
  // An alarm for QuicIdleNetworkDetector.
  QuicArenaScopedPtr<QuicAlarm> idle_network_detector_alarm_;
  // An alarm for QuicNetworkBlackholeDetection.
  QuicArenaScopedPtr<QuicAlarm> network_blackhole_detector_alarm_;
  // An alarm for QuicPingManager.
  QuicArenaScopedPtr<QuicAlarm> ping_alarm_;
};

using QuicAlarmProxy = QuicConnectionAlarms::AlarmProxy;
using QuicConstAlarmProxy = QuicConnectionAlarms::ConstAlarmProxy;

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_CONNECTION_ALARMS_H_
