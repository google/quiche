// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// QuicPeerIssuedConnectionIdManager handles the states associated with receving
// and retiring peer issued connection Ids.
// TODO(haoyuewang) Implements QuicSelfIssuedConnectionIdManager.
// QuicConnectionIdManager handles the states associated with connection Ids
// issued by the current end point.

#ifndef QUICHE_QUIC_CORE_QUIC_CONNECTION_ID_MANAGER_H_
#define QUICHE_QUIC_CORE_QUIC_CONNECTION_ID_MANAGER_H_

#include <memory>
#include "quic/core/frames/quic_new_connection_id_frame.h"
#include "quic/core/quic_alarm.h"
#include "quic/core/quic_alarm_factory.h"
#include "quic/core/quic_connection_id.h"
#include "quic/core/quic_interval_set.h"
#include "quic/platform/api/quic_uint128.h"
#include "net/quic/platform/impl/quic_export_impl.h"

namespace quic {

struct QUIC_EXPORT_PRIVATE QuicConnectionIdData {
  QuicConnectionIdData(const QuicConnectionId& connection_id,
                       uint64_t sequence_number,
                       QuicUint128 stateless_reset_token);

  QuicConnectionId connection_id;
  uint64_t sequence_number;
  QuicUint128 stateless_reset_token;
};

// Used by QuicSelfIssuedConnectionIdManager
// and QuicPeerIssuedConnectionIdManager.
class QUIC_EXPORT_PRIVATE QuicConnectionIdManagerVisitorInterface {
 public:
  virtual ~QuicConnectionIdManagerVisitorInterface() = default;
  virtual void OnPeerIssuedConnectionIdRetired() = 0;
};

class QUIC_EXPORT_PRIVATE QuicPeerIssuedConnectionIdManager {
 public:
  // QuicPeerIssuedConnectionIdManager should be instantiated only when a peer
  // issued-non empty connection ID is received.
  QuicPeerIssuedConnectionIdManager(
      size_t active_connection_id_limit,
      const QuicConnectionId& initial_peer_issued_connection_id,
      const QuicClock* clock,
      QuicAlarmFactory* alarm_factory,
      QuicConnectionIdManagerVisitorInterface* visitor);

  ~QuicPeerIssuedConnectionIdManager();

  QuicErrorCode OnNewConnectionIdFrame(const QuicNewConnectionIdFrame& frame,
                                       std::string* error_detail);

  // Returns the data associated with an unused connection Id. After the call,
  // the Id is marked as used. Returns nullptr if there is no unused connection
  // Id.
  const QuicConnectionIdData* ConsumeOneUnusedConnectionId();

  // Add the connection Id to the pending retirement connection Id list.
  void PrepareToRetireActiveConnectionId(const QuicConnectionId& cid);

  bool IsConnectionIdActive(const QuicConnectionId& cid) const;

  // Get the sequence numbers of all the connection Ids pending retirement when
  // it is safe to retires these Ids.
  std::vector<uint64_t> ConsumeToBeRetiredConnectionIdSequenceNumbers();

 private:
  friend class QuicConnectionIdManagerPeer;

  bool IsConnectionIdNew(const QuicNewConnectionIdFrame& frame);

  void PrepareToRetireConnectionIdPriorTo(
      uint64_t retire_prior_to,
      std::vector<QuicConnectionIdData>* cid_data_vector);

  size_t active_connection_id_limit_;
  const QuicClock* clock_;
  std::unique_ptr<QuicAlarm> retire_connection_id_alarm_;
  std::vector<QuicConnectionIdData> active_connection_id_data_;
  std::vector<QuicConnectionIdData> unused_connection_id_data_;
  std::vector<QuicConnectionIdData> to_be_retired_connection_id_data_;
  // Track sequence numbers of recent NEW_CONNECTION_ID frames received from
  // the peer.
  QuicIntervalSet<uint64_t> recent_new_connection_id_sequence_numbers_;
  uint64_t max_new_connection_id_frame_retire_prior_to_ = 0u;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_CONNECTION_ID_MANAGER_H_
