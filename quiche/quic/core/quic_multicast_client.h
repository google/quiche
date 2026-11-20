// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_MULTICAST_CLIENT_H_
#define QUICHE_QUIC_CORE_QUIC_MULTICAST_CLIENT_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_multicast_channel.h"
#include "quiche/quic/core/quic_multicast_control.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quic {

class QuicDataReader;
class QuicSession;

// Client side of draft-jholland-quic-multicast-08 on one QUIC connection.
// Owned by its QuicSession; every method runs on the session's thread.
// The interface is frozen by lane cr-net (INTERFACES.md, I3).
// Amendment A17 (P8) only adds JoinResult, Delegate::JoinChannelWithResult,
// the two-argument constructor, CompleteJoin and OnChannelLost.
class QUICHE_EXPORT QuicMulticastClient {
 public:
  using JoinResult = QuicMulticastControl::JoinResult;

  // Implemented by the embedder (Chromium //net), which owns the sockets.
  class QUICHE_EXPORT Delegate {
   public:
    // A17: also here, so an embedder's override can name it unqualified.
    using JoinResult = QuicMulticastControl::JoinResult;

    virtual ~Delegate() = default;
    // Opens one source-specific multicast socket for (|source|, |group|,
    // |port|) and binds it to |channel_id|. Called re-entrantly from inside
    // packet processing: must be synchronous and must not destroy the
    // session. Returns false on refusal or socket error.
    virtual bool JoinChannel(absl::string_view channel_id,
                             const QuicIpAddress& source,
                             const QuicIpAddress& group, uint16_t port) = 0;
    // Closes the socket for |channel_id|. Same rules as JoinChannel.
    virtual void LeaveChannel(absl::string_view channel_id) = 0;
    // A17. The answer to a JOIN, under JoinChannel()'s rules. The default
    // keeps JoinChannel()'s meaning: true is kJoined, false kFailed. An
    // embedder that answers kPending calls CompleteJoin() later; one that
    // overrides this is never asked JoinChannel().
    virtual JoinResult JoinChannelWithResult(absl::string_view channel_id,
                                             const QuicIpAddress& source,
                                             const QuicIpAddress& group,
                                             uint16_t port) {
      return JoinChannel(channel_id, source, group, port) ? JoinResult::kJoined
                                                          : JoinResult::kFailed;
    }
  };

  // A17: every source goes to |delegate|, the trust boundary (P8).
  QuicMulticastClient(QuicSession* session, Delegate* delegate);
  // |allowed_sources| is the lab trust boundary: a JOIN for a channel whose
  // source is not in it is declined without calling |delegate|.
  QuicMulticastClient(QuicSession* session, Delegate* delegate,
                      std::vector<QuicIpAddress> allowed_sources);
  QuicMulticastClient(const QuicMulticastClient&) = delete;
  QuicMulticastClient& operator=(const QuicMulticastClient&) = delete;
  // Runs inside ~QuicSession: must not call |session_| or |delegate_|.
  virtual ~QuicMulticastClient();

  // A multicast frame received on the unicast connection
  // (QuicFramerVisitorInterface::OnMulticastFrame contract).
  QuicMulticastFrameStatus OnMulticastFrame(uint64_t frame_type,
                                            QuicDataReader* reader);

  // The extended CONNECT response carried `wt-multicast: ?1`. Until this is
  // called the client sends nothing and defers any JOIN.
  void OnMulticastAccepted();

  // One datagram received on the socket opened for |channel_id|, with the
  // ECN codepoint it carried. Called from a socket read callback, outside
  // QuicConnection::ProcessUdpPacket.
  void OnChannelPacket(absl::string_view channel_id, absl::string_view packet,
                       QuicEcnCodepoint ecn, QuicTime receipt_time);

  // Counters of the channel joined as |channel_id|, or nullptr while it is not
  // joined. Read-only; for //net's NetLog (C8) and the live interop tool.
  const QuicMulticastChannel::Stats* channel_stats(
      absl::string_view channel_id) const;

  // A17. Completes a JOIN answered kPending; kPending is not a valid |result|.
  // Ignored unless |channel_id| is still pending (a LEAVE or RETIRE that
  // came first cancelled it). Never from inside a Delegate call.
  void CompleteJoin(absl::string_view channel_id, JoinResult result);

  // A17. The embedder lost joined channel |channel_id|: sends MC_STATE LEFT
  // with |reason| (-08 section 10.9: 0x2 consent withdrawn, 0x12 rate
  // exceeded, 0x0 otherwise) and drops the channel, without
  // Delegate::LeaveChannel.
  void OnChannelLost(absl::string_view channel_id, uint64_t reason);

  // Private members: lane cr-core (C4).
 private:
  // QuicMulticastControl's outputs, onto the session, channels and delegate.
  class ControlVisitor : public QuicMulticastControl::Visitor {
   public:
    explicit ControlVisitor(QuicMulticastClient* client) : client_(client) {}
    void SendLimits(const QuicMcLimits& frame) override;
    void SendState(const QuicMcState& frame) override;
    JoinResult JoinChannel(const QuicMcAnnounce& announce,
                           const QuicMcKey& key) override;
    void LeaveChannel(absl::string_view channel_id) override;
    void UpdateKey(const QuicMcKey& key) override;
    void OnProtocolError(absl::string_view details) override;

   private:
    QuicMulticastClient* client_;
  };
  class AlarmDelegate;

  QuicTime Now() const;
  // Hands a channel's decrypted STREAM and RESET_STREAM frames to the session
  // and its MC frames to OnMulticastFrame; closes the connection if the
  // channel saw a frame -08 section 11 forbids.
  void Deliver(const std::string& channel_id,
               std::vector<QuicMulticastChannelFrame> frames);
  // Sends each channel's MC_ACK that is due (C6), then arms the alarm for the
  // next MC_ACK or control deadline.
  void UpdateAlarm();
  void OnAlarm();

  QuicSession* session_;
  Delegate* delegate_;
  ControlVisitor control_visitor_{this};
  QuicMulticastControl control_;
  absl::flat_hash_map<std::string, std::unique_ptr<QuicMulticastChannel>>
      channels_;
  std::unique_ptr<QuicAlarm> alarm_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_MULTICAST_CLIENT_H_
