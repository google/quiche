// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// C4 SKELETON (lane Q cr-core, 2026-11-04): states, transitions and the
// interface only. No bodies yet. Design note follows; it is the spec the
// bodies implement.
//
// WHAT IT IS
// The client side of -08 channel management for one WebTransport session's
// QUIC connection. It is pure: inputs are decoded frames, the opt-in and
// channel packet numbers from C5, and |now|. Outputs go to a Visitor: frames
// to send, joins and leaves, and protocol errors. It owns no QuicAlarm; the
// owner arms one at NextDeadline() and calls OnAlarm(). So the session tests
// drive it with no sockets and no QuicSession.
//
// WHERE IT SITS (cr-net INTERFACES.md, I1-I4)
// QuicMulticastClient (I3; header cr-net's, .cc cr-core's) holds one
// QuicMulticastControl as a private member (I3: C1 declares none; cr-core
// adds them in C4).
//   - OnMulticastFrame(type, reader): decode with C2's DecodeMc* (I1), then
//     the matching On* below. MC_INTEGRITY goes to the channel's
//     QuicMulticastChannel::OnIntegrity (I4) instead.
//   - OnMulticastAccepted(): reads TP 0xff3e808 from the session's
//     received_custom_transport_parameters(), then calls OnMulticastAccepted.
//   - Visitor::SendLimits/SendState: session->WriteMulticastControlFrame(
//     type, EncodeMcLimits/EncodeMcState(...)) (I2, C3).
//   - Visitor::JoinChannel: build the QuicMulticastChannel (I4) from the
//     ANNOUNCE and install the KEY, then delegate->JoinChannelWithResult(id,
//     source, group, port) (I3, C8, A17), which by default asks the bool
//     JoinChannel. LeaveChannel: delegate->LeaveChannel, drop it.
//   - Visitor::OnProtocolError: close the connection.
//
// SESSION STATES
//   kAwaitingOptIn -> kActive    on OnMulticastAccepted (the CONNECT 2xx had
//                                wt-multicast: ?1) when the server also sent
//                                TP 0xff3e808. Action: send MC_LIMITS
//                                (sequence 1, the fork's limits, max joined =
//                                max channel IDs), then replay deferred frames
//                                in arrival order.
//   kAwaitingOptIn: an MC frame  is deferred in a FIFO of kMaxDeferredFrames;
//                                past that it is dropped. ("Early JOINs
//                                deferred": the fork oracle sends ANNOUNCE and
//                                JOIN at session start, main.rs:364-381, which
//                                can beat the response headers.)
//   kAwaitingOptIn -> kRefused   on OnMulticastAccepted without 0xff3e808.
//                                Deferred frames are dropped and MC_LIMITS is
//                                never sent. Without ?1, //net never calls
//                                OnMulticastAccepted: the session stays in
//                                kAwaitingOptIn, holds at most
//                                kMaxDeferredFrames, and sends nothing.
//   kRefused: MC frames are ignored. No MC frame is ever sent.
//
// CHANNEL STATES (session kActive; keyed by channel ID; at most
// max_channel_ids entries, extra ANNOUNCEs ignored as the fork does,
// Http3Session.cpp:1449-1461)
//   (none) --ANNOUNCE--> kAnnounced. Guard: header protection and AEAD are
//     0x1301 and the hash is 1, else OnProtocolError (-08 section 3,
//     MC_EXTENSION_ERROR). A repeat ANNOUNCE that differs is also an error;
//     an identical one is ignored.
//   KEY on a tracked channel: keep the highest key sequence (older secrets
//     are wiped, -08 section 10.2). The same sequence with a different secret
//     is OnProtocolError. KEY on an untracked channel is ignored (fork). A
//     newer key reaches a joined or pending channel (Visitor::UpdateKey).
//   JOIN, not joined or pending. Decline (MC_STATE DECLINED_JOIN) for
//   exactly these:
//     a. no ANNOUNCE: UNSYNCHRONIZED_PROPERTIES (0x5), transient;
//     b. no KEY, or our highest key sequence < JOIN's: 0x5, transient;
//     c. an allowlist is set and S is not in it: ADMINISTRATIVE_BLOCK (0x2),
//        permanent;
//     d. joined count = max joined, or the joined rate plus this channel's
//        Max Rate > max aggregate rate: LIMIT_VIOLATION (0x16), permanent. A
//        pending channel counts as joined;
//     e. Visitor::JoinChannel returns kBlocked: 0x2, or kFailed (socket):
//        UNSPECIFIED_OTHER (0x0), both permanent.
//     Never decline because JOIN's MC_LIMITS or MC_STATE sequence is stale:
//     -08 section 10.3 lets the client join anyway, and declining would loop
//     against the oracle (it re-JOINs with the sequences it last saw).
//     Otherwise Visitor::JoinChannel returns kJoined: MC_STATE JOINED (reason
//     0x1), -> kJoined; or kPending: nothing is sent, -> kJoinPending.
//     Record JOIN's MC_STATE sequence as last_control_state.
//   JOIN, joined or pending: ignored (fork, Http3Session.cpp:1648-1653).
//   CompleteJoin (A17), pending only: kJoined sends JOINED (0x1), ->
//     kJoined; kBlocked and kFailed decline as in e. Otherwise ignored, so a
//     LEAVE or RETIRE that came first wins.
//   OnChannelLost (A17), joined only: MC_STATE LEFT with the embedder's
//     reason, -> kLeft, without Visitor::LeaveChannel.
//   Transient decline at t: arm a deadline at t + 1 s. A JOIN before it is
//     handled normally (the oracle re-JOINs itself after KEY,
//     main.rs:528-544). At the deadline, if the channel is still not joined,
//     send MC_LIMITS with sequence + 1 and the same limits: TQ blocks re-JOINs
//     after any decline until a newer MC_LIMITS (server_control.rs:1360-1372,
//     :1420-1430 at b677f5b5). At most kMaxLimitsBumps bumps between JOINEDs.
//     A permanent decline never bumps, or TQ would re-JOIN every second.
//   LEAVE: ignored unless joined or pending, or if its MC_STATE sequence <
//     last_control_state (-08 section 10.4). After Packet Number 0 leaves now;
//     n > 0 leaves at the first channel packet >= n (OnChannelPacket). A
//     pending channel has no packets and leaves now.
//     Leaving: Visitor::LeaveChannel, MC_STATE LEFT (reason 0x1), -> kLeft.
//   RETIRE: when joined with data and After Packet Number n > 0, wait for a
//     packet >= n; otherwise now. Leave if joined or pending, send MC_STATE
//     RETIRED (reason 0x1, no separate LEFT), erase the entry. An untracked
//     channel gets RETIRED too, under the entry cap (fork, :1757-1790).
//   INTEGRITY: not handled here; QuicMulticastClient routes it to C5 (I4).
//   ACK, LIMITS, STATE: client-sent types; ignored if a server sends them.
//   MC_STATE sequence numbers are per channel and start at 1 (fork,
//   Http3Session.cpp:1383).
//
// MC FRAMES INSIDE A CHANNEL PACKET (I4 Sink::OnChannelMulticastFrame;
// -08 section 11; Q multicast.rs:3609-3628)
//   MC_KEY, MC_LEAVE, MC_RETIRE: decoded with C2 and fed to the same OnKey,
//     OnLeave and OnRetire as unicast copies. So the "same key sequence,
//     different secret" error spans both paths.
//   MC_INTEGRITY for ANOTHER channel: that channel's OnIntegrity (I4).
//   MC_INTEGRITY for this channel, and every other MC type (ANNOUNCE, JOIN,
//     LIMITS, STATE, ACK): kError, which closes the connection with
//     MC_EXTENSION_ERROR as -08 section 11 requires.
//
// AFTER PACKET NUMBER INPUT (requested from cr-chan, I4 addition)
//   OnChannelPacket needs the channel's largest received packet number and
//   whether any data arrived (RETIRE waits only then). The I4 Sink has no
//   such callback, so the request is an accessor on QuicMulticastChannel,
//   std::optional<uint64_t> largest_received_packet_number() const, which
//   QuicMulticastClient reads after each ProcessPacket.
//
// NOT IN THE MVP: key rotation beyond keeping the newest key (F2), zero-limits
// revocation and the consent gate (F6; O1(g): the lab build has no consent
// gate), several channels' rate fairness (F3), -10 (P6).
//
// SESSION TESTS (C4 acceptance; both peers' rules)
//   - Parameter offered; nothing sent before the ?1 2xx; MC_LIMITS seq 1 after.
//   - Oracle: ANNOUNCE + JOIN(no KEY) before the response -> deferred ->
//     DECLINED 0x5; then KEY + JOIN(limits 1, state 1, key 1) -> JOINED, no
//     MC_LIMITS bump. Invariants (main.rs:454-474): the first JOIN is
//     declined, and no JOIN is declined once its key is installed.
//   - TQ: JOIN only after MC_LIMITS; a lost KEY -> decline -> 1 s -> MC_LIMITS
//     seq 2 -> re-JOIN -> JOINED.
//   - S outside the allowlist -> DECLINED 0x2 and no bump, ever.
//   - LEAVE -> LEFT; a stale LEAVE is ignored; LEAVE after n waits for n.
//   - RETIRE drops state and sends RETIRED; a no-?1 session sends nothing.

#ifndef QUICHE_QUIC_CORE_QUIC_MULTICAST_CONTROL_H_
#define QUICHE_QUIC_CORE_QUIC_MULTICAST_CONTROL_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_export.h"
#include "quiche/quic/platform/api/quic_ip_address.h"

namespace quic {

class QUICHE_EXPORT QuicMulticastControl {
 public:
  enum class SessionState { kAwaitingOptIn, kActive, kRefused };
  enum class ChannelState {
    kAnnounced,
    kDeclined,
    kJoinPending,
    kJoined,
    kLeft
  };
  // The embedder's answer to a JOIN.
  enum class JoinResult : uint8_t {
    kJoined,   // MC_STATE JOINED now.
    kPending,  // Nothing now; CompleteJoin() follows.
    kBlocked,  // DECLINED_JOIN, ADMINISTRATIVE_BLOCK (0x2): no consent for S.
    kFailed,   // DECLINED_JOIN, UNSPECIFIED_OTHER (0x0).
  };

  static constexpr size_t kMaxDeferredFrames = 64;
  static constexpr int kMaxLimitsBumps = 3;
  static constexpr QuicTime::Delta kRejoinWait =
      QuicTime::Delta::FromSeconds(1);

  class QUICHE_EXPORT Visitor {
   public:
    virtual ~Visitor() = default;
    virtual void SendLimits(const QuicMcLimits& frame) = 0;
    virtual void SendState(const QuicMcState& frame) = 0;
    // Opens the channel's receiver and SSM socket, or starts to (kPending).
    // kBlocked and kFailed decline the JOIN.
    virtual JoinResult JoinChannel(const QuicMcAnnounce& announce,
                                   const QuicMcKey& key) = 0;
    // Also cancels a pending JOIN.
    virtual void LeaveChannel(absl::string_view channel_id) = 0;
    // A newer KEY for a joined or pending channel (key rotation, newest key
    // only).
    virtual void UpdateKey(const QuicMcKey& key) = 0;
    // MC_EXTENSION_ERROR: the owner closes the connection.
    virtual void OnProtocolError(absl::string_view details) = 0;
  };

  // |allowed_sources| is the lab trust boundary (I3's allowed_sources);
  // nullopt leaves every source to the visitor (P8, A17).
  // |params| is what the client sent in TP 0xff3e800; MC_LIMITS repeats them.
  QuicMulticastControl(
      Visitor* visitor,
      std::optional<std::vector<QuicIpAddress>> allowed_sources,
      QuicMcClientParams params = QuicMcDefaultClientParams());

  void OnMulticastAccepted(bool server_sent_support, QuicTime now);
  void OnAnnounce(QuicMcAnnounce frame, QuicTime now);
  void OnKey(QuicMcKey frame, QuicTime now);
  void OnJoin(const QuicMcJoin& frame, QuicTime now);
  void OnLeave(const QuicMcLeave& frame, QuicTime now);
  void OnRetire(const QuicMcRetire& frame, QuicTime now);
  // C5 decrypted channel packet |packet_number| (for After Packet Number).
  void OnChannelPacket(absl::string_view channel_id, uint64_t packet_number,
                       QuicTime now);
  // The answer to a JOIN that Visitor::JoinChannel left pending (A17).
  // Ignored unless |channel_id| is still kJoinPending; kPending leaves it so.
  void CompleteJoin(absl::string_view channel_id, JoinResult result,
                    QuicTime now);
  // The embedder lost joined channel |channel_id| (A17): MC_STATE LEFT with
  // |reason|, without Visitor::LeaveChannel. Ignored unless joined.
  void OnChannelLost(absl::string_view channel_id, uint64_t reason,
                     QuicTime now);
  void OnAlarm(QuicTime now);
  std::optional<QuicTime> NextDeadline() const;

  SessionState session_state() const { return session_state_; }
  // Test and debug accessor; nullopt for an untracked channel.
  std::optional<ChannelState> channel_state(absl::string_view id) const;

 private:
  using DeferredFrame = std::variant<QuicMcAnnounce, QuicMcKey, QuicMcJoin,
                                     QuicMcLeave, QuicMcRetire>;

  struct Channel {
    ChannelState state = ChannelState::kAnnounced;
    std::optional<QuicMcAnnounce> announce;
    std::optional<QuicMcKey> key;      // highest key sequence only
    uint64_t state_sequence = 0;       // last MC_STATE sequence sent
    uint64_t last_control_state = 0;   // highest JOIN/LEAVE state sequence
    std::optional<uint64_t> leave_after_packet;
    std::optional<uint64_t> retire_after_packet;
    std::optional<uint64_t> largest_packet_number;  // set => received data
    std::optional<QuicTime> rejoin_deadline;  // set by a transient decline
  };

  // True when the frame was deferred or the session is not active.
  bool Defer(DeferredFrame frame);
  void SendLimits();
  void SendState(absl::string_view id, Channel& channel,
                 QuicMcChannelState state, uint64_t reason);
  void ProtocolError(absl::string_view details);
  // MC_STATE DECLINED_JOIN with |reason|; only 0x5 arms a re-JOIN deadline.
  void Decline(absl::string_view id, Channel& channel, uint64_t reason,
               QuicTime now);
  // Visitor::JoinChannel's answer, now (OnJoin) or later (CompleteJoin).
  void Answer(absl::string_view id, Channel& channel, JoinResult result,
              QuicTime now);
  void Leave(absl::string_view id, Channel& channel);
  void Retire(absl::flat_hash_map<std::string, Channel>::iterator it);

  Visitor* visitor_;
  const std::optional<std::vector<QuicIpAddress>> allowed_sources_;
  const QuicMcClientParams params_;
  SessionState session_state_ = SessionState::kAwaitingOptIn;
  std::deque<DeferredFrame> deferred_;
  absl::flat_hash_map<std::string, Channel> channels_;
  uint64_t limits_sequence_ = 0;
  int limits_bumps_ = 0;  // reset by each JOINED
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_MULTICAST_CONTROL_H_
