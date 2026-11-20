// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_MULTICAST_CHANNEL_H_
#define QUICHE_QUIC_CORE_QUIC_MULTICAST_CHANNEL_H_

#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_interval_set.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"

namespace quic {

// Early channel packets (no MC_KEY or MC_INTEGRITY yet) are held at most this
// many at a time, and at most this long.
inline constexpr size_t kMulticastChannelMaxPendingPackets = 256;
inline constexpr int64_t kMulticastChannelMaxPendingSeconds = 5;
// Integrity hashes kept, lowest packet numbers evicted first.
inline constexpr size_t kMulticastChannelMaxIntegrityEntries = 1024;
// MC_ACK history, as Q's AckTracker keeps it (multicast.rs:64-65): the newest
// 4096 packet numbers, in at most 64 ranges.
inline constexpr uint64_t kMulticastChannelAckHistoryPackets = 4096;
inline constexpr size_t kMulticastChannelMaxAckRanges = 64;

// A frame from a channel packet whose MC_INTEGRITY hash matched: STREAM or
// RESET_STREAM, which the caller hands to the session's shared stream, or an
// MC frame (-08 section 11), which the caller handles as if it came on the
// unicast connection.
struct QUICHE_EXPORT QuicMulticastChannelFrame {
  uint64_t packet_number = 0;
  bool reset = false;  // RESET_STREAM if true, else STREAM.
  QuicStreamId stream_id = 0;
  // STREAM: the data offset. RESET_STREAM: the final size.
  QuicStreamOffset offset = 0;
  uint64_t error_code = 0;  // RESET_STREAM only.
  bool fin = false;         // STREAM only.
  std::string data;         // STREAM: the data. MC frame: its body.
  // Non-zero for an MC frame: MC_KEY, MC_LEAVE, MC_RETIRE, or MC_INTEGRITY
  // for another channel. `data` holds the body after the type varint.
  uint64_t multicast_frame_type = 0;

  bool operator==(const QuicMulticastChannelFrame&) const = default;
};

// Channel ingress for draft-jholland-quic-multicast-08 on the client.
//
// One QuicFramer per channel gives the channel its own packet-number space and
// keys. The secrets are split as -08 requires: header protection comes from
// MC_ANNOUNCE's header secret, the packet key and IV from MC_KEY's secret.
// A packet is decrypted only after SHA-256 of its raw bytes equals the
// MC_INTEGRITY hash for its packet number; until then (and until MC_KEY) it
// waits in a buffer of 256 packets or 5 s, replayed when the metadata arrives.
// A hash mismatch drops the packet. STREAM and RESET_STREAM frames on
// server-initiated unidirectional streams above the HTTP/3 static ones come
// out, and so do the MC frames -08 section 11 permits; PADDING, PING and
// DATAGRAM are accepted and not forwarded. Any other frame drops the whole
// packet and counts in stats().forbidden_frames, after which the caller must
// close the connection with MC_EXTENSION_ERROR (-08 section 11).
//
// C6: every delivered packet number is kept for MC_ACK, with the ECN counts
// of the delivered packets. ack_deadline() says when the pending MC_ACK is
// due and TakeAck() builds it.
//
// The methods return the frames they released, so nothing re-enters the
// framer from the caller.
class QUICHE_EXPORT QuicMulticastChannel : public QuicFramerVisitorInterface {
 public:
  struct Stats {
    uint64_t delivered_packets = 0;
    uint64_t integrity_mismatches = 0;  // Hash differs: dropped.
    uint64_t duplicates = 0;            // Packet number already delivered.
    uint64_t undecodable = 0;           // Framer error, wrong DCID.
    uint64_t forbidden_frames = 0;      // -08 section 11: close the connection.
    uint64_t guard_drops = 0;           // Frames on a stream the guard refuses.
    uint64_t expired = 0;               // Waited 5 s without its metadata.
    uint64_t evicted = 0;               // Pushed out by the 256-packet cap.
  };

  // Returns nullptr unless the channel uses what the MVP supports: AEAD and
  // header protection 0x1301 (TLS_AES_128_GCM_SHA256) and integrity hash 1
  // (SHA-256), with a channel ID of 1-20 bytes. |max_ack_delay_ms| is
  // MC_ANNOUNCE's Max ACK Delay.
  static std::unique_ptr<QuicMulticastChannel> Create(
      absl::string_view channel_id, uint16_t header_protection_algorithm,
      absl::string_view header_secret, uint16_t aead_algorithm,
      uint16_t integrity_hash_algorithm, uint64_t max_ack_delay_ms);

  QuicMulticastChannel(const QuicMulticastChannel&) = delete;
  QuicMulticastChannel& operator=(const QuicMulticastChannel&) = delete;
  ~QuicMulticastChannel() override;

  // MC_KEY. A key with a sequence no newer than the current one is ignored.
  // ponytail: one key at a time; rotation (P7) keeps the old decrypter until
  // from_packet_number and selects by key phase.
  std::vector<QuicMulticastChannelFrame> OnKey(uint64_t key_sequence,
                                               absl::string_view secret,
                                               QuicTime now);

  // MC_INTEGRITY: `hashes` holds one 32-byte SHA-256 per packet number from
  // `packet_number_start` upward. Any other length is ignored.
  std::vector<QuicMulticastChannelFrame> OnIntegrity(
      uint64_t packet_number_start, absl::string_view hashes, QuicTime now);

  // A datagram read from the channel's (S, G, port) socket, with its ECN
  // codepoint.
  std::vector<QuicMulticastChannelFrame> OnPacket(absl::string_view packet,
                                                  QuicEcnCodepoint ecn,
                                                  QuicTime now);

  // When the pending MC_ACK is due: at once for the channel's first MC_ACK,
  // then Max ACK Delay after the oldest packet it covers (-08 section 10.1).
  // nullopt when nothing is pending.
  std::optional<QuicTime> ack_deadline() const;
  // The pending MC_ACK for every delivered packet number still kept, with
  // ECN counts (MC_ACK_ECN) once a delivered packet carried an ECN mark.
  // nullopt when nothing is pending; otherwise nothing is pending after it.
  std::optional<QuicMcAck> TakeAck();

  size_t pending_packets() const { return pending_.size(); }
  const Stats& stats() const { return stats_; }

  // QuicFramerVisitorInterface.
  void OnError(QuicFramer* framer) override;
  bool OnProtocolVersionMismatch(ParsedQuicVersion received_version) override;
  void OnPacket() override {}
  void OnVersionNegotiationPacket(
      const QuicVersionNegotiationPacket& /*packet*/) override {}
  void OnRetryPacket(QuicConnectionId /*original_connection_id*/,
                     QuicConnectionId /*new_connection_id*/,
                     absl::string_view /*retry_token*/,
                     absl::string_view /*retry_integrity_tag*/,
                     absl::string_view /*retry_without_tag*/) override {}
  bool OnUnauthenticatedPublicHeader(const QuicPacketHeader& header) override;
  bool OnUnauthenticatedHeader(const QuicPacketHeader& header) override;
  void OnDecryptedPacket(size_t /*length*/,
                         EncryptionLevel /*level*/) override {}
  bool OnPacketHeader(const QuicPacketHeader& /*header*/) override {
    return true;
  }
  void OnCoalescedPacket(const QuicEncryptedPacket& /*packet*/) override {}
  void OnUndecryptablePacket(const QuicEncryptedPacket& /*packet*/,
                             EncryptionLevel /*decryption_level*/,
                             bool /*has_decryption_key*/) override {}
  bool OnStreamFrame(const QuicStreamFrame& frame) override;
  bool OnCryptoFrame(const QuicCryptoFrame& frame) override;
  bool OnAckFrameStart(QuicPacketNumber largest_acked,
                       QuicTime::Delta ack_delay_time) override;
  bool OnAckRange(QuicPacketNumber start, QuicPacketNumber end) override;
  bool OnAckTimestamp(QuicPacketNumber packet_number,
                      QuicReceiveTime timestamp) override;
  bool OnAckFrameEnd(QuicPacketNumber start,
                     const std::optional<QuicEcnCounts>& ecn_counts) override;
  bool OnStopWaitingFrame(const QuicStopWaitingFrame& frame) override;
  bool OnPaddingFrame(const QuicPaddingFrame& /*frame*/) override {
    return true;
  }
  bool OnPingFrame(const QuicPingFrame& /*frame*/) override { return true; }
  bool OnRstStreamFrame(const QuicRstStreamFrame& frame) override;
  bool OnConnectionCloseFrame(const QuicConnectionCloseFrame& frame) override;
  bool OnStopSendingFrame(const QuicStopSendingFrame& frame) override;
  bool OnPathChallengeFrame(const QuicPathChallengeFrame& frame) override;
  bool OnPathResponseFrame(const QuicPathResponseFrame& frame) override;
  bool OnGoAwayFrame(const QuicGoAwayFrame& frame) override;
  bool OnWindowUpdateFrame(const QuicWindowUpdateFrame& frame) override;
  bool OnBlockedFrame(const QuicBlockedFrame& frame) override;
  bool OnNewConnectionIdFrame(const QuicNewConnectionIdFrame& frame) override;
  bool OnRetireConnectionIdFrame(
      const QuicRetireConnectionIdFrame& frame) override;
  bool OnNewTokenFrame(const QuicNewTokenFrame& frame) override;
  bool OnDatagramFrame(const QuicDatagramFrame& /*frame*/) override {
    return true;
  }
  bool OnHandshakeDoneFrame(const QuicHandshakeDoneFrame& frame) override;
  bool OnAckFrequencyFrame(const QuicAckFrequencyFrame& frame) override;
  bool OnImmediateAckFrame(const QuicImmediateAckFrame& frame) override;
  bool OnResetStreamAtFrame(const QuicResetStreamAtFrame& frame) override;
  QuicMulticastFrameStatus OnMulticastFrame(uint64_t frame_type,
                                            QuicDataReader* reader) override;
  void OnPacketComplete() override;
  bool IsValidStatelessResetToken(
      const StatelessResetToken& /*token*/) const override {
    return false;
  }
  void OnAuthenticatedIetfStatelessResetPacket() override {}
  bool OnMaxStreamsFrame(const QuicMaxStreamsFrame& frame) override;
  bool OnStreamsBlockedFrame(const QuicStreamsBlockedFrame& frame) override;
  void OnKeyUpdate(KeyUpdateReason /*reason*/) override {}
  void OnDecryptedFirstPacketInKeyPhase() override {}
  void OnSconePacket(uint8_t /*signal*/) override {}
  std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
      override {
    return nullptr;  // Key update is off on the channel framer.
  }
  std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override {
    return nullptr;  // The channel is receive-only.
  }

 private:
  enum class Result { kDelivered, kWaiting, kDropped };
  struct Pending {
    std::string packet;
    QuicEcnCodepoint ecn;
    QuicTime arrival;
  };

  QuicMulticastChannel(absl::string_view channel_id,
                       absl::string_view header_secret,
                       uint64_t max_ack_delay_ms);

  // Runs one packet through the framer; appends its frames to `out` only if
  // the whole packet is delivered.
  Result Process(absl::string_view packet, QuicEcnCodepoint ecn, QuicTime now,
                 std::vector<QuicMulticastChannelFrame>* out);
  // Keeps a delivered packet number for MC_ACK.
  void RecordAck(uint64_t packet_number, QuicEcnCodepoint ecn, QuicTime now);
  // Drops expired packets, then replays the rest in arrival order.
  void Replay(QuicTime now, std::vector<QuicMulticastChannelFrame>* out);
  void Expire(QuicTime now);
  bool Refuse();  // A frame that has no place on a channel.
  bool Guard(QuicStreamId stream_id);

  const QuicConnectionId channel_id_;
  const std::string header_secret_;
  const QuicTime::Delta max_ack_delay_;
  QuicFramer framer_;
  std::optional<uint64_t> key_sequence_;
  // Packet number to its SHA-256; an empty value marks a delivered packet.
  std::map<uint64_t, std::string> hash_by_packet_number_;
  std::deque<Pending> pending_;
  Stats stats_;

  // C6 (MC_ACK) state.
  QuicIntervalSet<uint64_t> acked_;  // Delivered packet numbers.
  QuicEcnCounts ecn_counts_;         // Of the delivered packets.
  std::optional<QuicTime> ack_pending_since_;
  bool ack_sent_ = false;

  // Per-packet state while the framer runs.
  std::string current_hash_;
  uint64_t current_packet_number_ = 0;
  Result current_result_ = Result::kDropped;
  bool current_refused_ = false;
  std::vector<QuicMulticastChannelFrame> staged_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_MULTICAST_CHANNEL_H_
