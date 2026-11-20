// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_multicast_channel.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/digest.h"
#include "openssl/mem.h"
#include "openssl/sha.h"
#include "openssl/tls1.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/quic_decrypter.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_versions.h"

namespace quic {
namespace {

constexpr uint16_t kAes128GcmSha256 = 0x1301;  // AEAD and header protection.
constexpr uint16_t kSha256 = 1;                // Named-information hash 1.
// Server-initiated unidirectional stream IDs end in 0b11. The first three
// (3, 7, 11) are the server's HTTP/3 control and QPACK streams.
constexpr QuicStreamId kFirstChannelStreamId = 15;
// The short header's Key Phase bit, unmasked once header protection is off.
constexpr uint8_t kShortHeaderKeyPhaseBit = 0x04;

absl::Span<const uint8_t> Bytes(absl::string_view s) {
  return absl::MakeConstSpan(reinterpret_cast<const uint8_t*>(s.data()),
                             s.size());
}

std::string Sha256(absl::string_view data) {
  std::string out(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
         reinterpret_cast<uint8_t*>(out.data()));
  return out;
}

}  // namespace

// static
std::unique_ptr<QuicMulticastChannel> QuicMulticastChannel::Create(
    absl::string_view channel_id, uint16_t header_protection_algorithm,
    absl::string_view header_secret, uint16_t aead_algorithm,
    uint16_t integrity_hash_algorithm, uint64_t max_ack_delay_ms) {
  if (channel_id.empty() ||
      channel_id.size() > kQuicMaxConnectionIdWithLengthPrefixLength ||
      header_protection_algorithm != kAes128GcmSha256 ||
      aead_algorithm != kAes128GcmSha256 ||
      integrity_hash_algorithm != kSha256 || header_secret.empty()) {
    return nullptr;
  }
  return std::unique_ptr<QuicMulticastChannel>(
      new QuicMulticastChannel(channel_id, header_secret, max_ack_delay_ms));
}

QuicMulticastChannel::QuicMulticastChannel(absl::string_view channel_id,
                                           absl::string_view header_secret,
                                           uint64_t max_ack_delay_ms)
    : channel_id_(channel_id.data(), static_cast<uint8_t>(channel_id.size())),
      header_secret_(header_secret),
      // At most a day, so a huge varint cannot overflow QuicTime::Delta.
      max_ack_delay_(QuicTime::Delta::FromMilliseconds(static_cast<int64_t>(
          std::min<uint64_t>(max_ack_delay_ms, 86400000)))),
      framer_({ParsedQuicVersion::RFCv1()}, QuicTime::Zero(),
              Perspective::IS_CLIENT,
              /*expected_server_connection_id_length=*/0) {
  framer_.set_visitor(this);
  // The short header carries the channel ID where a DCID would be.
  framer_.SetExpectedClientConnectionIdLength(
      static_cast<uint8_t>(channel_id.size()));
}

QuicMulticastChannel::~QuicMulticastChannel() = default;

std::vector<QuicMulticastChannelFrame> QuicMulticastChannel::OnKey(
    uint64_t key_sequence, absl::string_view secret, QuicTime now) {
  std::vector<QuicMulticastChannelFrame> out;
  if (key_sequence_.has_value() && key_sequence <= *key_sequence_) {
    return out;
  }
  std::unique_ptr<QuicDecrypter> decrypter =
      QuicDecrypter::CreateFromCipherSuite(TLS1_3_CK_AES_128_GCM_SHA256);
  // -08 splits the secrets: key and IV from MC_KEY, header protection from
  // MC_ANNOUNCE. InitializeCrypterSecrets would take all three from one.
  CryptoUtils::SetKeyAndIV(EVP_sha256(), Bytes(secret),
                           ParsedQuicVersion::RFCv1(), decrypter.get());
  std::string hp_key(decrypter->GetKeySize(), '\0');
  if (!CryptoUtils::GenerateHeaderProtectionKey(
          EVP_sha256(), Bytes(header_secret_), ParsedQuicVersion::RFCv1(),
          absl::MakeSpan(reinterpret_cast<uint8_t*>(hp_key.data()),
                         hp_key.size())) ||
      !decrypter->SetHeaderProtectionKey(hp_key)) {
    return out;
  }
  framer_.InstallDecrypter(ENCRYPTION_FORWARD_SECURE, std::move(decrypter));
  key_sequence_ = key_sequence;
  Replay(now, &out);
  return out;
}

std::vector<QuicMulticastChannelFrame> QuicMulticastChannel::OnIntegrity(
    uint64_t packet_number_start, absl::string_view hashes, QuicTime now) {
  std::vector<QuicMulticastChannelFrame> out;
  if (hashes.empty() || hashes.size() % SHA256_DIGEST_LENGTH != 0) {
    return out;
  }
  for (size_t i = 0; i * SHA256_DIGEST_LENGTH < hashes.size(); ++i) {
    // The first hash for a packet number wins; it came over the
    // authenticated control connection.
    hash_by_packet_number_.emplace(
        packet_number_start + i,
        std::string(
            hashes.substr(i * SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH)));
  }
  while (hash_by_packet_number_.size() > kMulticastChannelMaxIntegrityEntries) {
    hash_by_packet_number_.erase(hash_by_packet_number_.begin());
  }
  Replay(now, &out);
  return out;
}

std::vector<QuicMulticastChannelFrame> QuicMulticastChannel::OnPacket(
    absl::string_view packet, QuicEcnCodepoint ecn, QuicTime now) {
  std::vector<QuicMulticastChannelFrame> out;
  Expire(now);
  if (Process(packet, ecn, now, &out) != Result::kWaiting) {
    return out;
  }
  // ponytail: anyone who can reach (S, G) can fill these 256 slots with
  // garbage and push out early genuine packets; unicast recovery covers the
  // loss. A per-source budget is the upgrade if that shows up.
  if (pending_.size() == kMulticastChannelMaxPendingPackets) {
    pending_.pop_front();
    ++stats_.evicted;
  }
  pending_.push_back({std::string(packet), ecn, now});
  return out;
}

std::optional<QuicTime> QuicMulticastChannel::ack_deadline() const {
  if (!ack_pending_since_.has_value()) {
    return std::nullopt;
  }
  return ack_sent_ ? *ack_pending_since_ + max_ack_delay_ : *ack_pending_since_;
}

std::optional<QuicMcAck> QuicMulticastChannel::TakeAck() {
  if (!ack_pending_since_.has_value() || acked_.Empty()) {
    return std::nullopt;
  }
  ack_pending_since_.reset();
  ack_sent_ = true;
  // RFC 9000 19.3.1 ranges, newest first; QuicIntervalSet's are [min, max).
  QuicMcAck ack;
  ack.channel_id = std::string(channel_id_.data(), channel_id_.length());
  auto it = acked_.rbegin();
  ack.largest_acknowledged = it->max() - 1;
  ack.first_ack_range = it->max() - 1 - it->min();
  uint64_t smallest = it->min();
  for (++it; it != acked_.rend(); ++it) {
    ack.ranges.push_back({smallest - it->max() - 1, it->max() - 1 - it->min()});
    smallest = it->min();
  }
  if (ecn_counts_ != QuicEcnCounts()) {
    ack.ecn = ecn_counts_;
  }
  return ack;
}

void QuicMulticastChannel::RecordAck(uint64_t packet_number,
                                     QuicEcnCodepoint ecn, QuicTime now) {
  switch (ecn) {
    case ECN_ECT0:
      ++ecn_counts_.ect0;
      break;
    case ECN_ECT1:
      ++ecn_counts_.ect1;
      break;
    case ECN_CE:
      ++ecn_counts_.ce;
      break;
    case ECN_NOT_ECT:
      break;
  }
  acked_.Add(packet_number, packet_number + 1);
  const uint64_t end = acked_.rbegin()->max();
  if (end > kMulticastChannelAckHistoryPackets) {
    acked_.TrimLessThan(end - kMulticastChannelAckHistoryPackets);
  }
  while (acked_.Size() > kMulticastChannelMaxAckRanges) {
    acked_.PopFront();
  }
  if (!ack_pending_since_.has_value()) {
    ack_pending_since_ = now;
  }
}

QuicMulticastChannel::Result QuicMulticastChannel::Process(
    absl::string_view packet, QuicEcnCodepoint ecn, QuicTime now,
    std::vector<QuicMulticastChannelFrame>* out) {
  if (!key_sequence_.has_value()) {
    return Result::kWaiting;  // No decrypter yet, not even for the header.
  }
  // The hash covers the raw bytes as received, before header protection is
  // removed, so take it before the framer touches anything.
  current_hash_ = Sha256(packet);
  current_result_ = Result::kDropped;
  current_refused_ = false;
  staged_.clear();
  framer_.ProcessPacket(QuicEncryptedPacket(packet));
  if (current_result_ == Result::kDelivered) {
    hash_by_packet_number_[current_packet_number_].clear();
    ++stats_.delivered_packets;
    RecordAck(current_packet_number_, ecn, now);
    for (QuicMulticastChannelFrame& frame : staged_) {
      out->push_back(std::move(frame));
    }
  }
  staged_.clear();
  return current_result_;
}

void QuicMulticastChannel::Replay(QuicTime now,
                                  std::vector<QuicMulticastChannelFrame>* out) {
  Expire(now);
  std::deque<Pending> waiting;
  waiting.swap(pending_);
  for (Pending& p : waiting) {
    if (Process(p.packet, p.ecn, now, out) == Result::kWaiting) {
      pending_.push_back(std::move(p));
    }
  }
}

void QuicMulticastChannel::Expire(QuicTime now) {
  while (!pending_.empty() &&
         now - pending_.front().arrival >
             QuicTime::Delta::FromSeconds(kMulticastChannelMaxPendingSeconds)) {
    pending_.pop_front();
    ++stats_.expired;
  }
}

void QuicMulticastChannel::OnError(QuicFramer* /*framer*/) {
  ++stats_.undecodable;
  current_result_ = Result::kDropped;
}

bool QuicMulticastChannel::OnProtocolVersionMismatch(
    ParsedQuicVersion /*received_version*/) {
  return false;
}

bool QuicMulticastChannel::OnUnauthenticatedPublicHeader(
    const QuicPacketHeader& header) {
  if (header.form != IETF_QUIC_SHORT_HEADER_PACKET ||
      header.destination_connection_id != channel_id_) {
    ++stats_.undecodable;
    return false;
  }
  return true;
}

// Header protection is off and the packet number rebuilt; nothing is
// decrypted yet and the framer's largest packet number is still unchanged.
bool QuicMulticastChannel::OnUnauthenticatedHeader(
    const QuicPacketHeader& header) {
  current_packet_number_ = header.packet_number.ToUint64();
  auto it = hash_by_packet_number_.find(current_packet_number_);
  if (it == hash_by_packet_number_.end()) {
    current_result_ = Result::kWaiting;
  } else if (it->second.empty()) {
    ++stats_.duplicates;
  } else if (it->second != current_hash_) {
    ++stats_.integrity_mismatches;
  } else if (((header.type_byte & kShortHeaderKeyPhaseBit) != 0) !=
             (*key_sequence_ % 2 == 1)) {
    // -08 10.2: the Key Phase is the parity of the Key Sequence Number. This
    // genuine packet (its hash matched) needs a key whose MC_KEY has not
    // arrived yet, as after a rotation whose MC_KEY trails its first packet.
    // It waits, undecrypted, in the same bounded buffer; OnKey replays it.
    current_result_ = Result::kWaiting;
  } else {
    return true;
  }
  return false;
}

bool QuicMulticastChannel::Guard(QuicStreamId stream_id) {
  if ((stream_id & 0x3) == 0x3 && stream_id >= kFirstChannelStreamId) {
    return true;
  }
  ++stats_.guard_drops;
  return false;
}

bool QuicMulticastChannel::OnStreamFrame(const QuicStreamFrame& frame) {
  if (Guard(frame.stream_id)) {
    QuicMulticastChannelFrame& f = staged_.emplace_back();
    f.packet_number = current_packet_number_;
    f.stream_id = frame.stream_id;
    f.offset = frame.offset;
    f.fin = frame.fin;
    f.data.assign(frame.data_buffer, frame.data_length);
  }
  return true;
}

bool QuicMulticastChannel::OnRstStreamFrame(const QuicRstStreamFrame& frame) {
  if (Guard(frame.stream_id)) {
    QuicMulticastChannelFrame& f = staged_.emplace_back();
    f.packet_number = current_packet_number_;
    f.reset = true;
    f.stream_id = frame.stream_id;
    f.offset = frame.byte_offset;
    f.error_code = frame.ietf_error_code;
  }
  return true;
}

// -08 section 11: MC_KEY, MC_LEAVE, MC_RETIRE and MC_INTEGRITY for another
// channel may ride in a channel packet. They are decoded here only to find
// the end of the body; the caller decodes them again from the copy.
QuicMulticastFrameStatus QuicMulticastChannel::OnMulticastFrame(
    uint64_t frame_type, QuicDataReader* reader) {
  if (!IsMcFrameType(frame_type)) {
    return QuicMulticastFrameStatus::kNotHandled;
  }
  const absl::string_view body = reader->PeekRemainingPayload();
  bool permitted = true;
  bool decoded = false;
  switch (frame_type) {
    case kMcKey: {
      QuicMcKey f;
      decoded = DecodeMcKey(reader, &f);
      OPENSSL_cleanse(f.secret.data(), f.secret.size());
      break;
    }
    case kMcLeave: {
      QuicMcLeave f;
      decoded = DecodeMcLeave(reader, &f);
      break;
    }
    case kMcRetire: {
      QuicMcRetire f;
      decoded = DecodeMcRetire(reader, &f);
      break;
    }
    case kMcIntegrity:
    case kMcIntegrityWithLength: {
      QuicMcIntegrity f;
      decoded = DecodeMcIntegrity(frame_type, kMcSha256HashLength, reader, &f);
      // A channel's own hashes must come by another path (-08 section 4.3).
      permitted = f.channel_id !=
                  absl::string_view(channel_id_.data(), channel_id_.length());
      break;
    }
    default:  // ANNOUNCE, JOIN, ACK, LIMITS, STATE.
      permitted = false;
      break;
  }
  if (!permitted) {
    Refuse();
    return QuicMulticastFrameStatus::kStop;
  }
  if (!decoded) {
    return QuicMulticastFrameStatus::kError;  // Dropped as undecodable.
  }
  QuicMulticastChannelFrame& f = staged_.emplace_back();
  f.packet_number = current_packet_number_;
  f.multicast_frame_type = frame_type;
  f.data = std::string(body.substr(0, body.size() - reader->BytesRemaining()));
  return QuicMulticastFrameStatus::kContinue;
}

void QuicMulticastChannel::OnPacketComplete() {
  if (!current_refused_) {
    current_result_ = Result::kDelivered;
  }
}

bool QuicMulticastChannel::Refuse() {
  current_refused_ = true;
  ++stats_.forbidden_frames;
  return false;  // Stops the framer; Process() drops the packet.
}

bool QuicMulticastChannel::OnCryptoFrame(const QuicCryptoFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnAckFrameStart(QuicPacketNumber, QuicTime::Delta) {
  return Refuse();
}
bool QuicMulticastChannel::OnAckRange(QuicPacketNumber, QuicPacketNumber) {
  return Refuse();
}
bool QuicMulticastChannel::OnAckTimestamp(QuicPacketNumber, QuicReceiveTime) {
  return Refuse();
}
bool QuicMulticastChannel::OnAckFrameEnd(QuicPacketNumber,
                                         const std::optional<QuicEcnCounts>&) {
  return Refuse();
}
bool QuicMulticastChannel::OnStopWaitingFrame(const QuicStopWaitingFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnConnectionCloseFrame(
    const QuicConnectionCloseFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnStopSendingFrame(const QuicStopSendingFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnPathChallengeFrame(const QuicPathChallengeFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnPathResponseFrame(const QuicPathResponseFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnGoAwayFrame(const QuicGoAwayFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnWindowUpdateFrame(const QuicWindowUpdateFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnBlockedFrame(const QuicBlockedFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnNewConnectionIdFrame(
    const QuicNewConnectionIdFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnRetireConnectionIdFrame(
    const QuicRetireConnectionIdFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnNewTokenFrame(const QuicNewTokenFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnHandshakeDoneFrame(const QuicHandshakeDoneFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnAckFrequencyFrame(const QuicAckFrequencyFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnImmediateAckFrame(const QuicImmediateAckFrame&) {
  return Refuse();
}
// ponytail: RESET_STREAM_AT is allowed on channels by -08 but unused by our
// server; forward it like RESET_STREAM when the server starts sending it.
bool QuicMulticastChannel::OnResetStreamAtFrame(const QuicResetStreamAtFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnMaxStreamsFrame(const QuicMaxStreamsFrame&) {
  return Refuse();
}
bool QuicMulticastChannel::OnStreamsBlockedFrame(
    const QuicStreamsBlockedFrame&) {
  return Refuse();
}

}  // namespace quic
