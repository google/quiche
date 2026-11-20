// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Codec for draft-jholland-quic-multicast-08: the client transport parameter
// and the nine control frames (interface I1, frozen by lane cr-net in
// /data/scratch/quicmc-q/cr-net/INTERFACES.md). Every -08 byte layout lives
// here and in the .cc, so a later revision changes these two files only.
//
// The layouts match the engine our server runs (QUICast quiche f208164a,
// quiche/src/multicast.rs:234-344 and :860-1134), and the golden vectors in
// quic_multicast_frames_test.cc are that engine's own output.

#ifndef QUICHE_QUIC_CORE_QUIC_MULTICAST_FRAMES_H_
#define QUICHE_QUIC_CORE_QUIC_MULTICAST_FRAMES_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_export.h"
#include "quiche/quic/platform/api/quic_ip_address.h"

namespace quic {

// I0: wire constants (-08 sections 3 and 10). Each frame type is a minimal
// 4-byte varint, 8f f3 e8 xx.
inline constexpr uint64_t kMcClientParamsId = 0xff3e800;   // client TP
inline constexpr uint64_t kMcServerSupportId = 0xff3e808;  // server TP
enum QuicMcFrameType : uint64_t {
  kMcKey = 0xff3e801,
  kMcJoin = 0xff3e802,
  kMcLeave = 0xff3e803,
  kMcIntegrity = 0xff3e804,            // hashes run to the end of the packet
  kMcIntegrityWithLength = 0xff3e805,  // count x hash_len
  kMcAck = 0xff3e806,
  kMcAckEcn = 0xff3e807,
  kMcLimits = 0xff3e809,
  kMcRetire = 0xff3e80a,
  kMcState = 0xff3e80b,
  kMcStateApplication = 0xff3e80c,
  kMcAnnounceV4 = 0xff3e811,
  kMcAnnounceV6 = 0xff3e812,
};

// True for every QuicMcFrameType value.
QUICHE_EXPORT bool IsMcFrameType(uint64_t frame_type);

// The one hash and the one AEAD the client offers. A server must not announce
// a channel that uses anything else (-08 section 3).
inline constexpr uint16_t kMcHashSha256 = 1;  // named-information registry
inline constexpr size_t kMcSha256HashLength = 32;
inline constexpr uint16_t kMcAes128GcmSha256 = 0x1301;  // TLS cipher suite

// A channel ID is also the channel packet's DCID.
inline constexpr size_t kMcMaxChannelIdLength = 20;

// MC_STATE reason codes for kMcState (-08 section 10.9).
inline constexpr uint64_t kMcReasonUnspecifiedOther = 0x0;
inline constexpr uint64_t kMcReasonRequestedByServer = 0x1;
inline constexpr uint64_t kMcReasonAdministrativeBlock = 0x2;
inline constexpr uint64_t kMcReasonProtocolError = 0x3;
inline constexpr uint64_t kMcReasonPropertyViolation = 0x4;
inline constexpr uint64_t kMcReasonUnsynchronizedProperties = 0x5;
inline constexpr uint64_t kMcReasonIdCollision = 0x6;
inline constexpr uint64_t kMcReasonHeldDown = 0x10;
inline constexpr uint64_t kMcReasonMaxRateExceeded = 0x12;
inline constexpr uint64_t kMcReasonHighLoss = 0x13;
inline constexpr uint64_t kMcReasonExcessiveSpuriousTraffic = 0x14;
inline constexpr uint64_t kMcReasonMaxStreamsExceeded = 0x15;
inline constexpr uint64_t kMcReasonLimitViolation = 0x16;

// I1 structs. Channel IDs are raw bytes, 1 to 20 of them. Secrets are raw
// bytes too: never log header_secret or secret.
struct QUICHE_EXPORT QuicMcClientLimits {
  bool ipv4_allowed = false;
  bool ipv6_allowed = false;
  uint64_t max_rate_kibps = 0;
  uint64_t max_channel_ids = 0;
  bool operator==(const QuicMcClientLimits&) const = default;
};
struct QUICHE_EXPORT QuicMcClientParams {
  QuicMcClientLimits limits;
  std::vector<uint16_t> hash_algorithms;  // 1 = SHA-256
  std::vector<uint16_t> aead_algorithms;  // 0x1301
  bool operator==(const QuicMcClientParams&) const = default;
};
struct QUICHE_EXPORT QuicMcAnnounce {
  std::string channel_id;
  QuicIpAddress source, group;
  uint16_t port = 0;
  uint16_t header_protection_algorithm = 0;
  std::string header_secret;
  uint16_t aead_algorithm = 0;
  uint16_t integrity_hash_algorithm = 0;
  uint64_t max_rate_kibps = 0;
  uint64_t max_ack_delay_ms = 0;
  bool operator==(const QuicMcAnnounce&) const = default;
};
struct QUICHE_EXPORT QuicMcKey {
  std::string channel_id;
  uint64_t key_sequence = 0;
  uint64_t from_packet_number = 0;
  std::string secret;
  bool operator==(const QuicMcKey&) const = default;
};
struct QUICHE_EXPORT QuicMcJoin {
  std::string channel_id;
  uint64_t limits_sequence = 0;
  uint64_t state_sequence = 0;
  uint64_t key_sequence = 0;
  bool operator==(const QuicMcJoin&) const = default;
};
struct QUICHE_EXPORT QuicMcLeave {
  std::string channel_id;
  uint64_t state_sequence = 0;
  uint64_t after_packet_number = 0;
  bool operator==(const QuicMcLeave&) const = default;
};
struct QUICHE_EXPORT QuicMcIntegrity {
  std::string channel_id;
  uint64_t packet_number_start = 0;
  std::optional<uint64_t> packet_hash_count;  // set iff 0xff3e805
  std::string packet_hashes;                  // concatenated
  bool operator==(const QuicMcIntegrity&) const = default;
};
struct QUICHE_EXPORT QuicMcAckRange {
  uint64_t gap = 0;
  uint64_t length = 0;
  bool operator==(const QuicMcAckRange&) const = default;
};
struct QUICHE_EXPORT QuicMcAck {
  std::string channel_id;
  uint64_t largest_acknowledged = 0;
  uint64_t ack_delay = 0;
  uint64_t first_ack_range = 0;
  std::vector<QuicMcAckRange> ranges;
  std::optional<QuicEcnCounts> ecn;  // set => type 0xff3e807
  bool operator==(const QuicMcAck&) const = default;
};
struct QUICHE_EXPORT QuicMcLimits {
  uint64_t sequence = 0;
  QuicMcClientLimits limits;
  uint64_t max_joined_count = 0;
  bool operator==(const QuicMcLimits&) const = default;
};
struct QUICHE_EXPORT QuicMcRetire {
  std::string channel_id;
  uint64_t after_packet_number = 0;
  bool operator==(const QuicMcRetire&) const = default;
};
enum class QuicMcChannelState : uint8_t {
  kLeft = 1,
  kDeclinedJoin = 2,
  kJoined = 3,
  kRetired = 4
};
struct QUICHE_EXPORT QuicMcState {
  std::string channel_id;
  uint64_t sequence = 0;
  QuicMcChannelState state;
  bool application_reason = false;  // true => type 0xff3e80c
  uint64_t reason_code = 0;
  std::string reason_phrase;
  bool operator==(const QuicMcState&) const = default;
};

// The QUICast Firefox fork's values (FF 147cb811 neqo_glue lib.rs:388-394 and
// :876-879): IPv4 and IPv6 allowed, 100,000 Kibps, 32 channel IDs, hash {1},
// AEAD {0x1301}. Encodes to 03 800186a0 20 01 01 0001 1301.
QUICHE_EXPORT QuicMcClientParams QuicMcDefaultClientParams();

// Decoders. |reader| sits just after the type varint. On true, exactly one
// body was consumed. On false, the frame is malformed and |reader|'s position
// does not matter. Each checks every length against the bytes left.
QUICHE_EXPORT bool DecodeMcAnnounce(uint64_t frame_type, QuicDataReader* reader,
                                    QuicMcAnnounce* out);  // V4 or V6
QUICHE_EXPORT bool DecodeMcKey(QuicDataReader* reader, QuicMcKey* out);
QUICHE_EXPORT bool DecodeMcJoin(QuicDataReader* reader, QuicMcJoin* out);
QUICHE_EXPORT bool DecodeMcLeave(QuicDataReader* reader, QuicMcLeave* out);
QUICHE_EXPORT bool DecodeMcRetire(QuicDataReader* reader, QuicMcRetire* out);
// hash_len comes from the channel's ANNOUNCE (SHA-256 = 32). 0xff3e804 takes
// the rest of the packet; 0xff3e805 takes count * hash_len (Q
// multicast.rs:4904-4953). Hashes must be whole.
QUICHE_EXPORT bool DecodeMcIntegrity(uint64_t frame_type, size_t hash_len,
                                     QuicDataReader* reader,
                                     QuicMcIntegrity* out);
// The whole TP 0xff3e800 value; trailing bytes fail. Reserved flag bits are
// ignored.
QUICHE_EXPORT bool DecodeMcClientParams(absl::string_view value,
                                        QuicMcClientParams* out);
// Client-sent frames, for tests and the twin.
QUICHE_EXPORT bool DecodeMcLimits(QuicDataReader* reader, QuicMcLimits* out);
QUICHE_EXPORT bool DecodeMcState(uint64_t frame_type, QuicDataReader* reader,
                                 QuicMcState* out);
QUICHE_EXPORT bool DecodeMcAck(uint64_t frame_type, QuicDataReader* reader,
                               QuicMcAck* out);

// Encoders return the body only, with no type varint: exactly what
// WriteMulticastControlFrame (I2) takes. The type comes from the struct (see
// the comments). Every valid body is at least 2 bytes, so an empty string
// means a field cannot go on the wire: a value above 2^62-1, a channel ID
// outside 1-20 bytes, an ACK range below packet number 0, or a state and
// reason the draft forbids (JOINED and RETIRED need 0x1; a transport-scoped
// LEFT or DECLINED_JOIN needs a defined code).
QUICHE_EXPORT std::string EncodeMcLimits(const QuicMcLimits& f);  // 0xff3e809
QUICHE_EXPORT std::string EncodeMcState(const QuicMcState& f);  // ...80b or 80c
QUICHE_EXPORT std::string EncodeMcAck(const QuicMcAck& f);  // ...806 or 807
QUICHE_EXPORT std::string EncodeMcClientParams(const QuicMcClientParams& p);
// Server-sent frames, for tests. Announce also fails on mixed or unset address
// families; Integrity also fails when a count is set and the hashes are not
// count x 32 bytes, or when no count is set and they are not whole 32-byte
// hashes.
QUICHE_EXPORT std::string EncodeMcAnnounce(const QuicMcAnnounce& f);
QUICHE_EXPORT std::string EncodeMcKey(const QuicMcKey& f);
QUICHE_EXPORT std::string EncodeMcJoin(const QuicMcJoin& f);
QUICHE_EXPORT std::string EncodeMcLeave(const QuicMcLeave& f);
QUICHE_EXPORT std::string EncodeMcRetire(const QuicMcRetire& f);
QUICHE_EXPORT std::string EncodeMcIntegrity(const QuicMcIntegrity& f);

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_MULTICAST_FRAMES_H_
