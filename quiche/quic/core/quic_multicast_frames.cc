// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_multicast_frames.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_ip_address.h"

namespace quic {

namespace {

constexpr uint8_t kIpv4AllowedFlag = 0x01;
constexpr uint8_t kIpv6AllowedFlag = 0x02;

// Bytes of every fixed field of the largest body, each varint at its 8-byte
// maximum. Callers add their variable-length fields.
constexpr size_t kFixedFieldBound = 128;

// Runs |write| on a buffer of kFixedFieldBound + |variable_bytes|. Returns the
// written bytes, or an empty string if any write failed.
template <typename WriteFn>
std::string Encode(size_t variable_bytes, WriteFn write) {
  std::string buffer(kFixedFieldBound + variable_bytes, '\0');
  QuicDataWriter writer(buffer.size(), buffer.data());
  if (!write(&writer)) {
    return "";
  }
  buffer.resize(writer.length());
  return buffer;
}

bool ValidChannelId(absl::string_view id) {
  return !id.empty() && id.size() <= kMcMaxChannelIdLength;
}

bool ReadChannelId(QuicDataReader* reader, std::string* id) {
  absl::string_view value;
  if (!reader->ReadStringPiece8(&value) || !ValidChannelId(value)) {
    return false;
  }
  *id = std::string(value);
  return true;
}

bool WriteChannelId(absl::string_view id, QuicDataWriter* writer) {
  return ValidChannelId(id) &&
         writer->WriteUInt8(static_cast<uint8_t>(id.size())) &&
         writer->WriteStringPiece(id);
}

bool ReadIp(QuicDataReader* reader, size_t length, QuicIpAddress* address) {
  absl::string_view packed;
  return reader->ReadStringPiece(&packed, length) &&
         address->FromPackedString(packed.data(), packed.size());
}

bool ReadBytesVarInt62(QuicDataReader* reader, std::string* out) {
  absl::string_view value;
  if (!reader->ReadStringPieceVarInt62(&value)) {
    return false;
  }
  *out = std::string(value);
  return true;
}

// The six reserved bits are ignored on receipt (-08 section 10.7).
bool ReadLimits(QuicDataReader* reader, QuicMcClientLimits* limits) {
  uint8_t flags;
  if (!reader->ReadUInt8(&flags)) {
    return false;
  }
  limits->ipv4_allowed = (flags & kIpv4AllowedFlag) != 0;
  limits->ipv6_allowed = (flags & kIpv6AllowedFlag) != 0;
  return reader->ReadVarInt62(&limits->max_rate_kibps) &&
         reader->ReadVarInt62(&limits->max_channel_ids);
}

bool WriteLimits(const QuicMcClientLimits& limits, QuicDataWriter* writer) {
  const uint8_t flags = (limits.ipv6_allowed ? kIpv6AllowedFlag : 0) |
                        (limits.ipv4_allowed ? kIpv4AllowedFlag : 0);
  return writer->WriteUInt8(flags) &&
         writer->WriteVarInt62(limits.max_rate_kibps) &&
         writer->WriteVarInt62(limits.max_channel_ids);
}

bool ReadU16List(QuicDataReader* reader, uint64_t count,
                 std::vector<uint16_t>* out) {
  if (count > reader->BytesRemaining() / 2) {
    return false;
  }
  out->resize(count);
  for (uint16_t& value : *out) {
    if (!reader->ReadUInt16(&value)) {
      return false;
    }
  }
  return true;
}

bool WriteU16List(const std::vector<uint16_t>& values,
                  QuicDataWriter* writer) {
  for (uint16_t value : values) {
    if (!writer->WriteUInt16(value)) {
      return false;
    }
  }
  return true;
}

// -08 section 10.9: JOINED and RETIRED carry REQUESTED_BY_SERVER in either
// scope; a transport-scoped LEFT or DECLINED_JOIN carries a defined code.
bool ValidStateReason(QuicMcChannelState state, bool application_reason,
                      uint64_t code) {
  switch (state) {
    case QuicMcChannelState::kJoined:
    case QuicMcChannelState::kRetired:
      return code == kMcReasonRequestedByServer;
    case QuicMcChannelState::kLeft:
    case QuicMcChannelState::kDeclinedJoin:
      return application_reason || code <= kMcReasonIdCollision ||
             code == kMcReasonHeldDown ||
             (code >= kMcReasonMaxRateExceeded &&
              code <= kMcReasonLimitViolation);
  }
  return false;  // an undefined state byte
}

// Every range must stay at or above packet number 0 (RFC 9000 19.3.1).
bool ValidAckStructure(const QuicMcAck& f) {
  if (f.first_ack_range > f.largest_acknowledged) {
    return false;
  }
  uint64_t smallest = f.largest_acknowledged - f.first_ack_range;
  for (const QuicMcAckRange& range : f.ranges) {
    if (range.gap > quiche::kVarInt62MaxValue || smallest < range.gap + 2) {
      return false;
    }
    const uint64_t largest = smallest - range.gap - 2;
    if (range.length > largest) {
      return false;
    }
    smallest = largest - range.length;
  }
  return true;
}

}  // namespace

bool IsMcFrameType(uint64_t frame_type) {
  switch (frame_type) {
    case kMcKey:
    case kMcJoin:
    case kMcLeave:
    case kMcIntegrity:
    case kMcIntegrityWithLength:
    case kMcAck:
    case kMcAckEcn:
    case kMcLimits:
    case kMcRetire:
    case kMcState:
    case kMcStateApplication:
    case kMcAnnounceV4:
    case kMcAnnounceV6:
      return true;
    default:
      return false;
  }
}

QuicMcClientParams QuicMcDefaultClientParams() {
  QuicMcClientParams params;
  params.limits.ipv4_allowed = true;
  params.limits.ipv6_allowed = true;
  params.limits.max_rate_kibps = 100'000;
  params.limits.max_channel_ids = 32;
  params.hash_algorithms = {kMcHashSha256};
  params.aead_algorithms = {kMcAes128GcmSha256};
  return params;
}

// Decoders, in -08 field order.

bool DecodeMcAnnounce(uint64_t frame_type, QuicDataReader* reader,
                      QuicMcAnnounce* out) {
  if (frame_type != kMcAnnounceV4 && frame_type != kMcAnnounceV6) {
    return false;
  }
  const size_t address_length = frame_type == kMcAnnounceV4 ? 4 : 16;
  return ReadChannelId(reader, &out->channel_id) &&
         ReadIp(reader, address_length, &out->source) &&
         ReadIp(reader, address_length, &out->group) &&
         reader->ReadUInt16(&out->port) &&
         reader->ReadUInt16(&out->header_protection_algorithm) &&
         ReadBytesVarInt62(reader, &out->header_secret) &&
         reader->ReadUInt16(&out->aead_algorithm) &&
         reader->ReadUInt16(&out->integrity_hash_algorithm) &&
         reader->ReadVarInt62(&out->max_rate_kibps) &&
         reader->ReadVarInt62(&out->max_ack_delay_ms);
}

bool DecodeMcKey(QuicDataReader* reader, QuicMcKey* out) {
  return ReadChannelId(reader, &out->channel_id) &&
         reader->ReadVarInt62(&out->key_sequence) &&
         reader->ReadVarInt62(&out->from_packet_number) &&
         ReadBytesVarInt62(reader, &out->secret);
}

bool DecodeMcJoin(QuicDataReader* reader, QuicMcJoin* out) {
  return ReadChannelId(reader, &out->channel_id) &&
         reader->ReadVarInt62(&out->limits_sequence) &&
         reader->ReadVarInt62(&out->state_sequence) &&
         reader->ReadVarInt62(&out->key_sequence);
}

bool DecodeMcLeave(QuicDataReader* reader, QuicMcLeave* out) {
  return ReadChannelId(reader, &out->channel_id) &&
         reader->ReadVarInt62(&out->state_sequence) &&
         reader->ReadVarInt62(&out->after_packet_number);
}

bool DecodeMcRetire(QuicDataReader* reader, QuicMcRetire* out) {
  return ReadChannelId(reader, &out->channel_id) &&
         reader->ReadVarInt62(&out->after_packet_number);
}

bool DecodeMcIntegrity(uint64_t frame_type, size_t hash_len,
                       QuicDataReader* reader, QuicMcIntegrity* out) {
  if ((frame_type != kMcIntegrity && frame_type != kMcIntegrityWithLength) ||
      hash_len == 0 || !ReadChannelId(reader, &out->channel_id) ||
      !reader->ReadVarInt62(&out->packet_number_start)) {
    return false;
  }
  absl::string_view hashes;
  if (frame_type == kMcIntegrityWithLength) {
    uint64_t count;
    if (!reader->ReadVarInt62(&count) ||
        count > reader->BytesRemaining() / hash_len ||
        !reader->ReadStringPiece(&hashes, count * hash_len)) {
      return false;
    }
    out->packet_hash_count = count;
  } else {
    hashes = reader->ReadRemainingPayload();
    if (hashes.size() % hash_len != 0) {
      return false;
    }
    out->packet_hash_count.reset();
  }
  out->packet_hashes = std::string(hashes);
  return true;
}

bool DecodeMcClientParams(absl::string_view value, QuicMcClientParams* out) {
  QuicDataReader reader(value);
  uint64_t hash_count, aead_count;
  return ReadLimits(&reader, &out->limits) &&
         reader.ReadVarInt62(&hash_count) &&
         reader.ReadVarInt62(&aead_count) &&
         ReadU16List(&reader, hash_count, &out->hash_algorithms) &&
         ReadU16List(&reader, aead_count, &out->aead_algorithms) &&
         reader.IsDoneReading();
}

bool DecodeMcLimits(QuicDataReader* reader, QuicMcLimits* out) {
  return reader->ReadVarInt62(&out->sequence) &&
         ReadLimits(reader, &out->limits) &&
         reader->ReadVarInt62(&out->max_joined_count);
}

bool DecodeMcState(uint64_t frame_type, QuicDataReader* reader,
                   QuicMcState* out) {
  uint8_t state;
  if ((frame_type != kMcState && frame_type != kMcStateApplication) ||
      !ReadChannelId(reader, &out->channel_id) ||
      !reader->ReadVarInt62(&out->sequence) || !reader->ReadUInt8(&state)) {
    return false;
  }
  out->state = static_cast<QuicMcChannelState>(state);
  out->application_reason = frame_type == kMcStateApplication;
  return reader->ReadVarInt62(&out->reason_code) &&
         ReadBytesVarInt62(reader, &out->reason_phrase) &&
         ValidStateReason(out->state, out->application_reason,
                          out->reason_code);
}

bool DecodeMcAck(uint64_t frame_type, QuicDataReader* reader, QuicMcAck* out) {
  uint64_t range_count;
  if ((frame_type != kMcAck && frame_type != kMcAckEcn) ||
      !ReadChannelId(reader, &out->channel_id) ||
      !reader->ReadVarInt62(&out->largest_acknowledged) ||
      !reader->ReadVarInt62(&out->ack_delay) ||
      !reader->ReadVarInt62(&range_count) ||
      !reader->ReadVarInt62(&out->first_ack_range) ||
      range_count > reader->BytesRemaining() / 2) {
    return false;
  }
  out->ranges.resize(range_count);
  for (QuicMcAckRange& range : out->ranges) {
    if (!reader->ReadVarInt62(&range.gap) ||
        !reader->ReadVarInt62(&range.length)) {
      return false;
    }
  }
  out->ecn.reset();
  if (frame_type == kMcAckEcn) {
    QuicEcnCounts ecn;
    if (!reader->ReadVarInt62(&ecn.ect0) || !reader->ReadVarInt62(&ecn.ect1) ||
        !reader->ReadVarInt62(&ecn.ce)) {
      return false;
    }
    out->ecn = ecn;
  }
  return true;
}

// Encoders: bodies only, in -08 field order.

std::string EncodeMcLimits(const QuicMcLimits& f) {
  return Encode(0, [&](QuicDataWriter* w) {
    return w->WriteVarInt62(f.sequence) && WriteLimits(f.limits, w) &&
           w->WriteVarInt62(f.max_joined_count);
  });
}

std::string EncodeMcState(const QuicMcState& f) {
  return Encode(f.reason_phrase.size(), [&](QuicDataWriter* w) {
    return ValidStateReason(f.state, f.application_reason, f.reason_code) &&
           WriteChannelId(f.channel_id, w) && w->WriteVarInt62(f.sequence) &&
           w->WriteUInt8(static_cast<uint8_t>(f.state)) &&
           w->WriteVarInt62(f.reason_code) &&
           w->WriteStringPieceVarInt62(f.reason_phrase);
  });
}

std::string EncodeMcAck(const QuicMcAck& f) {
  return Encode(16 * f.ranges.size(), [&](QuicDataWriter* w) {
    if (!ValidAckStructure(f) || !WriteChannelId(f.channel_id, w) ||
        !w->WriteVarInt62(f.largest_acknowledged) ||
        !w->WriteVarInt62(f.ack_delay) || !w->WriteVarInt62(f.ranges.size()) ||
        !w->WriteVarInt62(f.first_ack_range)) {
      return false;
    }
    for (const QuicMcAckRange& range : f.ranges) {
      if (!w->WriteVarInt62(range.gap) || !w->WriteVarInt62(range.length)) {
        return false;
      }
    }
    return !f.ecn.has_value() ||
           (w->WriteVarInt62(f.ecn->ect0) && w->WriteVarInt62(f.ecn->ect1) &&
            w->WriteVarInt62(f.ecn->ce));
  });
}

std::string EncodeMcClientParams(const QuicMcClientParams& p) {
  return Encode(2 * (p.hash_algorithms.size() + p.aead_algorithms.size()),
                [&](QuicDataWriter* w) {
                  return WriteLimits(p.limits, w) &&
                         w->WriteVarInt62(p.hash_algorithms.size()) &&
                         w->WriteVarInt62(p.aead_algorithms.size()) &&
                         WriteU16List(p.hash_algorithms, w) &&
                         WriteU16List(p.aead_algorithms, w);
                });
}

std::string EncodeMcAnnounce(const QuicMcAnnounce& f) {
  return Encode(f.header_secret.size(), [&](QuicDataWriter* w) {
    const bool v4 = f.source.IsIPv4() && f.group.IsIPv4();
    const bool v6 = f.source.IsIPv6() && f.group.IsIPv6();
    return (v4 || v6) && WriteChannelId(f.channel_id, w) &&
           w->WriteStringPiece(f.source.ToPackedString()) &&
           w->WriteStringPiece(f.group.ToPackedString()) &&
           w->WriteUInt16(f.port) &&
           w->WriteUInt16(f.header_protection_algorithm) &&
           w->WriteStringPieceVarInt62(f.header_secret) &&
           w->WriteUInt16(f.aead_algorithm) &&
           w->WriteUInt16(f.integrity_hash_algorithm) &&
           w->WriteVarInt62(f.max_rate_kibps) &&
           w->WriteVarInt62(f.max_ack_delay_ms);
  });
}

std::string EncodeMcKey(const QuicMcKey& f) {
  return Encode(f.secret.size(), [&](QuicDataWriter* w) {
    return WriteChannelId(f.channel_id, w) && w->WriteVarInt62(f.key_sequence) &&
           w->WriteVarInt62(f.from_packet_number) &&
           w->WriteStringPieceVarInt62(f.secret);
  });
}

std::string EncodeMcJoin(const QuicMcJoin& f) {
  return Encode(0, [&](QuicDataWriter* w) {
    return WriteChannelId(f.channel_id, w) &&
           w->WriteVarInt62(f.limits_sequence) &&
           w->WriteVarInt62(f.state_sequence) &&
           w->WriteVarInt62(f.key_sequence);
  });
}

std::string EncodeMcLeave(const QuicMcLeave& f) {
  return Encode(0, [&](QuicDataWriter* w) {
    return WriteChannelId(f.channel_id, w) &&
           w->WriteVarInt62(f.state_sequence) &&
           w->WriteVarInt62(f.after_packet_number);
  });
}

std::string EncodeMcRetire(const QuicMcRetire& f) {
  return Encode(0, [&](QuicDataWriter* w) {
    return WriteChannelId(f.channel_id, w) &&
           w->WriteVarInt62(f.after_packet_number);
  });
}

// ponytail: hashes are sized for hash 1 (SHA-256), the only one offered.
std::string EncodeMcIntegrity(const QuicMcIntegrity& f) {
  const bool whole =
      f.packet_hash_count.has_value()
          ? *f.packet_hash_count <=
                    f.packet_hashes.size() / kMcSha256HashLength &&
                *f.packet_hash_count * kMcSha256HashLength ==
                    f.packet_hashes.size()
          : f.packet_hashes.size() % kMcSha256HashLength == 0;
  return Encode(f.packet_hashes.size(), [&](QuicDataWriter* w) {
    return whole && WriteChannelId(f.channel_id, w) &&
           w->WriteVarInt62(f.packet_number_start) &&
           (!f.packet_hash_count.has_value() ||
            w->WriteVarInt62(*f.packet_hash_count)) &&
           w->WriteStringPiece(f.packet_hashes);
  });
}

}  // namespace quic
