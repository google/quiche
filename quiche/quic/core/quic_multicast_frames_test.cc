// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_multicast_frames.h"

#include <cstdint>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace test {
namespace {

// Golden vectors: the -08 output of QUICast quiche f208164a, the engine our
// server runs (/data/scratch/quicmc-1103/plan-neqo/vectors/quiche.hex, from
// quiche-vec/src/main.rs). Channel "demo-channel", header secret 0x11 x 32,
// key secret 0x22 x 32. twin08.py checks these strings against the file.
constexpr absl::string_view kClientTransportParamsVector =
    "01800186a020010100011301";
constexpr absl::string_view kMcAnnounceVector =
    "8ff3e8110c64656d6f2d6368616e6e656cc0000201e9fc000111511301201111111111"
    "11111111111111111111111111111111111111111111111111111113010001671019";
constexpr absl::string_view kMcKeyVector =
    "8ff3e8010c64656d6f2d6368616e6e656c010020222222222222222222222222222222"
    "2222222222222222222222222222222222";
constexpr absl::string_view kMcIntegrityVector =
    "8ff3e8050c64656d6f2d6368616e6e656c000133333333333333333333333333333333"
    "33333333333333333333333333333333";
constexpr absl::string_view kMcJoinVector =
    "8ff3e8020c64656d6f2d6368616e6e656c010001";
constexpr absl::string_view kMcLeaveVector =
    "8ff3e8030c64656d6f2d6368616e6e656c0207";
constexpr absl::string_view kMcRetireVector =
    "8ff3e80a0c64656d6f2d6368616e6e656c09";
constexpr absl::string_view kMcStateVector =
    "8ff3e80b0c64656d6f2d6368616e6e656c010301066a6f696e6564";
constexpr absl::string_view kMcAckVector =
    "8ff3e8060c64656d6f2d6368616e6e656c0a000000";
// MC_INTEGRITY the engine sent for pkt_stream_off10_fin (packet number 1).
constexpr absl::string_view kPktStreamOff10FinIntegrityVector =
    "8ff3e8050c64656d6f2d6368616e6e656c01011721ad46bbdfbdc0528105def7a22bf7"
    "6a1dded9c4f2439da2db590eaf318ee3";

// No generated vector yet (C10 adds MC_LIMITS and MC_ACK_ECN). These follow
// the Rust encoders field by field (Q multicast.rs:1102-1107 and :206-213;
// fork neqo mcquic mod.rs:1551-1555), and twin08.py checks them.
// MC_LIMITS as the fork sends it: sequence 1, max_joined = max_channel_ids.
constexpr absl::string_view kMcLimitsDerived = "8ff3e8090103800186a02020";
constexpr absl::string_view kMcAckEcnDerived =
    "8ff3e8070c64656d6f2d6368616e6e656c0a0101000001040100";
constexpr absl::string_view kMcStateApplicationDerived =
    "8ff3e80c0c64656d6f2d6368616e6e656c02022a00";
constexpr absl::string_view kMcIntegrityToEndDerived =
    "8ff3e8040c64656d6f2d6368616e6e656c0033333333333333333333333333333333"
    "33333333333333333333333333333333";

constexpr absl::string_view kChannel = "demo-channel";

std::string FromHex(absl::string_view hex) {
  std::string bytes;
  EXPECT_TRUE(absl::HexStringToBytes(hex, &bytes)) << hex;
  return bytes;
}

QuicIpAddress Ip(absl::string_view text) {
  QuicIpAddress address;
  EXPECT_TRUE(address.FromString(std::string(text))) << text;
  return address;
}

// The type varint followed by |body|: the form the vectors hold, and what the
// framer writes for a QuicMulticastControlFrame.
std::string WithType(uint64_t type, absl::string_view body) {
  std::string out(8 + body.size(), '\0');
  QuicDataWriter writer(out.size(), out.data());
  EXPECT_TRUE(writer.WriteVarInt62(type) && writer.WriteStringPiece(body));
  out.resize(writer.length());
  return out;
}

// A frame's bytes and a reader just after its type varint, as the framer hook
// hands it over.
class Body {
 public:
  explicit Body(absl::string_view hex) : bytes_(FromHex(hex)), reader_(bytes_) {
    EXPECT_TRUE(reader_.ReadVarInt62(&type_));
  }
  uint64_t type() const { return type_; }
  QuicDataReader* reader() { return &reader_; }
  bool done() const { return reader_.IsDoneReading(); }

 private:
  std::string bytes_;
  QuicDataReader reader_;
  uint64_t type_ = 0;
};

// Byte-exact both ways: struct to vector, and vector to struct with the body
// consumed exactly.
template <typename T, typename DecodeFn>
void ExpectVector(absl::string_view hex, uint64_t type, const T& frame,
                  absl::string_view encoded_body, DecodeFn decode) {
  EXPECT_EQ(WithType(type, encoded_body), FromHex(hex)) << hex;
  Body body(hex);
  ASSERT_EQ(body.type(), type);
  EXPECT_TRUE(IsMcFrameType(type));
  T decoded{};
  ASSERT_TRUE(decode(type, body.reader(), &decoded)) << hex;
  EXPECT_TRUE(body.done()) << hex;
  EXPECT_EQ(decoded, frame) << hex;
}

const auto kAnnounce = [](uint64_t t, QuicDataReader* r, QuicMcAnnounce* f) {
  return DecodeMcAnnounce(t, r, f);
};
const auto kKey = [](uint64_t, QuicDataReader* r, QuicMcKey* f) {
  return DecodeMcKey(r, f);
};
const auto kJoin = [](uint64_t, QuicDataReader* r, QuicMcJoin* f) {
  return DecodeMcJoin(r, f);
};
const auto kLeave = [](uint64_t, QuicDataReader* r, QuicMcLeave* f) {
  return DecodeMcLeave(r, f);
};
const auto kRetire = [](uint64_t, QuicDataReader* r, QuicMcRetire* f) {
  return DecodeMcRetire(r, f);
};
const auto kIntegrity = [](uint64_t t, QuicDataReader* r, QuicMcIntegrity* f) {
  return DecodeMcIntegrity(t, kMcSha256HashLength, r, f);
};
const auto kLimits = [](uint64_t, QuicDataReader* r, QuicMcLimits* f) {
  return DecodeMcLimits(r, f);
};
const auto kState = [](uint64_t t, QuicDataReader* r, QuicMcState* f) {
  return DecodeMcState(t, r, f);
};
const auto kAck = [](uint64_t t, QuicDataReader* r, QuicMcAck* f) {
  return DecodeMcAck(t, r, f);
};

QuicMcAnnounce VectorAnnounce() {
  QuicMcAnnounce f;
  f.channel_id = std::string(kChannel);
  f.source = Ip("192.0.2.1");
  f.group = Ip("233.252.0.1");
  f.port = 4433;
  f.header_protection_algorithm = kMcAes128GcmSha256;
  f.header_secret = std::string(32, '\x11');
  f.aead_algorithm = kMcAes128GcmSha256;
  f.integrity_hash_algorithm = kMcHashSha256;
  f.max_rate_kibps = 10'000;
  f.max_ack_delay_ms = 25;
  return f;
}

QuicMcKey VectorKey() {
  return QuicMcKey{std::string(kChannel), 1, 0, std::string(32, '\x22')};
}

QuicMcJoin VectorJoin() { return QuicMcJoin{std::string(kChannel), 1, 0, 1}; }

QuicMcAck VectorAck() {
  QuicMcAck f;
  f.channel_id = std::string(kChannel);
  f.largest_acknowledged = 10;
  return f;
}

QuicMcState State(absl::string_view channel, uint64_t sequence,
                  QuicMcChannelState state, bool application, uint64_t code,
                  absl::string_view phrase) {
  QuicMcState f;
  f.channel_id = std::string(channel);
  f.sequence = sequence;
  f.state = state;
  f.application_reason = application;
  f.reason_code = code;
  f.reason_phrase = std::string(phrase);
  return f;
}

class QuicMulticastFramesTest : public QuicTest {};

TEST_F(QuicMulticastFramesTest, ClientParamsVector) {
  QuicMcClientParams params = QuicMcDefaultClientParams();
  params.limits.ipv6_allowed = false;  // as quiche-vec built it
  EXPECT_EQ(EncodeMcClientParams(params), FromHex(kClientTransportParamsVector));
  QuicMcClientParams decoded;
  ASSERT_TRUE(
      DecodeMcClientParams(FromHex(kClientTransportParamsVector), &decoded));
  EXPECT_EQ(decoded, params);
}

TEST_F(QuicMulticastFramesTest, DefaultClientParamsAreTheForks) {
  const std::string fork = FromHex("03800186a020010100011301");
  EXPECT_EQ(EncodeMcClientParams(QuicMcDefaultClientParams()), fork);
  QuicMcClientParams decoded;
  ASSERT_TRUE(DecodeMcClientParams(fork, &decoded));
  EXPECT_EQ(decoded, QuicMcDefaultClientParams());
}

TEST_F(QuicMulticastFramesTest, ClientParamsRejectMalformed) {
  const std::string good = FromHex(kClientTransportParamsVector);
  QuicMcClientParams p;
  EXPECT_FALSE(DecodeMcClientParams(good + "x", &p));
  EXPECT_FALSE(DecodeMcClientParams(good.substr(0, good.size() - 1), &p));
  // A list count larger than the bytes left.
  EXPECT_FALSE(DecodeMcClientParams(FromHex("010000050100011301"), &p));
  // Reserved bits are ignored on receipt.
  ASSERT_TRUE(DecodeMcClientParams(FromHex("fd800186a020010100011301"), &p));
  EXPECT_TRUE(p.limits.ipv4_allowed);
  EXPECT_FALSE(p.limits.ipv6_allowed);
}

TEST_F(QuicMulticastFramesTest, AnnounceVector) {
  ExpectVector(kMcAnnounceVector, kMcAnnounceV4, VectorAnnounce(),
               EncodeMcAnnounce(VectorAnnounce()), kAnnounce);
}

TEST_F(QuicMulticastFramesTest, KeyVector) {
  ExpectVector(kMcKeyVector, kMcKey, VectorKey(), EncodeMcKey(VectorKey()),
               kKey);
}

TEST_F(QuicMulticastFramesTest, IntegrityVector) {
  const QuicMcIntegrity f{std::string(kChannel), 0, 1, std::string(32, '\x33')};
  ExpectVector(kMcIntegrityVector, kMcIntegrityWithLength, f,
               EncodeMcIntegrity(f), kIntegrity);
}

TEST_F(QuicMulticastFramesTest, JoinVector) {
  ExpectVector(kMcJoinVector, kMcJoin, VectorJoin(), EncodeMcJoin(VectorJoin()),
               kJoin);
}

TEST_F(QuicMulticastFramesTest, LeaveVector) {
  const QuicMcLeave f{std::string(kChannel), 2, 7};
  ExpectVector(kMcLeaveVector, kMcLeave, f, EncodeMcLeave(f), kLeave);
}

TEST_F(QuicMulticastFramesTest, RetireVector) {
  const QuicMcRetire f{std::string(kChannel), 9};
  ExpectVector(kMcRetireVector, kMcRetire, f, EncodeMcRetire(f), kRetire);
}

TEST_F(QuicMulticastFramesTest, StateVector) {
  const QuicMcState f = State(kChannel, 1, QuicMcChannelState::kJoined, false,
                              kMcReasonRequestedByServer, "joined");
  ExpectVector(kMcStateVector, kMcState, f, EncodeMcState(f), kState);
}

TEST_F(QuicMulticastFramesTest, AckVector) {
  ExpectVector(kMcAckVector, kMcAck, VectorAck(), EncodeMcAck(VectorAck()),
               kAck);
}

TEST_F(QuicMulticastFramesTest, PacketIntegrityVector) {
  Body body(kPktStreamOff10FinIntegrityVector);
  QuicMcIntegrity f;
  ASSERT_TRUE(DecodeMcIntegrity(body.type(), kMcSha256HashLength,
                                body.reader(), &f));
  EXPECT_TRUE(body.done());
  EXPECT_EQ(f.packet_number_start, 1u);
  EXPECT_EQ(f.packet_hash_count, 1u);
  EXPECT_EQ(f.packet_hashes.size(), kMcSha256HashLength);
}

TEST_F(QuicMulticastFramesTest, DerivedLimits) {
  const QuicMcLimits f{1, QuicMcDefaultClientParams().limits, 32};
  ExpectVector(kMcLimitsDerived, kMcLimits, f, EncodeMcLimits(f), kLimits);
}

TEST_F(QuicMulticastFramesTest, DerivedAckEcnWithRange) {
  // Acknowledges 10, then 7-8 (gap 0 skips 9), with ECT0 4, ECT1 1, CE 0.
  QuicMcAck f = VectorAck();
  f.ack_delay = 1;
  f.ranges = {{0, 1}};
  f.ecn = QuicEcnCounts(4, 1, 0);
  ExpectVector(kMcAckEcnDerived, kMcAckEcn, f, EncodeMcAck(f), kAck);
}

TEST_F(QuicMulticastFramesTest, DerivedApplicationState) {
  const QuicMcState f =
      State(kChannel, 2, QuicMcChannelState::kDeclinedJoin, true, 0x2a, "");
  ExpectVector(kMcStateApplicationDerived, kMcStateApplication, f,
               EncodeMcState(f), kState);
}

TEST_F(QuicMulticastFramesTest, DerivedIntegrityToPacketEnd) {
  const QuicMcIntegrity f{std::string(kChannel), 0, std::nullopt,
                          std::string(32, '\x33')};
  ExpectVector(kMcIntegrityToEndDerived, kMcIntegrity, f, EncodeMcIntegrity(f),
               kIntegrity);
}

TEST_F(QuicMulticastFramesTest, AnnounceV6RoundTrip) {
  QuicMcAnnounce f = VectorAnnounce();
  f.source = Ip("2001:db8::1");
  f.group = Ip("ff3e::8000:1");
  const std::string bytes = WithType(kMcAnnounceV6, EncodeMcAnnounce(f));
  Body body(absl::BytesToHexString(bytes));
  QuicMcAnnounce decoded;
  ASSERT_TRUE(DecodeMcAnnounce(body.type(), body.reader(), &decoded));
  EXPECT_TRUE(body.done());
  EXPECT_EQ(decoded, f);
}

// The framer hook hands over a reader positioned after the type varint, with
// more frames behind it. Each decoder must stop at its own frame's end.
TEST_F(QuicMulticastFramesTest, DecodersStopAtTheirFrameEnd) {
  const std::string packet = FromHex(kMcAnnounceVector) +
                             FromHex(kMcKeyVector) + FromHex(kMcJoinVector);
  QuicDataReader reader(packet);
  uint64_t type;
  QuicMcAnnounce announce;
  QuicMcKey key;
  QuicMcJoin join;
  ASSERT_TRUE(reader.ReadVarInt62(&type));
  ASSERT_TRUE(DecodeMcAnnounce(type, &reader, &announce));
  ASSERT_TRUE(reader.ReadVarInt62(&type));
  ASSERT_TRUE(DecodeMcKey(&reader, &key));
  ASSERT_TRUE(reader.ReadVarInt62(&type));
  ASSERT_TRUE(DecodeMcJoin(&reader, &join));
  EXPECT_TRUE(reader.IsDoneReading());
  EXPECT_EQ(announce, VectorAnnounce());
  EXPECT_EQ(key, VectorKey());
  EXPECT_EQ(join, VectorJoin());
}

TEST_F(QuicMulticastFramesTest, RejectsMalformedServerFrames) {
  QuicMcJoin join;
  QuicMcRetire retire;
  QuicMcIntegrity integrity;
  QuicMcAck ack;
  {  // Truncated.
    const std::string hex(kMcJoinVector.substr(0, kMcJoinVector.size() - 2));
    Body body(hex);
    EXPECT_FALSE(DecodeMcJoin(body.reader(), &join));
  }
  EXPECT_FALSE(IsMcFrameType(0xff3e810));
  EXPECT_FALSE(IsMcFrameType(0x08));
  {  // Channel ID of length 0.
    Body body("8ff3e80a0009");
    EXPECT_FALSE(DecodeMcRetire(body.reader(), &retire));
  }
  {  // Channel ID of length 21.
    Body body("8ff3e80a15" + std::string(42, 'a') + "09");
    EXPECT_FALSE(DecodeMcRetire(body.reader(), &retire));
  }
  {  // MC_INTEGRITY count whose byte length overflows.
    Body body("8ff3e8050161" "00" "ffffffffffffffff");
    EXPECT_FALSE(DecodeMcIntegrity(body.type(), kMcSha256HashLength,
                                   body.reader(), &integrity));
  }
  {  // MC_INTEGRITY to packet end with a partial hash.
    Body body("8ff3e8040161" "00" + std::string(62, '3'));
    EXPECT_FALSE(DecodeMcIntegrity(body.type(), kMcSha256HashLength,
                                   body.reader(), &integrity));
  }
  {  // MC_ACK range count larger than the bytes left.
    Body body("8ff3e8060161" "0a00" "8000ffff" "00");
    EXPECT_FALSE(DecodeMcAck(body.type(), body.reader(), &ack));
  }
  {  // A decoder handed the wrong type.
    Body body(kMcRetireVector);
    QuicMcAnnounce announce;
    EXPECT_FALSE(DecodeMcAnnounce(body.type(), body.reader(), &announce));
  }
}

TEST_F(QuicMulticastFramesTest, RejectsInvalidState) {
  const std::string prefix = "8ff3e80b0161" "01";
  QuicMcState state;
  for (absl::string_view rest : {"000100", "050100", "030000", "010700"}) {
    Body body(prefix + std::string(rest));
    EXPECT_FALSE(DecodeMcState(body.type(), body.reader(), &state)) << rest;
  }
  Body ok(prefix + "010500");
  EXPECT_TRUE(DecodeMcState(ok.type(), ok.reader(), &state));
  EXPECT_EQ(EncodeMcState(State("a", 1, QuicMcChannelState::kJoined, false, 0,
                                "")),
            "");
}

TEST_F(QuicMulticastFramesTest, RefusesUnencodableFrames) {
  QuicMcAnnounce mixed = VectorAnnounce();
  mixed.group = Ip("ff3e::1");
  EXPECT_EQ(EncodeMcAnnounce(mixed), "");
  EXPECT_EQ(EncodeMcAnnounce(QuicMcAnnounce{}), "");
  EXPECT_EQ(EncodeMcRetire(QuicMcRetire{std::string(21, 'a'), 0}), "");
  EXPECT_EQ(EncodeMcRetire(QuicMcRetire{"", 0}), "");
  EXPECT_EQ(EncodeMcRetire(QuicMcRetire{"a", uint64_t{1} << 62}), "");
  EXPECT_EQ(EncodeMcIntegrity(QuicMcIntegrity{"a", 0, 1, std::string(31, 'x')}),
            "");
  EXPECT_EQ(EncodeMcIntegrity(QuicMcIntegrity{"a", 0, 2, std::string(32, 'x')}),
            "");
  QuicMcAck ack = VectorAck();
  ack.first_ack_range = 11;  // below packet number 0
  EXPECT_EQ(EncodeMcAck(ack), "");
  ack.first_ack_range = 0;
  ack.ranges = {{9, 0}};  // 10 - 0 - 9 - 2 < 0
  EXPECT_EQ(EncodeMcAck(ack), "");
}

}  // namespace
}  // namespace test
}  // namespace quic
