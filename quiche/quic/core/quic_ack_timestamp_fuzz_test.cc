// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Fuzz tests for ACK receive timestamps (draft-ietf-quic-receive-ts): the
// serialization in QuicAckTimestampList and the parsing in QuicFramer.

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "quiche/quic/core/crypto/null_decrypter.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/frames/quic_ack_frame.h"
#include "quiche/quic/core/frames/quic_frame.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_receive_time.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {
namespace test {
namespace {

using ::fuzztest::Arbitrary;
using ::fuzztest::InRange;
using ::fuzztest::OneOf;
using ::fuzztest::StructOf;
using ::fuzztest::VectorOf;

// The largest packet number that can be encoded as a varint62.
constexpr uint64_t kMaxPacketNumber = kMaxIetfVarInt;

// Records the receive timestamps parsed by the framer.
class TimestampRecordingVisitor : public NoOpFramerVisitor {
 public:
  bool OnAckTimestamp(QuicPacketNumber packet_number,
                      QuicReceiveTime timestamp) override {
    timestamps_.emplace_back(packet_number, timestamp);
    return true;
  }

  const PacketTimeVector& timestamps() const { return timestamps_; }

 private:
  PacketTimeVector timestamps_;
};

// A pair of framers in which the client sends 1-RTT packets with null
// encryption to the server, and both sides have agreed on the same receive
// timestamp parameters.
class FramerPair {
 public:
  FramerPair(uint32_t max_timestamps, uint32_t exponent)
      : sender_({ParsedQuicVersion::RFCv1()}, QuicTime::Zero(),
                Perspective::IS_CLIENT, kQuicDefaultConnectionIdLength),
        receiver_({ParsedQuicVersion::RFCv1()}, QuicTime::Zero(),
                  Perspective::IS_SERVER, kQuicDefaultConnectionIdLength) {
    sender_.set_visitor(&sender_visitor_);
    sender_.SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(sender_.perspective()));
    sender_.set_peer_max_receive_timestamps_per_ack(max_timestamps);
    sender_.set_peer_receive_timestamps_exponent(exponent);

    receiver_.set_visitor(&receiver_visitor_);
    receiver_.InstallDecrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullDecrypter>(receiver_.perspective()));
    receiver_.set_local_max_receive_timestamps_per_ack(max_timestamps);
    receiver_.set_local_receive_timestamps_exponent(exponent);

    header_.form = IETF_QUIC_SHORT_HEADER_PACKET;
    header_.destination_connection_id = TestConnectionId();
    header_.destination_connection_id_included = CONNECTION_ID_PRESENT;
    header_.source_connection_id_included = CONNECTION_ID_ABSENT;
    header_.version_flag = false;
    header_.reset_flag = false;
    header_.packet_number = QuicPacketNumber(1);
    header_.packet_number_length = PACKET_4BYTE_PACKET_NUMBER;
  }

  QuicFramer& sender() { return sender_; }
  QuicFramer& receiver() { return receiver_; }
  const QuicPacketHeader& header() const { return header_; }
  const PacketTimeVector& received_timestamps() const {
    return receiver_visitor_.timestamps();
  }

  // Encrypts `packet` and passes it to the receiver.  Returns the result of
  // QuicFramer::ProcessPacket().
  bool EncryptAndProcess(const QuicPacket& packet) {
    char buffer[kMaxOutgoingPacketSize];
    const size_t encrypted_length =
        sender_.EncryptPayload(ENCRYPTION_FORWARD_SECURE, header_.packet_number,
                               packet, buffer, sizeof(buffer));
    QUICHE_CHECK_NE(encrypted_length, 0u);
    return receiver_.ProcessPacket(
        QuicEncryptedPacket(buffer, encrypted_length));
  }

 private:
  NoOpFramerVisitor sender_visitor_;
  TimestampRecordingVisitor receiver_visitor_;
  QuicFramer sender_;
  QuicFramer receiver_;
  QuicPacketHeader header_;
};

// A packet for which a receive timestamp has been recorded.
struct ReceivedPacket {
  uint64_t packet_number;
  // Time elapsed since the previous packet in the list has been received.
  uint64_t time_since_previous_us;
};

auto PacketNumberDomain() {
  // Small packet numbers make contiguous ranges likely; large ones exercise
  // the multi-byte varint encodings.
  return OneOf(InRange<uint64_t>(1, 128),
               InRange<uint64_t>(1, kMaxPacketNumber));
}

// Serializes a well-formed ACK frame with receive timestamps into a packet with
// `extra_space` bytes available beyond the minimum ACK frame size, parses it
// back, and checks that the timestamps received are the most recent ones sent,
// up to the rounding error allowed by `exponent`.
void TimestampsRoundTrip(const std::vector<ReceivedPacket>& received,
                         const std::vector<uint64_t>& acked_without_timestamp,
                         uint32_t max_timestamps, uint32_t exponent,
                         uint32_t ack_delay_us, bool has_ecn,
                         size_t extra_space) {
  // Build the frame the same way QuicReceivedPacketManager does: timestamps
  // are listed in the order of arrival, and every timestamped packet is
  // acknowledged.
  QuicAckFrame ack;
  QuicTimeDelta receive_time = QuicTimeDelta::Zero();
  for (const ReceivedPacket& packet : received) {
    receive_time = receive_time + QuicTimeDelta::FromMicroseconds(
                                      packet.time_since_previous_us);
    const QuicPacketNumber packet_number(packet.packet_number);
    if (ack.packets.Contains(packet_number)) {
      continue;
    }
    ack.packets.Add(packet_number);
    ack.received_packet_times.push_back(
        {packet_number, *QuicReceiveTime::FromPeerTime(receive_time)});
  }
  for (const uint64_t packet_number : acked_without_timestamp) {
    ack.packets.Add(QuicPacketNumber(packet_number));
  }
  // QuicFramer's ACK range truncation requires the ACK block count to fit in a
  // single-byte varint (< 64 additional blocks, or <= 64 total intervals).
  if (ack.packets.Empty() || ack.packets.NumIntervals() > 64) {
    return;
  }
  ack.largest_acked = ack.packets.Max();
  ack.ack_delay_time = QuicTimeDelta::FromMicroseconds(ack_delay_us);
  if (has_ecn) {
    ack.ecn_counters = QuicEcnCounts(1, 2, 3);
  }
  const PacketTimeVector& sent = ack.received_packet_times;

  FramerPair framers(max_timestamps, exponent);
  QuicFramer& sender = framers.sender();
  const QuicFrames frames = {QuicFrame(&ack)};
  const size_t header_size =
      GetPacketHeaderSize(sender.transport_version(), framers.header());
  const size_t min_frame_size = QuicFramer::GetMinAckFrameSize(
      sender.transport_version(), ack, sender.local_ack_delay_exponent(),
      /*use_ietf_ack_with_receive_timestamp=*/!sent.empty());
  const size_t available_space = std::min(
      min_frame_size + extra_space,
      sender.GetMaxPlaintextSize(kMaxOutgoingPacketSize) - header_size);

  // An ACK frame can always be serialized as long as the minimum ACK frame
  // fits.
  const size_t frame_size = sender.GetSerializedFrameLength(
      frames[0], available_space, /*first_frame=*/true, /*last_frame=*/true,
      framers.header().packet_number_length);
  ASSERT_GT(frame_size, 0u);
  ASSERT_LE(frame_size, available_space);
  std::unique_ptr<QuicPacket> packet = BuildUnsizedDataPacket(
      &sender, framers.header(), frames, header_size + frame_size);
  ASSERT_NE(packet, nullptr) << sender.detailed_error();

  ASSERT_TRUE(framers.EncryptAndProcess(*packet))
      << framers.receiver().detailed_error();
  ASSERT_EQ(framers.receiver().error(), QUIC_NO_ERROR);

  // The receiver gets the newest timestamps first.  Truncation, whether due to
  // `max_timestamps` or to the lack of space, drops the oldest ones.
  const PacketTimeVector& parsed = framers.received_timestamps();
  const size_t max_count = std::min<size_t>(sent.size(), max_timestamps);
  ASSERT_LE(parsed.size(), max_count);
  if (frame_size < available_space) {
    // The frame fit without being truncated to the available space.
    EXPECT_EQ(parsed.size(), max_count);
  }
  const QuicTimeDelta max_rounding_error =
      QuicTimeDelta::FromMicroseconds(int64_t{1} << exponent);
  for (size_t i = 0; i < parsed.size(); ++i) {
    const auto& [sent_packet_number, sent_time] = sent[sent.size() - 1 - i];
    const auto& [parsed_packet_number, parsed_time] = parsed[i];
    EXPECT_EQ(parsed_packet_number, sent_packet_number) << "i = " << i;
    // Timestamps are never rounded down, so that the receive time reported is
    // never earlier than the actual one.
    const QuicTimeDelta rounding_error = parsed_time - sent_time;
    EXPECT_GE(rounding_error, QuicTimeDelta::Zero()) << "i = " << i;
    EXPECT_LT(rounding_error, max_rounding_error) << "i = " << i;
  }
}
FUZZ_TEST(QuicAckTimestampFuzzTest, TimestampsRoundTrip)
    .WithDomains(
        /*received=*/VectorOf(
            StructOf<ReceivedPacket>(PacketNumberDomain(),
                                     InRange<uint64_t>(0, uint64_t{1} << 50)))
            .WithMaxSize(64),
        /*acked_without_timestamp=*/
        VectorOf(PacketNumberDomain()).WithMaxSize(32),
        /*max_timestamps=*/InRange<uint32_t>(1, 64),
        /*exponent=*/InRange<uint32_t>(0, kMaxReceiveTimestampsExponent),
        /*ack_delay_us=*/Arbitrary<uint32_t>(),
        /*has_ecn=*/Arbitrary<bool>(),
        /*extra_space=*/InRange<size_t>(0, 2 * kMaxOutgoingPacketSize));

// Three timestamp ranges with six timestamps in total, taken from
// QuicFramerTest.AckFrameMultipleReceiveTimestampRanges.
std::string ValidAckPayload() {
  constexpr char kPayload[] =
      "\x52\x34\x00\x00\x00"                  // ACK header
      "\x03"                                  // range count
      "\x02\x03\xa9\xff\xff\xff\x51\x11\x01"  // range 1
      "\x0b\x01\x50\x00"                      // range 2
      "\x15\x02\x10\x41\x00";                 // range 3
  return std::string(kPayload, std::size(kPayload) - 1);
}

// Passes a packet containing an ACK_RECEIVE_TIMESTAMPS frame type followed by
// `payload` to the receiver.  Returns the result of
// QuicFramer::ProcessPacket().
bool ProcessAckPayload(FramerPair& framers, const std::string& payload,
                       bool has_ecn) {
  char buffer[kMaxOutgoingPacketSize];
  QuicDataWriter writer(sizeof(buffer), buffer);
  size_t length_field_offset = 0;
  QUICHE_CHECK(framers.sender().AppendIetfPacketHeader(
      framers.header(), &writer, &length_field_offset));
  QUICHE_CHECK(writer.WriteVarInt62(has_ecn ? IETF_ACK_RECEIVE_TIMESTAMPS_ECN
                                            : IETF_ACK_RECEIVE_TIMESTAMPS));
  QUICHE_CHECK(writer.WriteBytes(payload.data(), payload.size()));
  const QuicPacket packet(framers.sender().transport_version(), buffer,
                          writer.length(), /*owns_buffer=*/false,
                          framers.header());
  return framers.EncryptAndProcess(packet);
}

class QuicAckTimestampFuzzSeedTest : public QuicTest {};

// Ensures that the packets built by ProcessAckPayload() reach the timestamp
// parser, and that the seed used below is valid.
TEST_F(QuicAckTimestampFuzzSeedTest, ValidPayloadIsParsed) {
  FramerPair framers(/*max_timestamps=*/1000, /*exponent=*/0);
  ASSERT_TRUE(ProcessAckPayload(framers, ValidAckPayload(), /*has_ecn=*/false))
      << framers.receiver().detailed_error();
  EXPECT_EQ(framers.received_timestamps().size(), 6u);
}

// Passes an ACK_RECEIVE_TIMESTAMPS frame with an arbitrary payload to the
// framer.  The payload may contain other frames after the ACK frame.
void ParserHandlesArbitraryInput(const std::string& payload, bool has_ecn,
                                 uint32_t max_timestamps, uint32_t exponent) {
  FramerPair framers(max_timestamps, exponent);
  ProcessAckPayload(framers, payload, has_ecn);
}
FUZZ_TEST(QuicAckTimestampFuzzTest, ParserHandlesArbitraryInput)
    .WithDomains(/*payload=*/Arbitrary<std::string>().WithMaxSize(1200),
                 /*has_ecn=*/Arbitrary<bool>(),
                 /*max_timestamps=*/InRange<uint32_t>(1, 1 << 16),
                 /*exponent=*/
                 InRange<uint32_t>(0, kMaxReceiveTimestampsExponent))
    .WithSeeds({{ValidAckPayload(), false, 1000, 0}});

}  // namespace
}  // namespace test
}  // namespace quic
