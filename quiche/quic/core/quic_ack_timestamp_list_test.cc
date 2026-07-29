// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_ack_timestamp_list.h"

#include <cstdint>
#include <string>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/frames/quic_ack_frame.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_text_utils.h"

namespace quic::test {
namespace {

class QuicAckTimestampListTest : public quiche::test::QuicheTest {
 protected:
  QuicAckTimestampListTest()
      : basis_(QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1000)) {}

  QuicTime TimePlus(uint64_t offset_us) {
    return basis_ + QuicTime::Delta::FromMicroseconds(offset_us);
  }

  void ExpectBinaryEncoding(const QuicAckTimestampList& list,
                            absl::string_view hex) {
    std::string expected;
    ASSERT_TRUE(absl::HexStringToBytes(hex, &expected));
    EXPECT_EQ(list.MaxEncodedSize(), expected.size());

    std::string buffer(list.MaxEncodedSize(), '\0');
    QuicDataWriter writer(buffer.size(), buffer.data());
    EXPECT_TRUE(list.Write(writer));
    EXPECT_EQ(writer.remaining(), 0u);

    EXPECT_EQ(expected, buffer) << quiche::QuicheTextUtils::HexDump(buffer);
  }

  QuicAckFrame ack_;
  QuicTime basis_;
};

TEST_F(QuicAckTimestampListTest, EmptyList) {
  ack_.largest_acked = QuicPacketNumber(100);
  QuicAckTimestampList list(ack_, /*max_ack_count=*/100, /*exponent=*/0,
                            basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       // Range count = 0
                       "00");
}

// Based on Section 8, Table 1 of draft-ietf-quic-receive-ts-02.
TEST_F(QuicAckTimestampListTest, DraftExampleTable1) {
  ack_.largest_acked = QuicPacketNumber(100);
  ack_.received_packet_times = {
      {QuicPacketNumber(87), TimePlus(300)},
      {QuicPacketNumber(88), TimePlus(305)},
      {QuicPacketNumber(89), TimePlus(310)},
      {QuicPacketNumber(90), TimePlus(320)},
      {QuicPacketNumber(91), TimePlus(330)},
      {QuicPacketNumber(96), TimePlus(350)},
      {QuicPacketNumber(97), TimePlus(355)},
      {QuicPacketNumber(98), TimePlus(360)},
      {QuicPacketNumber(99), TimePlus(370)},
      {QuicPacketNumber(100), TimePlus(380)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/100, /*exponent=*/0,
                            basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       "02"            // Range count = 2
                                       // ------------ Range 1 ------------
                       "00"            // Delta largest acked = 0
                       "05"            // Count = 5
                       "417c0a0a0505"  // Deltas = 380, 10, 10, 5, 5
                                       // ------------ Range 2 ------------
                       "09"            // Delta largest acked = 9
                       "05"            // Count = 5
                       "140a0a0505"    // Deltas = 20, 10, 10, 5, 5
  );
}

// Based on Section 8, Table 2 of draft-ietf-quic-receive-ts-02.
TEST_F(QuicAckTimestampListTest, DraftExampleTable2OutOfOrder) {
  ack_.largest_acked = QuicPacketNumber(100);
  ack_.received_packet_times = {
      {QuicPacketNumber(87), TimePlus(300)},
      {QuicPacketNumber(88), TimePlus(305)},
      {QuicPacketNumber(89), TimePlus(310)},
      {QuicPacketNumber(90), TimePlus(320)},
      {QuicPacketNumber(91), TimePlus(330)},
      {QuicPacketNumber(96), TimePlus(350)},
      {QuicPacketNumber(97), TimePlus(355)},
      {QuicPacketNumber(98), TimePlus(360)},
      {QuicPacketNumber(99), TimePlus(370)},
      {QuicPacketNumber(100), TimePlus(380)},
      {QuicPacketNumber(92), TimePlus(390)},
      {QuicPacketNumber(93), TimePlus(392)},
      {QuicPacketNumber(94), TimePlus(394)},
      {QuicPacketNumber(95), TimePlus(395)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/100, /*exponent=*/0,
                            basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       "03"          // Range count = 3
                                     // ------------ Range 1 ------------
                       "05"          // Delta largest acked = 5
                       "04"          // Count = 4
                       "418b010202"  // Deltas = 395, 1, 2, 2
                                     // ------------ Range 2 ------------
                       "00"          // Delta largest acked = 0
                       "05"          // Count = 5
                       "0a0a0a0505"  // Deltas = 10, 10, 10, 5, 5
                                     // ------------ Range 3 ------------
                       "09"          // Delta largest acked = 9
                       "05"          // Count = 5
                       "140a0a0505"  // Deltas = 20, 10, 10, 5, 5
  );
}

// Derived from AckFrameMultipleReceiveTimestampRanges in quic_framer_test.cc.
// Tests encoding multiple ranges with gaps where the first range does not
// start at largest_acked.
TEST_F(QuicAckTimestampListTest, InspiredByFramerTestMultipleRanges) {
  ack_.largest_acked = QuicPacketNumber(1000);
  ack_.received_packet_times = {
      // Range 3: Delta largest acked = 21 (979), Count = 2
      {QuicPacketNumber(978), TimePlus(100)},
      {QuicPacketNumber(979), TimePlus(110)},
      // Range 2: Delta largest acked = 11 (989), Count = 1
      {QuicPacketNumber(989), TimePlus(200)},
      // Range 1: Delta largest acked = 2 (998), Count = 3
      {QuicPacketNumber(996), TimePlus(300)},
      {QuicPacketNumber(997), TimePlus(350)},
      {QuicPacketNumber(998), TimePlus(400)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/100, /*exponent=*/0,
                            basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       "03"        // Range count = 3
                                   // ------------ Range 1 ------------
                       "02"        // Delta largest acked = 2
                       "03"        // Count = 3
                       "41903232"  // Deltas = 400, 50, 50
                                   // ------------ Range 2 ------------
                       "0b"        // Delta largest acked = 11
                       "01"        // Count = 1
                       "4064"      // Deltas = 100
                                   // ------------ Range 3 ------------
                       "15"        // Delta largest acked = 21
                       "02"        // Count = 2
                       "405a0a"    // Deltas = 90, 10
  );
}

// Ensure that ACK timestamps are truncated up to the limit specified by the
// peer.
TEST_F(QuicAckTimestampListTest, MaxAckCountTruncation) {
  ack_.largest_acked = QuicPacketNumber(10);
  ack_.received_packet_times = {
      {QuicPacketNumber(6), TimePlus(60)},
      {QuicPacketNumber(7), TimePlus(70)},
      {QuicPacketNumber(8), TimePlus(80)},
      {QuicPacketNumber(9), TimePlus(90)},
      {QuicPacketNumber(10), TimePlus(100)},
  };

  // Only the 3 newest timestamps (packets 10, 9, 8) should be included.
  QuicAckTimestampList list(ack_, /*max_ack_count=*/3, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       "01"        // Range count = 1
                                   // Range 1
                       "00"        // Delta largest acked = 0
                       "03"        // Count = 3
                       "40640a0a"  // Deltas = 100, 10, 10
  );
}

TEST_F(QuicAckTimestampListTest, ExponentAndRounding) {
  ack_.largest_acked = QuicPacketNumber(3);
  ack_.received_packet_times = {
      {QuicPacketNumber(1), TimePlus(17)},
      {QuicPacketNumber(2), TimePlus(25)},
      {QuicPacketNumber(3), TimePlus(41)},
  };

  // Exponent 3 encodes time deltas in units of 2^3 = 8 microseconds.
  // First delta is rounded up:
  //         ((41 - 1) >> 3) + 1 = 6
  //         Effective time = 48
  // Second delta:
  //         (48 - 25) >> 3 = 2
  //         Effective time = 32.
  // Third delta:
  //         (32 - 17) >> 3 = 1
  //         Effective time = 24.
  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/3, basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       "01"      // Range count = 1
                                 // Range 1
                       "00"      // Delta largest acked = 0
                       "03"      // Count = 3
                       "060201"  // Deltas = 6, 2, 1
  );
}

TEST_F(QuicAckTimestampListTest, EncodeWhileRoundingUpZeroDelta) {
  ack_.largest_acked = QuicPacketNumber(3);
  ack_.received_packet_times = {
      {QuicPacketNumber(1), basis_},
      {QuicPacketNumber(2), basis_},
      {QuicPacketNumber(3), basis_},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/3, basis_);
  EXPECT_EQ(list.error(), "");
  ExpectBinaryEncoding(list,
                       "01"      // Range count = 1
                                 // Range 1
                       "00"      // Delta largest acked = 0
                       "03"      // Count = 3
                       "000000"  // Deltas = 0, 0, 0
  );
}

TEST_F(QuicAckTimestampListTest, ErrorPacketEarlierThanBasis) {
  ack_.largest_acked = QuicPacketNumber(10);
  ack_.received_packet_times = {
      {QuicPacketNumber(10), basis_ - QuicTime::Delta::FromMicroseconds(1)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(),
            "Packet is received earlier than framer creation time");
}

TEST_F(QuicAckTimestampListTest, ErrorPacketNumberHigherThanLargestAcked) {
  ack_.largest_acked = QuicPacketNumber(50);
  ack_.received_packet_times = {
      {QuicPacketNumber(51), TimePlus(100)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(), "Packet number listed higher than largest_acked");
}

TEST_F(QuicAckTimestampListTest, ErrorTimestampsNotMonotonicallyAscending) {
  ack_.largest_acked = QuicPacketNumber(10);
  ack_.received_packet_times = {
      {QuicPacketNumber(9), TimePlus(100)},
      {QuicPacketNumber(10), TimePlus(90)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(),
            "Receive timestamps have to be in monotonically ascending order.");
}

TEST_F(QuicAckTimestampListTest, ErrorExponentTooLarge) {
  ack_.largest_acked = QuicPacketNumber(10);
  ack_.received_packet_times = {
      {QuicPacketNumber(10), TimePlus(100)},
  };

  QuicAckTimestampList valid_list(ack_, /*max_ack_count=*/10, /*exponent=*/20,
                                  basis_);
  EXPECT_EQ(valid_list.error(), "");

  QuicAckTimestampList invalid_list(ack_, /*max_ack_count=*/10, /*exponent=*/21,
                                    basis_);
  EXPECT_EQ(
      invalid_list.error(),
      "The specified exponent exceeds the one allowed by the specification");
}

TEST_F(QuicAckTimestampListTest, BufferTooSmall) {
  ack_.largest_acked = QuicPacketNumber(100);
  ack_.received_packet_times = {
      {QuicPacketNumber(99), TimePlus(10)},
      {QuicPacketNumber(100), TimePlus(20)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(), "");

  // Any buffer of the size at least one byte should let serialization succeed.
  for (QuicByteCount buf_len = 1; buf_len < 4; ++buf_len) {
    std::string buffer(buf_len, '\0');
    QuicDataWriter writer(buffer.size(), buffer.data());
    EXPECT_TRUE(list.Write(writer)) << "buf_len: " << buf_len;
  }
}

TEST_F(QuicAckTimestampListTest, BufferTruncationSingleRange) {
  ack_.largest_acked = QuicPacketNumber(100);
  ack_.received_packet_times = {
      {QuicPacketNumber(98), TimePlus(5)},
      {QuicPacketNumber(99), TimePlus(10)},
      {QuicPacketNumber(100), TimePlus(20)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(), "");
  EXPECT_EQ(list.MaxEncodedSize(), 6u);

  // Buffer size 5 allows encoding packets 100 and 99, but truncates packet 98.
  std::string buffer(5, '\0');
  QuicDataWriter writer(buffer.size(), buffer.data());
  EXPECT_TRUE(list.Write(writer));
  EXPECT_EQ(writer.remaining(), 0u);
  EXPECT_EQ(absl::BytesToHexString(buffer), "010002140a");
}

TEST_F(QuicAckTimestampListTest, BufferTruncationMultipleRanges) {
  ack_.largest_acked = QuicPacketNumber(100);
  ack_.received_packet_times = {
      // Range 2: Packet 90
      {QuicPacketNumber(90), TimePlus(5)},
      // Range 1: Packets 99 and 100
      {QuicPacketNumber(99), TimePlus(10)},
      {QuicPacketNumber(100), TimePlus(20)},
  };

  QuicAckTimestampList list(ack_, /*max_ack_count=*/10, /*exponent=*/0, basis_);
  EXPECT_EQ(list.error(), "");
  EXPECT_EQ(list.MaxEncodedSize(), 8u);

  // Buffer sizes 5, 6, and 7 allow encoding Range 1 (packets 100 and 99, taking
  // 5 bytes total including range count), but are not large enough to encode
  // Range 2 (packet 90, which requires 3 additional bytes).
  for (QuicByteCount buf_len : {5u, 6u, 7u}) {
    std::string buffer(buf_len, '\0');
    QuicDataWriter writer(buffer.size(), buffer.data());
    EXPECT_TRUE(list.Write(writer)) << "buf_len: " << buf_len;
    EXPECT_EQ(writer.length(), 5u) << "buf_len: " << buf_len;
    EXPECT_EQ(absl::BytesToHexString(absl::string_view(buffer.data(), 5)),
              "010002140a")
        << "buf_len: " << buf_len;
  }

  // Buffer size 4 allows encoding only packet 100 of Range 1 (taking 4 bytes
  // total including range count), but truncates packet 99 of Range 1.
  {
    std::string buffer(4, '\0');
    QuicDataWriter writer(buffer.size(), buffer.data());
    EXPECT_TRUE(list.Write(writer));
    EXPECT_EQ(writer.length(), 4u);
    EXPECT_EQ(absl::BytesToHexString(buffer), "01000114");
  }

  // Buffer sizes 1, 2, and 3 are not large enough to encode any range (as even
  // a single-timestamp range requires 4 bytes total including range count), so
  // only the range count of 0 (taking 1 byte) is written.
  for (QuicByteCount buf_len : {1u, 2u, 3u}) {
    std::string buffer(buf_len, '\0');
    QuicDataWriter writer(buffer.size(), buffer.data());
    EXPECT_TRUE(list.Write(writer)) << "buf_len: " << buf_len;
    EXPECT_EQ(writer.length(), 1u) << "buf_len: " << buf_len;
    EXPECT_EQ(absl::BytesToHexString(absl::string_view(buffer.data(), 1)), "00")
        << "buf_len: " << buf_len;
  }
}

}  // namespace
}  // namespace quic::test
