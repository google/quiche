// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_chaos_protector.h"

#include <cstddef>
#include <memory>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/frames/quic_crypto_frame.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_framer.h"
#include "quiche/quic/core/quic_packet_number.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_stream_frame_data_producer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_random.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/quic/test_tools/simple_quic_framer.h"

namespace quic {
namespace test {

class QuicChaosProtectorTest : public QuicTestWithParam<ParsedQuicVersion>,
                               public QuicStreamFrameDataProducer {
 public:
  QuicChaosProtectorTest()
      : version_(GetParam()),
        framer_({version_}, QuicTime::Zero(), Perspective::IS_CLIENT,
                kQuicDefaultConnectionIdLength),
        validation_framer_({version_}),
        random_(/*base=*/3),
        level_(ENCRYPTION_INITIAL),
        crypto_offset_(0),
        crypto_data_length_(100),
        crypto_frame_(level_, crypto_offset_, crypto_data_length_),
        num_padding_bytes_(50),
        packet_size_(1000),
        packet_buffer_(std::make_unique<char[]>(packet_size_)) {
    ReCreateChaosProtector();
  }

  void ReCreateChaosProtector() {
    chaos_protector_ = std::make_unique<QuicChaosProtector>(
        crypto_frame_, num_padding_bytes_, packet_size_,
        SetupHeaderAndFramers(), &random_);
  }

  // From QuicStreamFrameDataProducer.
  WriteStreamDataResult WriteStreamData(QuicStreamId /*id*/,
                                        QuicStreamOffset /*offset*/,
                                        QuicByteCount /*data_length*/,
                                        QuicDataWriter* /*writer*/) override {
    ADD_FAILURE() << "This should never be called";
    return STREAM_MISSING;
  }

  // From QuicStreamFrameDataProducer.
  bool WriteCryptoData(EncryptionLevel level, QuicStreamOffset offset,
                       QuicByteCount data_length,
                       QuicDataWriter* writer) override {
    EXPECT_EQ(level, level);
    EXPECT_EQ(offset, crypto_offset_);
    EXPECT_EQ(data_length, crypto_data_length_);
    for (QuicByteCount i = 0; i < data_length; i++) {
      EXPECT_TRUE(writer->WriteUInt8(static_cast<uint8_t>(i & 0xFF)));
    }
    return true;
  }

 protected:
  QuicFramer* SetupHeaderAndFramers() {
    // Setup header.
    header_.destination_connection_id = TestConnectionId();
    header_.destination_connection_id_included = CONNECTION_ID_PRESENT;
    header_.source_connection_id = EmptyQuicConnectionId();
    header_.source_connection_id_included = CONNECTION_ID_PRESENT;
    header_.reset_flag = false;
    header_.version_flag = true;
    header_.has_possible_stateless_reset_token = false;
    header_.packet_number_length = PACKET_4BYTE_PACKET_NUMBER;
    header_.version = version_;
    header_.packet_number = QuicPacketNumber(1);
    header_.form = IETF_QUIC_LONG_HEADER_PACKET;
    header_.long_packet_type = INITIAL;
    header_.retry_token_length_length =
        quiche::VARIABLE_LENGTH_INTEGER_LENGTH_1;
    header_.length_length = quiche::kQuicheDefaultLongHeaderLengthLength;
    // Setup validation framer.
    validation_framer_.framer()->SetInitialObfuscators(
        header_.destination_connection_id);
    // Setup framer.
    framer_.SetInitialObfuscators(header_.destination_connection_id);
    framer_.set_data_producer(this);
    return &framer_;
  }

  void BuildEncryptAndParse() {
    absl::optional<size_t> length =
        chaos_protector_->BuildDataPacket(header_, packet_buffer_.get());
    ASSERT_TRUE(length.has_value());
    ASSERT_GT(length.value(), 0u);
    size_t encrypted_length = framer_.EncryptInPlace(
        level_, header_.packet_number,
        GetStartOfEncryptedData(framer_.transport_version(), header_),
        length.value(), packet_size_, packet_buffer_.get());
    ASSERT_GT(encrypted_length, 0u);
    ASSERT_TRUE(validation_framer_.ProcessPacket(QuicEncryptedPacket(
        absl::string_view(packet_buffer_.get(), encrypted_length))));
  }

  void ResetOffset(QuicStreamOffset offset) {
    crypto_offset_ = offset;
    crypto_frame_.offset = offset;
    ReCreateChaosProtector();
  }

  void ResetLength(QuicByteCount length) {
    crypto_data_length_ = length;
    crypto_frame_.data_length = length;
    ReCreateChaosProtector();
  }

  ParsedQuicVersion version_;
  QuicPacketHeader header_;
  QuicFramer framer_;
  SimpleQuicFramer validation_framer_;
  MockRandom random_;
  EncryptionLevel level_;
  QuicStreamOffset crypto_offset_;
  QuicByteCount crypto_data_length_;
  QuicCryptoFrame crypto_frame_;
  int num_padding_bytes_;
  size_t packet_size_;
  std::unique_ptr<char[]> packet_buffer_;
  std::unique_ptr<QuicChaosProtector> chaos_protector_;
};

namespace {

ParsedQuicVersionVector TestVersions() {
  ParsedQuicVersionVector versions;
  for (const ParsedQuicVersion& version : AllSupportedVersions()) {
    if (version.UsesCryptoFrames()) {
      versions.push_back(version);
    }
  }
  return versions;
}

INSTANTIATE_TEST_SUITE_P(QuicChaosProtectorTests, QuicChaosProtectorTest,
                         ::testing::ValuesIn(TestVersions()),
                         ::testing::PrintToStringParamName());

TEST_P(QuicChaosProtectorTest, Main) {
  BuildEncryptAndParse();
  ASSERT_EQ(validation_framer_.crypto_frames().size(), 4u);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->offset, 0u);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->data_length, 1u);
  ASSERT_EQ(validation_framer_.ping_frames().size(), 3u);
  ASSERT_EQ(validation_framer_.padding_frames().size(), 7u);
  EXPECT_EQ(validation_framer_.padding_frames()[0].num_padding_bytes, 3);
}

TEST_P(QuicChaosProtectorTest, DifferentRandom) {
  random_.ResetBase(4);
  BuildEncryptAndParse();
  ASSERT_EQ(validation_framer_.crypto_frames().size(), 4u);
  ASSERT_EQ(validation_framer_.ping_frames().size(), 4u);
  ASSERT_EQ(validation_framer_.padding_frames().size(), 8u);
}

TEST_P(QuicChaosProtectorTest, RandomnessZero) {
  random_.ResetBase(0);
  BuildEncryptAndParse();
  ASSERT_EQ(validation_framer_.crypto_frames().size(), 1u);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->offset, crypto_offset_);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->data_length,
            crypto_data_length_);
  ASSERT_EQ(validation_framer_.ping_frames().size(), 0u);
  ASSERT_EQ(validation_framer_.padding_frames().size(), 1u);
}

TEST_P(QuicChaosProtectorTest, Offset) {
  ResetOffset(123);
  BuildEncryptAndParse();
  ASSERT_EQ(validation_framer_.crypto_frames().size(), 4u);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->offset, crypto_offset_);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->data_length, 1u);
  ASSERT_EQ(validation_framer_.ping_frames().size(), 3u);
  ASSERT_EQ(validation_framer_.padding_frames().size(), 7u);
  EXPECT_EQ(validation_framer_.padding_frames()[0].num_padding_bytes, 3);
}

TEST_P(QuicChaosProtectorTest, OffsetAndRandomnessZero) {
  ResetOffset(123);
  random_.ResetBase(0);
  BuildEncryptAndParse();
  ASSERT_EQ(validation_framer_.crypto_frames().size(), 1u);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->offset, crypto_offset_);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->data_length,
            crypto_data_length_);
  ASSERT_EQ(validation_framer_.ping_frames().size(), 0u);
  ASSERT_EQ(validation_framer_.padding_frames().size(), 1u);
}

TEST_P(QuicChaosProtectorTest, ZeroRemainingBytesAfterSplit) {
  QuicPacketLength new_length = 63;
  num_padding_bytes_ = QuicFramer::GetMinCryptoFrameSize(
      crypto_frame_.offset + new_length, new_length);
  ResetLength(new_length);
  BuildEncryptAndParse();

  ASSERT_EQ(validation_framer_.crypto_frames().size(), 2u);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->offset, crypto_offset_);
  EXPECT_EQ(validation_framer_.crypto_frames()[0]->data_length, 4);
  EXPECT_EQ(validation_framer_.crypto_frames()[1]->offset, crypto_offset_ + 4);
  EXPECT_EQ(validation_framer_.crypto_frames()[1]->data_length,
            crypto_data_length_ - 4);
  ASSERT_EQ(validation_framer_.ping_frames().size(), 0u);
}

}  // namespace
}  // namespace test
}  // namespace quic
