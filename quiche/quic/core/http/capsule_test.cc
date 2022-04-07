// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/capsule.h"

#include <cstddef>
#include <deque>
#include <string>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

using ::testing::_;
using ::testing::InSequence;
using ::testing::Return;

namespace quic {
namespace test {

class CapsuleParserPeer {
 public:
  static std::string* buffered_data(CapsuleParser* capsule_parser) {
    return &capsule_parser->buffered_data_;
  }
};

namespace {

constexpr DatagramFormatType kFakeFormatType =
    static_cast<DatagramFormatType>(0x123456);
constexpr ContextCloseCode kFakeCloseCode =
    static_cast<ContextCloseCode>(0x654321);

class MockCapsuleParserVisitor : public CapsuleParser::Visitor {
 public:
  MockCapsuleParserVisitor() {
    ON_CALL(*this, OnCapsule(_)).WillByDefault(Return(true));
  }
  ~MockCapsuleParserVisitor() override = default;
  MOCK_METHOD(bool, OnCapsule, (const Capsule& capsule), (override));
  MOCK_METHOD(void, OnCapsuleParseFailure, (const std::string& error_message),
              (override));
};

class CapsuleTest : public QuicTest {
 public:
  CapsuleTest() : capsule_parser_(&visitor_) {}

  void ValidateParserIsEmpty() {
    EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
    EXPECT_CALL(visitor_, OnCapsuleParseFailure(_)).Times(0);
    capsule_parser_.ErrorIfThereIsRemainingBufferedData();
    EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
  }

  void TestSerialization(const Capsule& capsule,
                         const std::string& expected_bytes) {
    quiche::QuicheBuffer serialized_capsule =
        SerializeCapsule(capsule, quiche::SimpleBufferAllocator::Get());
    quiche::test::CompareCharArraysWithHexError(
        "Serialized capsule", serialized_capsule.data(),
        serialized_capsule.size(), expected_bytes.data(),
        expected_bytes.size());
  }

  ::testing::StrictMock<MockCapsuleParserVisitor> visitor_;
  CapsuleParser capsule_parser_;
};

TEST_F(CapsuleTest, LegacyDatagramCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a0"          // LEGACY_DATAGRAM capsule type
      "08"                // capsule length
      "a1a2a3a4a5a6a7a8"  // HTTP Datagram payload
  );
  std::string datagram_payload = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  Capsule expected_capsule =
      Capsule::LegacyDatagram(/*context_id=*/absl::nullopt, datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, LegacyDatagramCapsuleWithContext) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a0"          // LEGACY_DATAGRAM capsule type
      "09"                // capsule length
      "04"                // context ID
      "a1a2a3a4a5a6a7a8"  // HTTP Datagram payload
  );
  capsule_parser_.set_datagram_context_id_present(true);
  std::string datagram_payload = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  Capsule expected_capsule =
      Capsule::LegacyDatagram(/*context_id=*/4, datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, DatagramWithoutContextCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a5"          // DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"                // capsule length
      "a1a2a3a4a5a6a7a8"  // HTTP Datagram payload
  );
  std::string datagram_payload = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  Capsule expected_capsule = Capsule::DatagramWithoutContext(datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, DatagramWithContextCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a4"          // DATAGRAM_WITH_CONTEXT capsule type
      "09"                // capsule length
      "04"                // context ID
      "a1a2a3a4a5a6a7a8"  // HTTP Datagram payload
  );
  std::string datagram_payload = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  Capsule expected_capsule =
      Capsule::DatagramWithContext(/*context_id=*/4, datagram_payload);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, RegisterContextCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a1"          // REGISTER_DATAGRAM_CONTEXT capsule type
      "0d"                // capsule length
      "04"                // context ID
      "80123456"          // 0x123456 datagram format type
      "f1f2f3f4f5f6f7f8"  // format additional data
  );
  std::string format_additional_data =
      absl::HexStringToBytes("f1f2f3f4f5f6f7f8");
  Capsule expected_capsule = Capsule::RegisterDatagramContext(
      /*context_id=*/4, kFakeFormatType, format_additional_data);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, RegisterNoContextCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a2"          // REGISTER_DATAGRAM_NO_CONTEXT capsule type
      "0c"                // capsule length
      "80123456"          // 0x123456 datagram format type
      "f1f2f3f4f5f6f7f8"  // format additional data
  );
  std::string format_additional_data =
      absl::HexStringToBytes("f1f2f3f4f5f6f7f8");
  Capsule expected_capsule = Capsule::RegisterDatagramNoContext(
      kFakeFormatType, format_additional_data);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, CloseContextCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a3"  // CLOSE_DATAGRAM_CONTEXT capsule type
      "27"        // capsule length
      "04"        // context ID
      "80654321"  // 0x654321 close code
  );
  std::string close_details = "All your contexts are belong to us";
  capsule_fragment += close_details;
  Capsule expected_capsule = Capsule::CloseDatagramContext(
      /*context_id=*/4, kFakeCloseCode, close_details);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, CloseWebTransportStreamCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "6843"        // CLOSE_WEBTRANSPORT_STREAM capsule type
      "09"          // capsule length
      "00001234"    // 0x1234 error code
      "68656c6c6f"  // "hello" error message
  );
  Capsule expected_capsule = Capsule::CloseWebTransportSession(
      /*error_code=*/0x1234, /*error_message=*/"hello");
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, UnknownCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "33"                // unknown capsule type of 0x33
      "08"                // capsule length
      "a1a2a3a4a5a6a7a8"  // unknown capsule data
  );
  std::string unknown_capsule_data = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  Capsule expected_capsule = Capsule::Unknown(0x33, unknown_capsule_data);
  {
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
  TestSerialization(expected_capsule, capsule_fragment);
}

TEST_F(CapsuleTest, TwoCapsules) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a5"          // DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"                // capsule length
      "a1a2a3a4a5a6a7a8"  // HTTP Datagram payload
      "80ff37a5"          // DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"                // capsule length
      "b1b2b3b4b5b6b7b8"  // HTTP Datagram payload
  );
  std::string datagram_payload1 = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  std::string datagram_payload2 = absl::HexStringToBytes("b1b2b3b4b5b6b7b8");
  Capsule expected_capsule1 =
      Capsule::DatagramWithoutContext(datagram_payload1);
  Capsule expected_capsule2 =
      Capsule::DatagramWithoutContext(datagram_payload2);
  {
    InSequence s;
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule1));
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule2));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  ValidateParserIsEmpty();
}

TEST_F(CapsuleTest, TwoCapsulesPartialReads) {
  std::string capsule_fragment1 = absl::HexStringToBytes(
      "80ff37a5"  // first capsule DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"        // frist capsule length
      "a1a2a3a4"  // first half of HTTP Datagram payload of first capsule
  );
  std::string capsule_fragment2 = absl::HexStringToBytes(
      "a5a6a7a8"  // second half of HTTP Datagram payload 1
      "80ff37a5"  // second capsule DATAGRAM_WITHOUT_CONTEXT capsule type
  );
  std::string capsule_fragment3 = absl::HexStringToBytes(
      "08"                // second capsule length
      "b1b2b3b4b5b6b7b8"  // HTTP Datagram payload of second capsule
  );
  capsule_parser_.ErrorIfThereIsRemainingBufferedData();
  std::string datagram_payload1 = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  std::string datagram_payload2 = absl::HexStringToBytes("b1b2b3b4b5b6b7b8");
  Capsule expected_capsule1 =
      Capsule::DatagramWithoutContext(datagram_payload1);
  Capsule expected_capsule2 =
      Capsule::DatagramWithoutContext(datagram_payload2);
  {
    InSequence s;
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule1));
    EXPECT_CALL(visitor_, OnCapsule(expected_capsule2));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment1));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment2));
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment3));
  }
  ValidateParserIsEmpty();
}

TEST_F(CapsuleTest, TwoCapsulesOneByteAtATime) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a5"          // DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"                // capsule length
      "a1a2a3a4a5a6a7a8"  // HTTP Datagram payload
      "80ff37a5"          // DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"                // capsule length
      "b1b2b3b4b5b6b7b8"  // HTTP Datagram payload
  );
  std::string datagram_payload1 = absl::HexStringToBytes("a1a2a3a4a5a6a7a8");
  std::string datagram_payload2 = absl::HexStringToBytes("b1b2b3b4b5b6b7b8");
  Capsule expected_capsule1 =
      Capsule::DatagramWithoutContext(datagram_payload1);
  Capsule expected_capsule2 =
      Capsule::DatagramWithoutContext(datagram_payload2);
  for (size_t i = 0; i < capsule_fragment.size(); i++) {
    if (i < capsule_fragment.size() / 2 - 1) {
      EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
    } else if (i == capsule_fragment.size() / 2 - 1) {
      EXPECT_CALL(visitor_, OnCapsule(expected_capsule1));
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
      EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
    } else if (i < capsule_fragment.size() - 1) {
      EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
    } else {
      EXPECT_CALL(visitor_, OnCapsule(expected_capsule2));
      ASSERT_TRUE(
          capsule_parser_.IngestCapsuleFragment(capsule_fragment.substr(i, 1)));
      EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
    }
  }
  capsule_parser_.ErrorIfThereIsRemainingBufferedData();
  EXPECT_TRUE(CapsuleParserPeer::buffered_data(&capsule_parser_)->empty());
}

TEST_F(CapsuleTest, PartialCapsuleThenError) {
  std::string capsule_fragment = absl::HexStringToBytes(
      "80ff37a5"  // DATAGRAM_WITHOUT_CONTEXT capsule type
      "08"        // capsule length
      "a1a2a3a4"  // first half of HTTP Datagram payload
  );
  EXPECT_CALL(visitor_, OnCapsule(_)).Times(0);
  {
    EXPECT_CALL(visitor_, OnCapsuleParseFailure(_)).Times(0);
    ASSERT_TRUE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
  }
  {
    EXPECT_CALL(visitor_,
                OnCapsuleParseFailure(
                    "Incomplete capsule left at the end of the stream"));
    capsule_parser_.ErrorIfThereIsRemainingBufferedData();
  }
}

TEST_F(CapsuleTest, RejectOverlyLongCapsule) {
  std::string capsule_fragment = absl::HexStringToBytes(
                                     "33"        // unknown capsule type of 0x33
                                     "80123456"  // capsule length
                                     ) +
                                 std::string(1111111, '?');
  EXPECT_CALL(visitor_, OnCapsuleParseFailure(
                            "Refusing to buffer too much capsule data"));
  EXPECT_FALSE(capsule_parser_.IngestCapsuleFragment(capsule_fragment));
}

}  // namespace
}  // namespace test
}  // namespace quic
