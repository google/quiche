// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for WebTransport capsule types (Section 6, 9.6).
// Pure capsule serialization/parsing tests — no QUIC session dependencies.
// Session-dependent tests live in
// quiche/quic/core/http/web_transport_capsule_dispatch_draft15_test.cc.

#include <cstdint>
#include <optional>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/common/capsule.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"
#include "quiche/web_transport/web_transport.h"

namespace quiche {
namespace {

// --- Capsule type codepoint assertions (Section 9.6) ---

TEST(CapsuleDraft15, WtCloseSessionCapsuleType) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::CLOSE_WEBTRANSPORT_SESSION),
            webtransport::draft15::kWtCloseSession);
}

TEST(CapsuleDraft15, WtDrainSessionCapsuleType) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::DRAIN_WEBTRANSPORT_SESSION),
            webtransport::draft15::kWtDrainSession);
}

TEST(CapsuleDraft15, WtMaxStreamsBidiCapsuleParse) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::WT_MAX_STREAMS_BIDI),
            webtransport::draft15::kWtMaxStreamsBidi);
}

TEST(CapsuleDraft15, WtMaxStreamsUnidiCapsuleParse) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::WT_MAX_STREAMS_UNIDI),
            webtransport::draft15::kWtMaxStreamsUnidi);
}

TEST(CapsuleDraft15, WtMaxDataCapsuleParse) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::WT_MAX_DATA),
            webtransport::draft15::kWtMaxData);
}

TEST(CapsuleDraft15, WtDataBlockedCapsuleParse) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::WT_DATA_BLOCKED),
            webtransport::draft15::kWtDataBlocked);
}

TEST(CapsuleDraft15, WtStreamsBlockedBidiCapsuleParse) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::WT_STREAMS_BLOCKED_BIDI),
            webtransport::draft15::kWtStreamsBlockedBidi);
}

TEST(CapsuleDraft15, WtStreamsBlockedUnidiCapsuleParse) {
  EXPECT_EQ(static_cast<uint64_t>(CapsuleType::WT_STREAMS_BLOCKED_UNIDI),
            webtransport::draft15::kWtStreamsBlockedUnidi);
}

// --- Message length validation (Section 6) ---

class TestCapsuleVisitor : public CapsuleParser::Visitor {
 public:
  bool OnCapsule(const Capsule& capsule) override {
    last_capsule_type_ = capsule.capsule_type();
    if (capsule.capsule_type() ==
        CapsuleType::CLOSE_WEBTRANSPORT_SESSION) {
      last_error_message_length_ =
          capsule.close_web_transport_session_capsule()
              .error_message.size();
    }
    capsule_received_ = true;
    last_capsule_ = capsule;
    if (capsule.capsule_type() ==
            CapsuleType::CLOSE_WEBTRANSPORT_SESSION &&
        capsule.close_web_transport_session_capsule()
                .error_message.size() > 1024) {
      return false;
    }
    return true;
  }

  void OnCapsuleParseFailure(absl::string_view error_message) override {
    parse_failure_ = true;
    failure_message_ = std::string(error_message);
  }

  bool capsule_received_ = false;
  bool parse_failure_ = false;
  std::string failure_message_;
  std::optional<CapsuleType> last_capsule_type_;
  std::optional<Capsule> last_capsule_;
  size_t last_error_message_length_ = 0;
};

TEST(CapsuleDraft15, WtCloseSessionMaxMessage1024) {
  std::string long_message(1025, 'x');
  Capsule capsule = Capsule::CloseWebTransportSession(0, long_message);

  quiche::SimpleBufferAllocator allocator;
  quiche::QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  bool parse_ok = parser.IngestCapsuleFragment(serialized.AsStringView());

  EXPECT_FALSE(parse_ok)
      << "Parsing a CLOSE_WEBTRANSPORT_SESSION capsule with a 1025-byte "
         "message should fail validation";
  EXPECT_TRUE(visitor.capsule_received_);
  EXPECT_TRUE(visitor.parse_failure_);

  std::string ok_message(1024, 'y');
  Capsule ok_capsule = Capsule::CloseWebTransportSession(0, ok_message);
  quiche::QuicheBuffer ok_serialized =
      SerializeCapsule(ok_capsule, &allocator);

  TestCapsuleVisitor ok_visitor;
  CapsuleParser ok_parser(&ok_visitor);
  EXPECT_TRUE(ok_parser.IngestCapsuleFragment(ok_serialized.AsStringView()));
  EXPECT_TRUE(ok_visitor.capsule_received_);
  EXPECT_FALSE(ok_visitor.parse_failure_);
}

// --- Round-trip serialization tests ---

TEST(CapsuleDraft15, WtMaxDataSerializeRoundTrip) {
  quiche::SimpleBufferAllocator allocator;
  Capsule capsule(WebTransportMaxDataCapsule{65536});
  QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  ASSERT_TRUE(parser.IngestCapsuleFragment(serialized.AsStringView()));
  ASSERT_TRUE(visitor.capsule_received_);
  EXPECT_EQ(visitor.last_capsule_type_, CapsuleType::WT_MAX_DATA);
  ASSERT_TRUE(visitor.last_capsule_.has_value());
  EXPECT_EQ(visitor.last_capsule_->web_transport_max_data().max_data, 65536u);
}

TEST(CapsuleDraft15, WtMaxStreamsBidiSerializeRoundTrip) {
  quiche::SimpleBufferAllocator allocator;
  Capsule capsule(WebTransportMaxStreamsCapsule{
      webtransport::StreamType::kBidirectional, 100});
  QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  ASSERT_TRUE(parser.IngestCapsuleFragment(serialized.AsStringView()));
  ASSERT_TRUE(visitor.capsule_received_);
  EXPECT_EQ(visitor.last_capsule_type_, CapsuleType::WT_MAX_STREAMS_BIDI);
  ASSERT_TRUE(visitor.last_capsule_.has_value());
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_max_streams().stream_type,
      webtransport::StreamType::kBidirectional);
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_max_streams().max_stream_count,
      100u);
}

TEST(CapsuleDraft15, WtMaxStreamsUnidiSerializeRoundTrip) {
  quiche::SimpleBufferAllocator allocator;
  Capsule capsule(WebTransportMaxStreamsCapsule{
      webtransport::StreamType::kUnidirectional, 50});
  QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  ASSERT_TRUE(parser.IngestCapsuleFragment(serialized.AsStringView()));
  ASSERT_TRUE(visitor.capsule_received_);
  EXPECT_EQ(visitor.last_capsule_type_, CapsuleType::WT_MAX_STREAMS_UNIDI);
  ASSERT_TRUE(visitor.last_capsule_.has_value());
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_max_streams().stream_type,
      webtransport::StreamType::kUnidirectional);
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_max_streams().max_stream_count,
      50u);
}

TEST(CapsuleDraft15, WtDataBlockedSerializeRoundTrip) {
  quiche::SimpleBufferAllocator allocator;
  Capsule capsule(WebTransportDataBlockedCapsule{1024});
  QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  ASSERT_TRUE(parser.IngestCapsuleFragment(serialized.AsStringView()));
  ASSERT_TRUE(visitor.capsule_received_);
  EXPECT_EQ(visitor.last_capsule_type_, CapsuleType::WT_DATA_BLOCKED);
  ASSERT_TRUE(visitor.last_capsule_.has_value());
  EXPECT_EQ(visitor.last_capsule_->web_transport_data_blocked().data_limit,
            1024u);
}

TEST(CapsuleDraft15, WtStreamsBlockedBidiSerializeRoundTrip) {
  quiche::SimpleBufferAllocator allocator;
  Capsule capsule(WebTransportStreamsBlockedCapsule{
      webtransport::StreamType::kBidirectional, 50});
  QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  ASSERT_TRUE(parser.IngestCapsuleFragment(serialized.AsStringView()));
  ASSERT_TRUE(visitor.capsule_received_);
  EXPECT_EQ(visitor.last_capsule_type_, CapsuleType::WT_STREAMS_BLOCKED_BIDI);
  ASSERT_TRUE(visitor.last_capsule_.has_value());
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_streams_blocked().stream_type,
      webtransport::StreamType::kBidirectional);
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_streams_blocked().stream_limit,
      50u);
}

TEST(CapsuleDraft15, WtStreamsBlockedUnidiSerializeRoundTrip) {
  quiche::SimpleBufferAllocator allocator;
  Capsule capsule(WebTransportStreamsBlockedCapsule{
      webtransport::StreamType::kUnidirectional, 25});
  QuicheBuffer serialized = SerializeCapsule(capsule, &allocator);
  ASSERT_FALSE(serialized.empty());

  TestCapsuleVisitor visitor;
  CapsuleParser parser(&visitor);
  ASSERT_TRUE(parser.IngestCapsuleFragment(serialized.AsStringView()));
  ASSERT_TRUE(visitor.capsule_received_);
  EXPECT_EQ(visitor.last_capsule_type_, CapsuleType::WT_STREAMS_BLOCKED_UNIDI);
  ASSERT_TRUE(visitor.last_capsule_.has_value());
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_streams_blocked().stream_type,
      webtransport::StreamType::kUnidirectional);
  EXPECT_EQ(
      visitor.last_capsule_->web_transport_streams_blocked().stream_limit,
      25u);
}


}  // namespace
}  // namespace quiche
