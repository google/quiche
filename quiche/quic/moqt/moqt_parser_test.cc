// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_parser.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt::test {

namespace {

inline bool IsObjectMessage(MoqtMessageType type) {
  return (type == MoqtMessageType::kObjectStream ||
          type == MoqtMessageType::kObjectDatagram ||
          type == MoqtMessageType::kStreamHeaderTrack ||
          type == MoqtMessageType::kStreamHeaderGroup);
}

inline bool IsObjectWithoutPayloadLength(MoqtMessageType type) {
  return (type == MoqtMessageType::kObjectStream ||
          type == MoqtMessageType::kObjectDatagram);
}

std::vector<MoqtMessageType> message_types = {
    MoqtMessageType::kObjectStream,
    // kObjectDatagram is a unique set of tests.
    MoqtMessageType::kSubscribe,
    MoqtMessageType::kSubscribeOk,
    MoqtMessageType::kSubscribeError,
    MoqtMessageType::kUnsubscribe,
    MoqtMessageType::kSubscribeDone,
    MoqtMessageType::kAnnounce,
    MoqtMessageType::kAnnounceOk,
    MoqtMessageType::kAnnounceError,
    MoqtMessageType::kUnannounce,
    MoqtMessageType::kClientSetup,
    MoqtMessageType::kServerSetup,
    MoqtMessageType::kStreamHeaderTrack,
    MoqtMessageType::kStreamHeaderGroup,
    MoqtMessageType::kGoAway,
};

}  // namespace

struct MoqtParserTestParams {
  MoqtParserTestParams(MoqtMessageType message_type, bool uses_web_transport)
      : message_type(message_type), uses_web_transport(uses_web_transport) {}
  MoqtMessageType message_type;
  bool uses_web_transport;
};

std::vector<MoqtParserTestParams> GetMoqtParserTestParams() {
  std::vector<MoqtParserTestParams> params;

  std::vector<bool> uses_web_transport_bool = {
      false,
      true,
  };
  for (const MoqtMessageType message_type : message_types) {
    if (message_type == MoqtMessageType::kClientSetup) {
      for (const bool uses_web_transport : uses_web_transport_bool) {
        params.push_back(
            MoqtParserTestParams(message_type, uses_web_transport));
      }
    } else {
      // All other types are processed the same for either perspective or
      // transport.
      params.push_back(MoqtParserTestParams(message_type, true));
    }
  }
  return params;
}

std::string ParamNameFormatter(
    const testing::TestParamInfo<MoqtParserTestParams>& info) {
  return MoqtMessageTypeToString(info.param.message_type) + "_" +
         (info.param.uses_web_transport ? "WebTransport" : "QUIC");
}

class MoqtParserTestVisitor : public MoqtParserVisitor {
 public:
  ~MoqtParserTestVisitor() = default;

  void OnObjectMessage(const MoqtObject& message, absl::string_view payload,
                       bool end_of_message) override {
    MoqtObject object = message;
    object_payload_ = payload;
    end_of_message_ = end_of_message;
    messages_received_++;
    last_message_ = TestMessageBase::MessageStructuredData(object);
  }

  template <typename Message>
  void OnControlMessage(const Message& message) {
    end_of_message_ = true;
    ++messages_received_;
    last_message_ = TestMessageBase::MessageStructuredData(message);
  }
  void OnClientSetupMessage(const MoqtClientSetup& message) override {
    OnControlMessage(message);
  }
  void OnServerSetupMessage(const MoqtServerSetup& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeMessage(const MoqtSubscribe& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeOkMessage(const MoqtSubscribeOk& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeErrorMessage(const MoqtSubscribeError& message) override {
    OnControlMessage(message);
  }
  void OnUnsubscribeMessage(const MoqtUnsubscribe& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeDoneMessage(const MoqtSubscribeDone& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceMessage(const MoqtAnnounce& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceOkMessage(const MoqtAnnounceOk& message) override {
    OnControlMessage(message);
  }
  void OnAnnounceErrorMessage(const MoqtAnnounceError& message) override {
    OnControlMessage(message);
  }
  void OnUnannounceMessage(const MoqtUnannounce& message) override {
    OnControlMessage(message);
  }
  void OnGoAwayMessage(const MoqtGoAway& message) override {
    OnControlMessage(message);
  }
  void OnParsingError(MoqtError code, absl::string_view reason) override {
    QUIC_LOG(INFO) << "Parsing error: " << reason;
    parsing_error_ = reason;
    parsing_error_code_ = code;
  }

  std::optional<absl::string_view> object_payload_;
  bool end_of_message_ = false;
  std::optional<absl::string_view> parsing_error_;
  MoqtError parsing_error_code_;
  uint64_t messages_received_ = 0;
  std::optional<TestMessageBase::MessageStructuredData> last_message_;
};

class MoqtParserTest
    : public quic::test::QuicTestWithParam<MoqtParserTestParams> {
 public:
  MoqtParserTest()
      : message_type_(GetParam().message_type),
        webtrans_(GetParam().uses_web_transport),
        parser_(GetParam().uses_web_transport, visitor_) {}

  std::unique_ptr<TestMessageBase> MakeMessage(MoqtMessageType message_type) {
    return CreateTestMessage(message_type, webtrans_);
  }

  MoqtParserTestVisitor visitor_;
  MoqtMessageType message_type_;
  bool webtrans_;
  MoqtParser parser_;
};

INSTANTIATE_TEST_SUITE_P(MoqtParserTests, MoqtParserTest,
                         testing::ValuesIn(GetMoqtParserTestParams()),
                         ParamNameFormatter);

TEST_P(MoqtParserTest, OneMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  parser_.ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (IsObjectMessage(message_type_)) {
    // Check payload message.
    EXPECT_TRUE(visitor_.object_payload_.has_value());
    EXPECT_EQ(*(visitor_.object_payload_), "foo");
  }
}

TEST_P(MoqtParserTest, OneMessageWithLongVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->ExpandVarints();
  parser_.ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (IsObjectMessage(message_type_)) {
    // Check payload message.
    EXPECT_EQ(visitor_.object_payload_, "foo");
  }
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, TwoPartMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  // The test Object message has payload for less then half the message length,
  // so splitting the message in half will prevent the first half from being
  // processed.
  size_t first_data_size = message->total_message_size() / 2;
  if (message_type_ == MoqtMessageType::kStreamHeaderTrack) {
    // The boundary happens to fall right after the stream header, so move it.
    ++first_data_size;
  }
  parser_.ProcessData(message->PacketSample().substr(0, first_data_size),
                      false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  parser_.ProcessData(
      message->PacketSample().substr(
          first_data_size, message->total_message_size() - first_data_size),
      true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  if (IsObjectMessage(message_type_)) {
    EXPECT_EQ(visitor_.object_payload_, "foo");
  }
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, OneByteAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  size_t kObjectPayloadSize = 3;
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    if (!IsObjectMessage(message_type_)) {
      EXPECT_EQ(visitor_.messages_received_, 0);
    }
    EXPECT_FALSE(visitor_.end_of_message_);
    parser_.ProcessData(message->PacketSample().substr(i, 1), false);
  }
  EXPECT_EQ(visitor_.messages_received_,
            (IsObjectMessage(message_type_) ? (kObjectPayloadSize + 1) : 1));
  if (IsObjectWithoutPayloadLength(message_type_)) {
    EXPECT_FALSE(visitor_.end_of_message_);
    parser_.ProcessData(absl::string_view(), true);  // Needs the FIN
    EXPECT_EQ(visitor_.messages_received_, kObjectPayloadSize + 2);
  }
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, OneByteAtATimeLongerVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->ExpandVarints();
  size_t kObjectPayloadSize = 3;
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    if (!IsObjectMessage(message_type_)) {
      EXPECT_EQ(visitor_.messages_received_, 0);
    }
    EXPECT_FALSE(visitor_.end_of_message_);
    parser_.ProcessData(message->PacketSample().substr(i, 1), false);
  }
  EXPECT_EQ(visitor_.messages_received_,
            (IsObjectMessage(message_type_) ? (kObjectPayloadSize + 1) : 1));
  if (IsObjectWithoutPayloadLength(message_type_)) {
    EXPECT_FALSE(visitor_.end_of_message_);
    parser_.ProcessData(absl::string_view(), true);  // Needs the FIN
    EXPECT_EQ(visitor_.messages_received_, kObjectPayloadSize + 2);
  }
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, EarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  size_t first_data_size = message->total_message_size() / 2;
  if (message_type_ == MoqtMessageType::kStreamHeaderTrack) {
    // The boundary happens to fall right after the stream header, so move it.
    ++first_data_size;
  }
  parser_.ProcessData(message->PacketSample().substr(0, first_data_size), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "FIN after incomplete message");
}

TEST_P(MoqtParserTest, SeparateEarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  size_t first_data_size = message->total_message_size() / 2;
  if (message_type_ == MoqtMessageType::kStreamHeaderTrack) {
    // The boundary happens to fall right after the stream header, so move it.
    ++first_data_size;
  }
  parser_.ProcessData(message->PacketSample().substr(0, first_data_size),
                      false);
  parser_.ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End of stream before complete message");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

// Tests for message-specific error cases, and behaviors for a single message
// type.
class MoqtMessageSpecificTest : public quic::test::QuicTest {
 public:
  MoqtMessageSpecificTest() {}

  MoqtParserTestVisitor visitor_;

  static constexpr bool kWebTrans = true;
  static constexpr bool kRawQuic = false;
};

TEST_F(MoqtMessageSpecificTest, ObjectStreamSeparateFin) {
  // OBJECT can return on an unknown-length message even without receiving a
  // FIN.
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<ObjectStreamMessage>();
  parser.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "foo");
  EXPECT_FALSE(visitor_.end_of_message_);

  parser.ProcessData(absl::string_view(), true);  // send the FIN
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "");
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

// Send the header + some payload, pure payload, then pure payload to end the
// message.
TEST_F(MoqtMessageSpecificTest, ThreePartObject) {
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<ObjectStreamMessage>();
  parser.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "foo");

  // second part
  parser.ProcessData("bar", false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");

  // third part includes FIN
  parser.ProcessData("deadbeef", true);
  EXPECT_EQ(visitor_.messages_received_, 3);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "deadbeef");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

// Send the part of header, rest of header + payload, plus payload.
TEST_F(MoqtMessageSpecificTest, ThreePartObjectFirstIncomplete) {
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<ObjectStreamMessage>();

  // first part
  parser.ProcessData(message->PacketSample().substr(0, 4), false);
  EXPECT_EQ(visitor_.messages_received_, 0);

  // second part. Add padding to it.
  message->set_wire_image_size(100);
  parser.ProcessData(
      message->PacketSample().substr(4, message->total_message_size() - 4),
      false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(visitor_.object_payload_->length(), 94);

  // third part includes FIN
  parser.ProcessData("bar", true);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderGroupFollowOn) {
  MoqtParser parser(kRawQuic, visitor_);
  // first part
  auto message1 = std::make_unique<StreamHeaderGroupMessage>();
  parser.ProcessData(message1->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message1->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "foo");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // second part
  auto message2 = std::make_unique<StreamMiddlerGroupMessage>();
  parser.ProcessData(message2->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message2->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderTrackFollowOn) {
  MoqtParser parser(kRawQuic, visitor_);
  // first part
  auto message1 = std::make_unique<StreamHeaderTrackMessage>();
  parser.ProcessData(message1->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message1->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "foo");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // second part
  auto message2 = std::make_unique<StreamMiddlerTrackMessage>();
  parser.ProcessData(message2->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message2->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, ClientSetupRoleIsInvalid) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions
      0x03,                          // 3 params
      0x00, 0x01, 0x04,              // role = invalid
      0x01, 0x03, 0x66, 0x6f, 0x6f   // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Invalid ROLE parameter");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupRoleIsInvalid) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x41, 0x01,
      0x01,                         // 1 param
      0x00, 0x01, 0x04,             // role = invalid
      0x01, 0x03, 0x66, 0x6f, 0x6f  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Invalid ROLE parameter");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupRoleAppearsTwice) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions
      0x03,                          // 3 params
      0x00, 0x01, 0x03,              // role = PubSub
      0x00, 0x01, 0x03,              // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f   // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "ROLE parameter appears twice in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ClientSetupRoleIsMissing) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x01,                          // 1 param
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "ROLE parameter missing from CLIENT_SETUP message");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupRoleIsMissing) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x41, 0x01, 0x00,  // 1 param
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "ROLE parameter missing from SERVER_SETUP message");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupRoleVarintLengthIsWrong) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40,                   // type
      0x02, 0x01, 0x02,             // versions
      0x02,                         // 2 parameters
      0x00, 0x02, 0x03,             // role = PubSub, but length is 2
      0x01, 0x03, 0x66, 0x6f, 0x6f  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Parameter length does not match varint encoding");

  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kParameterLengthMismatch);
}

TEST_F(MoqtMessageSpecificTest, SetupPathFromServer) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x41,
      0x01,                          // version = 1
      0x01,                          // 1 param
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "PATH parameter in SERVER_SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathAppearsTwice) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x03,                          // 3 params
      0x00, 0x01, 0x03,              // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH parameter appears twice in CLIENT_SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathOverWebtrans) {
  MoqtParser parser(kWebTrans, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x02,                          // 2 params
      0x00, 0x01, 0x03,              // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "WebTransport connection is using PATH parameter in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathMissing) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x01,                          // 1 param
      0x00, 0x01, 0x03,              // role = PubSub
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH SETUP parameter missing from Client message over QUIC");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeAuthorizationInfoTwice) {
  MoqtParser parser(kWebTrans, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,              // track_name = "abcd"
      0x02, 0x04,                    // start_group = 4 (relative previous)
      0x01, 0x01,                    // start_object = 1 (absolute)
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x02,                          // two params
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice in SUBSCRIBE_REQUEST");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, AnnounceAuthorizationInfoTwice) {
  MoqtParser parser(kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02,                          // 2 params
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice in ANNOUNCE");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, FinMidPayload) {
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<StreamHeaderGroupMessage>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Received FIN mid-payload");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, PartialPayloadThenFin) {
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<StreamHeaderTrackMessage>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      false);
  parser.ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "End of stream before complete OBJECT PAYLOAD");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, DataAfterFin) {
  MoqtParser parser(kRawQuic, visitor_);
  parser.ProcessData(absl::string_view(), true);  // Find FIN
  parser.ProcessData("foo", false);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Data after end of stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, Setup2KB) {
  MoqtParser parser(kRawQuic, visitor_);
  char big_message[2 * kMaxMessageHeaderSize];
  quic::QuicDataWriter writer(sizeof(big_message), big_message);
  writer.WriteVarInt62(static_cast<uint64_t>(MoqtMessageType::kServerSetup));
  writer.WriteVarInt62(0x1);                    // version
  writer.WriteVarInt62(0x1);                    // num_params
  writer.WriteVarInt62(0xbeef);                 // unknown param
  writer.WriteVarInt62(kMaxMessageHeaderSize);  // very long parameter
  writer.WriteRepeatedByte(0x04, kMaxMessageHeaderSize);
  // Send incomplete message
  parser.ProcessData(absl::string_view(big_message, writer.length() - 1),
                     false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Cannot parse non-OBJECT messages > 2KB");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kInternalError);
}

TEST_F(MoqtMessageSpecificTest, UnknownMessageType) {
  MoqtParser parser(kRawQuic, visitor_);
  char message[4];
  quic::QuicDataWriter writer(sizeof(message), message);
  writer.WriteVarInt62(0xbeef);  // unknown message type
  parser.ProcessData(absl::string_view(message, writer.length()), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Unknown message type");
}

TEST_F(MoqtMessageSpecificTest, StartGroupIsNone) {
  MoqtParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x00,                          // start_group = none
      0x01, 0x01,                    // start_object = 1 (absolute)
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "START_GROUP must not be None in SUBSCRIBE");
}

TEST_F(MoqtMessageSpecificTest, StartObjectIsNone) {
  MoqtParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02, 0x04,                    // start_group = 4 (relative previous)
      0x00,                          // start_object = none
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "START_OBJECT must not be None in SUBSCRIBE");
}

TEST_F(MoqtMessageSpecificTest, EndGroupIsNoneEndObjectIsNoNone) {
  MoqtParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02, 0x04,                    // start_group = 4 (relative previous)
      0x01, 0x01,                    // start_object = 1 (absolute)
      0x00,                          // end_group = none
      0x01, 0x01,                    // end_object = 1 (absolute)
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE end_group and end_object must be both None "
            "or both non_None");
}

TEST_F(MoqtMessageSpecificTest, AllMessagesTogether) {
  char buffer[5000];
  MoqtParser parser(kRawQuic, visitor_);
  size_t write = 0;
  size_t read = 0;
  int fully_received = 0;
  std::unique_ptr<TestMessageBase> prev_message = nullptr;
  for (MoqtMessageType type : message_types) {
    // Each iteration, process from the halfway point of one message to the
    // halfway point of the next.
    if (IsObjectMessage(type)) {
      continue;  // Objects cannot share a stream with other meessages.
    }
    std::unique_ptr<TestMessageBase> message =
        CreateTestMessage(type, kRawQuic);
    memcpy(buffer + write, message->PacketSample().data(),
           message->total_message_size());
    size_t new_read = write + message->total_message_size() / 2;
    parser.ProcessData(absl::string_view(buffer + read, new_read - read),
                       false);
    EXPECT_EQ(visitor_.messages_received_, fully_received);
    if (prev_message != nullptr) {
      EXPECT_TRUE(prev_message->EqualFieldValues(*visitor_.last_message_));
    }
    fully_received++;
    read = new_read;
    write += message->total_message_size();
    prev_message = std::move(message);
  }
  // Deliver the rest
  parser.ProcessData(absl::string_view(buffer + read, write - read), true);
  EXPECT_EQ(visitor_.messages_received_, fully_received);
  EXPECT_TRUE(prev_message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, RelativeLocation) {
  MoqtParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02, 0x00,                    // start_group = 0 (relative previous)
      0x03, 0x00,                    // start_object = 1 (relative next)
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>(*visitor_.last_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  ASSERT_TRUE(message.start_group.has_value());
  ASSERT_FALSE(message.start_group->absolute);
  EXPECT_EQ(message.start_group->relative_value, 0);
  ASSERT_TRUE(message.start_object.has_value());
  ASSERT_FALSE(message.start_object->absolute);
  EXPECT_EQ(message.start_object->relative_value, 1);
}

TEST_F(MoqtMessageSpecificTest, DatagramSuccessful) {
  ObjectDatagramMessage message;
  MoqtObject object;
  absl::string_view payload =
      MoqtParser::ProcessDatagram(message.PacketSample(), object);
  TestMessageBase::MessageStructuredData object_metadata =
      TestMessageBase::MessageStructuredData(object);
  EXPECT_TRUE(message.EqualFieldValues(object_metadata));
  EXPECT_EQ(payload, "foo");
}

TEST_F(MoqtMessageSpecificTest, WrongMessageInDatagram) {
  MoqtParser parser(kRawQuic, visitor_);
  ObjectStreamMessage message;
  MoqtObject object;
  absl::string_view payload =
      MoqtParser::ProcessDatagram(message.PacketSample(), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, TruncatedDatagram) {
  MoqtParser parser(kRawQuic, visitor_);
  ObjectDatagramMessage message;
  message.set_wire_image_size(4);
  MoqtObject object;
  absl::string_view payload =
      MoqtParser::ProcessDatagram(message.PacketSample(), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, VeryTruncatedDatagram) {
  MoqtParser parser(kRawQuic, visitor_);
  char message = 0x40;
  MoqtObject object;
  absl::string_view payload = MoqtParser::ProcessDatagram(
      absl::string_view(&message, sizeof(message)), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkInvalidContentExists) {
  MoqtParser parser(kRawQuic, visitor_);
  SubscribeOkMessage subscribe_ok;
  subscribe_ok.SetInvalidContentExists();
  parser.ProcessData(subscribe_ok.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_OK ContentExists has invalid value");
}

TEST_F(MoqtMessageSpecificTest, SubscribeDoneInvalidContentExists) {
  MoqtParser parser(kRawQuic, visitor_);
  SubscribeDoneMessage subscribe_done;
  subscribe_done.SetInvalidContentExists();
  parser.ProcessData(subscribe_done.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_DONE ContentExists has invalid value");
}

}  // namespace moqt::test
