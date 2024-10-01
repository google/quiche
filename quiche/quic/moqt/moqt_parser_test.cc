// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/str_join.h"
#include "absl/strings/string_view.h"
#include "absl/types/variant.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt::test {

namespace {

using ::testing::AnyOf;
using ::testing::HasSubstr;
using ::testing::Optional;

constexpr std::array kMessageTypes{
    MoqtMessageType::kSubscribe,
    MoqtMessageType::kSubscribeOk,
    MoqtMessageType::kSubscribeError,
    MoqtMessageType::kSubscribeUpdate,
    MoqtMessageType::kUnsubscribe,
    MoqtMessageType::kSubscribeDone,
    MoqtMessageType::kAnnounceCancel,
    MoqtMessageType::kTrackStatusRequest,
    MoqtMessageType::kTrackStatus,
    MoqtMessageType::kAnnounce,
    MoqtMessageType::kAnnounceOk,
    MoqtMessageType::kAnnounceError,
    MoqtMessageType::kUnannounce,
    MoqtMessageType::kClientSetup,
    MoqtMessageType::kServerSetup,
    MoqtMessageType::kGoAway,
    MoqtMessageType::kSubscribeNamespace,
    MoqtMessageType::kSubscribeNamespaceOk,
    MoqtMessageType::kSubscribeNamespaceError,
    MoqtMessageType::kUnsubscribeNamespace,
    MoqtMessageType::kMaxSubscribeId,
    MoqtMessageType::kObjectAck,
};
constexpr std::array kDataStreamTypes{
    MoqtDataStreamType::kStreamHeaderTrack,
    MoqtDataStreamType::kStreamHeaderSubgroup};

using GeneralizedMessageType =
    absl::variant<MoqtMessageType, MoqtDataStreamType>;
}  // namespace

struct MoqtParserTestParams {
  MoqtParserTestParams(MoqtMessageType message_type, bool uses_web_transport)
      : message_type(message_type), uses_web_transport(uses_web_transport) {}
  explicit MoqtParserTestParams(MoqtDataStreamType message_type)
      : message_type(message_type), uses_web_transport(true) {}
  GeneralizedMessageType message_type;
  bool uses_web_transport;
};

std::vector<MoqtParserTestParams> GetMoqtParserTestParams() {
  std::vector<MoqtParserTestParams> params;

  for (MoqtMessageType message_type : kMessageTypes) {
    if (message_type == MoqtMessageType::kClientSetup) {
      for (const bool uses_web_transport : {false, true}) {
        params.push_back(
            MoqtParserTestParams(message_type, uses_web_transport));
      }
    } else {
      // All other types are processed the same for either perspective or
      // transport.
      params.push_back(MoqtParserTestParams(message_type, true));
    }
  }
  for (MoqtDataStreamType type : kDataStreamTypes) {
    params.push_back(MoqtParserTestParams(type));
  }
  return params;
}

std::string TypeFormatter(MoqtMessageType type) {
  return MoqtMessageTypeToString(type);
}
std::string TypeFormatter(MoqtDataStreamType type) {
  return MoqtDataStreamTypeToString(type);
}
std::string ParamNameFormatter(
    const testing::TestParamInfo<MoqtParserTestParams>& info) {
  return absl::visit([](auto x) { return TypeFormatter(x); },
                     info.param.message_type) +
         "_" + (info.param.uses_web_transport ? "WebTransport" : "QUIC");
}

class MoqtParserTestVisitor : public MoqtControlParserVisitor,
                              public MoqtDataParserVisitor {
 public:
  ~MoqtParserTestVisitor() = default;

  void OnObjectMessage(const MoqtObject& message, absl::string_view payload,
                       bool end_of_message) override {
    MoqtObject object = message;
    object_payloads_.push_back(std::string(payload));
    end_of_message_ = end_of_message;
    if (end_of_message) {
      ++messages_received_;
    }
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
  void OnSubscribeUpdateMessage(const MoqtSubscribeUpdate& message) override {
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
  void OnAnnounceCancelMessage(const MoqtAnnounceCancel& message) override {
    OnControlMessage(message);
  }
  void OnTrackStatusRequestMessage(
      const MoqtTrackStatusRequest& message) override {
    OnControlMessage(message);
  }
  void OnUnannounceMessage(const MoqtUnannounce& message) override {
    OnControlMessage(message);
  }
  void OnTrackStatusMessage(const MoqtTrackStatus& message) override {
    OnControlMessage(message);
  }
  void OnGoAwayMessage(const MoqtGoAway& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeNamespaceMessage(
      const MoqtSubscribeNamespace& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeNamespaceOkMessage(
      const MoqtSubscribeNamespaceOk& message) override {
    OnControlMessage(message);
  }
  void OnSubscribeNamespaceErrorMessage(
      const MoqtSubscribeNamespaceError& message) override {
    OnControlMessage(message);
  }
  void OnUnsubscribeNamespaceMessage(
      const MoqtUnsubscribeNamespace& message) override {
    OnControlMessage(message);
  }
  void OnMaxSubscribeIdMessage(const MoqtMaxSubscribeId& message) override {
    OnControlMessage(message);
  }
  void OnObjectAckMessage(const MoqtObjectAck& message) override {
    OnControlMessage(message);
  }
  void OnParsingError(MoqtError code, absl::string_view reason) override {
    QUIC_LOG(INFO) << "Parsing error: " << reason;
    parsing_error_ = reason;
    parsing_error_code_ = code;
  }

  std::string object_payload() { return absl::StrJoin(object_payloads_, ""); }

  std::vector<std::string> object_payloads_;
  bool end_of_message_ = false;
  std::optional<std::string> parsing_error_;
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
        control_parser_(GetParam().uses_web_transport, visitor_),
        data_parser_(&visitor_) {}

  bool IsDataStream() {
    return absl::holds_alternative<MoqtDataStreamType>(message_type_);
  }

  std::unique_ptr<TestMessageBase> MakeMessage() {
    if (IsDataStream()) {
      return CreateTestDataStream(absl::get<MoqtDataStreamType>(message_type_));
    } else {
      return CreateTestMessage(absl::get<MoqtMessageType>(message_type_),
                               webtrans_);
    }
  }

  void ProcessData(absl::string_view data, bool fin) {
    if (IsDataStream()) {
      data_parser_.ProcessData(data, fin);
    } else {
      control_parser_.ProcessData(data, fin);
    }
  }

 protected:
  MoqtParserTestVisitor visitor_;
  GeneralizedMessageType message_type_;
  bool webtrans_;
  MoqtControlParser control_parser_;
  MoqtDataParser data_parser_;
};

INSTANTIATE_TEST_SUITE_P(MoqtParserTests, MoqtParserTest,
                         testing::ValuesIn(GetMoqtParserTestParams()),
                         ParamNameFormatter);

TEST_P(MoqtParserTest, OneMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneMessageWithLongVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->ExpandVarints();
  ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, TwoPartMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  // The test Object message has payload for less then half the message length,
  // so splitting the message in half will prevent the first half from being
  // processed.
  size_t first_data_size = message->total_message_size() / 2;
  ProcessData(message->PacketSample().substr(0, first_data_size), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  ProcessData(
      message->PacketSample().substr(
          first_data_size, message->total_message_size() - first_data_size),
      true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneByteAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    EXPECT_EQ(visitor_.messages_received_, 0);
    EXPECT_FALSE(visitor_.end_of_message_);
    bool last = i == (message->total_message_size() - 1);
    ProcessData(message->PacketSample().substr(i, 1), last);
  }
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneByteAtATimeLongerVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->ExpandVarints();
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    EXPECT_EQ(visitor_.messages_received_, 0);
    EXPECT_FALSE(visitor_.end_of_message_);
    bool last = i == (message->total_message_size() - 1);
    ProcessData(message->PacketSample().substr(i, 1), last);
  }
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, TwoBytesAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  data_parser_.set_chunk_size(1);
  for (size_t i = 0; i < message->total_message_size(); i += 3) {
    EXPECT_EQ(visitor_.messages_received_, 0);
    EXPECT_FALSE(visitor_.end_of_message_);
    bool last = (i + 2) >= message->total_message_size();
    ProcessData(message->PacketSample().substr(i, 3), last);
  }
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  if (IsDataStream()) {
    EXPECT_EQ(visitor_.object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, EarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  size_t first_data_size = message->total_message_size() - 1;
  ProcessData(message->PacketSample().substr(0, first_data_size), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_THAT(visitor_.parsing_error_,
              AnyOf("FIN after incomplete message",
                    "FIN received at an unexpected point in the stream"));
}

TEST_P(MoqtParserTest, SeparateEarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  size_t first_data_size = message->total_message_size() - 1;
  ProcessData(message->PacketSample().substr(0, first_data_size), false);
  ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_THAT(visitor_.parsing_error_,
              AnyOf("End of stream before complete message",
                    "FIN received at an unexpected point in the stream"));
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

// Send the header + some payload, pure payload, then pure payload to end the
// message.
TEST_F(MoqtMessageSpecificTest, ThreePartObject) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>();
  EXPECT_TRUE(message->SetPayloadLength(14));
  parser.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foo");

  // second part
  parser.ProcessData("bar", false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foobar");

  // third part includes FIN
  parser.ProcessData("deadbeef", true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foobardeadbeef");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

// Send the part of header, rest of header + payload, plus payload.
TEST_F(MoqtMessageSpecificTest, ThreePartObjectFirstIncomplete) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>();
  EXPECT_TRUE(message->SetPayloadLength(50));

  // first part
  parser.ProcessData(message->PacketSample().substr(0, 4), false);
  EXPECT_EQ(visitor_.messages_received_, 0);

  // second part. Add padding to it.
  message->set_wire_image_size(55);
  parser.ProcessData(
      message->PacketSample().substr(4, message->total_message_size() - 4),
      false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_FALSE(visitor_.end_of_message_);
  // The value "47" is the overall wire image size of 55 minus the non-payload
  // part of the message.
  EXPECT_EQ(visitor_.object_payload().length(), 47);

  // third part includes FIN
  parser.ProcessData("bar", true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(*visitor_.object_payloads_.crbegin(), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderSubgroupFollowOn) {
  MoqtDataParser parser(&visitor_);
  // first part
  auto message1 = std::make_unique<StreamHeaderSubgroupMessage>();
  parser.ProcessData(message1->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message1->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foo");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // second part
  visitor_.object_payloads_.clear();
  auto message2 = std::make_unique<StreamMiddlerSubgroupMessage>();
  parser.ProcessData(message2->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message2->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderTrackFollowOn) {
  MoqtDataParser parser(&visitor_);
  // first part
  auto message1 = std::make_unique<StreamHeaderTrackMessage>();
  parser.ProcessData(message1->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message1->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "foo");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // second part
  visitor_.object_payloads_.clear();
  auto message2 = std::make_unique<StreamMiddlerTrackMessage>();
  parser.ProcessData(message2->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message2->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_EQ(visitor_.object_payload(), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, ClientSetupRoleIsInvalid) {
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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

TEST_F(MoqtMessageSpecificTest, ClientSetupMaxSubscribeIdAppearsTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions
      0x04,                          // 4 params
      0x00, 0x01, 0x03,              // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x02, 0x01, 0x32,              // max_subscribe_id = 50
      0x02, 0x01, 0x32,              // max_subscribe_id = 50
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "MAX_SUBSCRIBE_ID parameter appears twice in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupRoleIsMissing) {
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kWebTrans, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
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

TEST_F(MoqtMessageSpecificTest, ServerSetupMaxSubscribeIdAppearsTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x04,                          // 4 params
      0x00, 0x01, 0x03,              // role = PubSub
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x02, 0x01, 0x32,              // max_subscribe_id = 50
      0x02, 0x01, 0x32,              // max_subscribe_id = 50
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "MAX_SUBSCRIBE_ID parameter appears twice in SETUP");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeAuthorizationInfoTwice) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02, 0x01, 0x03,
      0x66, 0x6f, 0x6f,              // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x02,                          // two params
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeDeliveryTimeoutTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02, 0x01, 0x03,
      0x66, 0x6f, 0x6f,              // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x02,                          // two params
      0x03, 0x02, 0x67, 0x10,        // delivery_timeout = 10000
      0x03, 0x02, 0x67, 0x10,        // delivery_timeout = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "DELIVERY_TIMEOUT parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeDeliveryTimeoutMalformed) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02, 0x01, 0x03,
      0x66, 0x6f, 0x6f,              // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x01,                          // one param
      0x03, 0x01, 0x67, 0x10,        // delivery_timeout = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "Parameter length does not match varint encoding");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kParameterLengthMismatch);
}

TEST_F(MoqtMessageSpecificTest, SubscribeMaxCacheDurationTwice) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02, 0x01, 0x03,
      0x66, 0x6f, 0x6f,              // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x02,                          // two params
      0x04, 0x02, 0x67, 0x10,        // max_cache_duration = 10000
      0x04, 0x02, 0x67, 0x10,        // max_cache_duration = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "MAX_CACHE_DURATION parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeMaxCacheDurationMalformed) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02, 0x01, 0x03,
      0x66, 0x6f, 0x6f,              // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x01,                          // one param
      0x04, 0x01, 0x67, 0x10,        // max_cache_duration = 10000
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "Parameter length does not match varint encoding");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kParameterLengthMismatch);
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkHasAuthorizationInfo) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char subscribe_ok[] = {
      0x04, 0x01, 0x03,        // subscribe_id = 1, expires = 3
      0x02, 0x01,              // group_order = 2, content exists
      0x0c, 0x14,              // largest_group_id = 12, largest_object_id = 20,
      0x02,                    // 2 parameters
      0x03, 0x02, 0x67, 0x10,  // delivery_timeout = 10000
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe_ok, sizeof(subscribe_ok)),
                     false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_, "SUBSCRIBE_OK has authorization info");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateHasAuthorizationInfo) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char subscribe_update[] = {
      0x02, 0x02, 0x03, 0x01, 0x05, 0x06,  // start and end sequences
      0xaa,                                // priority = 0xaa
      0x01,                                // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_, "SUBSCRIBE_UPDATE has authorization info");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, AnnounceAuthorizationInfoTwice) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02,                                // 2 params
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, AnnounceHasDeliveryTimeout) {
  MoqtControlParser parser(kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02,                                // 2 params
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
      0x03, 0x02, 0x67, 0x10,              // delivery_timeout = 10000
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "ANNOUNCE has delivery timeout");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, FinMidPayload) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "FIN received at an unexpected point in the stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, PartialPayloadThenFin) {
  MoqtDataParser parser(&visitor_);
  auto message = std::make_unique<StreamHeaderTrackMessage>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      false);
  parser.ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_EQ(visitor_.parsing_error_,
            "FIN received at an unexpected point in the stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, DataAfterFin) {
  MoqtControlParser parser(kRawQuic, visitor_);
  parser.ProcessData(absl::string_view(), true);  // Find FIN
  parser.ProcessData("foo", false);
  EXPECT_EQ(visitor_.parsing_error_, "Data after end of stream");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, InvalidObjectStatus) {
  MoqtDataParser parser(&visitor_);
  char stream_header_subgroup[] = {
      0x04,                    // type field
      0x03, 0x04, 0x05, 0x08,  // varints
      0x07,                    // publisher priority
      0x06, 0x00, 0x0f,        // object middler; status = 0x0f
  };
  parser.ProcessData(
      absl::string_view(stream_header_subgroup, sizeof(stream_header_subgroup)),
      false);
  EXPECT_EQ(visitor_.parsing_error_, "Invalid object status provided");
  EXPECT_EQ(visitor_.parsing_error_code_, MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, Setup2KB) {
  MoqtControlParser parser(kRawQuic, visitor_);
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
  MoqtControlParser parser(kRawQuic, visitor_);
  char message[4];
  quic::QuicDataWriter writer(sizeof(message), message);
  writer.WriteVarInt62(0xbeef);  // unknown message type
  parser.ProcessData(absl::string_view(message, writer.length()), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Unknown message type");
}

TEST_F(MoqtMessageSpecificTest, LatestGroup) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x01,                          // filter_type = kLatestGroup
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  ASSERT_TRUE(visitor_.last_message_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_FALSE(message.start_group.has_value());
  EXPECT_EQ(message.start_object, 0);
  EXPECT_FALSE(message.end_group.has_value());
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, LatestObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x02,                          // filter_type = kLatestObject
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_FALSE(message.start_group.has_value());
  EXPECT_FALSE(message.start_object.has_value());
  EXPECT_FALSE(message.end_group.has_value());
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, InvalidDeliveryOrder) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x08,                    // priority = 0x20 ???
      0x01,                          // filter_type = kLatestGroup
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_THAT(visitor_.parsing_error_, Optional(HasSubstr("group order")));
}

TEST_F(MoqtMessageSpecificTest, AbsoluteStart) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x03,                          // filter_type = kAbsoluteStart
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_EQ(message.start_group.value(), 4);
  EXPECT_EQ(message.start_object.value(), 1);
  EXPECT_FALSE(message.end_group.has_value());
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeExplicitEndObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteStart
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x07,                          // end_group = 7
      0x03,                          // end_object = 2
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_EQ(message.start_group.value(), 4);
  EXPECT_EQ(message.start_object.value(), 1);
  EXPECT_EQ(message.end_group.value(), 7);
  EXPECT_EQ(message.end_object.value(), 2);
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeWholeEndGroup) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x07,                          // end_group = 7
      0x00,                          // end whole group
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  MoqtSubscribe message =
      std::get<MoqtSubscribe>(visitor_.last_message_.value());
  EXPECT_EQ(message.start_group.value(), 4);
  EXPECT_EQ(message.start_object.value(), 1);
  EXPECT_EQ(message.end_group.value(), 7);
  EXPECT_FALSE(message.end_object.has_value());
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeEndGroupTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x03,                          // end_group = 3
      0x00,                          // end whole group
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End group is less than start group");
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeExactlyOneObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x04,                          // end_group = 4
      0x02,                          // end object = 1
      0x00,                          // no parameters
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateExactlyOneObject) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x02, 0x03, 0x01, 0x04, 0x07,  // start and end sequences
      0x20,                                // priority
      0x00,                                // No parameters
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateEndGroupTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x02, 0x03, 0x01, 0x03, 0x06,  // start and end sequences
      0x20,                                // priority
      0x01,                                // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End group is less than start group");
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeEndObjectTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe[] = {
      0x03, 0x01, 0x02,              // id and alias
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x20, 0x02,                    // priority = 0x20 descending
      0x04,                          // filter_type = kAbsoluteRange
      0x04,                          // start_group = 4
      0x01,                          // start_object = 1
      0x04,                          // end_group = 4
      0x01,                          // end_object = 0
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(subscribe, sizeof(subscribe)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End object comes before start object");
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateEndObjectTooLow) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x02, 0x03, 0x02, 0x04, 0x01,  // start and end sequences
      0xf0, 0x00,                          // priority, no parameter
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End object comes before start object");
}

TEST_F(MoqtMessageSpecificTest, SubscribeUpdateNoEndGroup) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char subscribe_update[] = {
      0x02, 0x02, 0x03, 0x02, 0x00, 0x01,  // start and end sequences
      0x20,                                // priority
      0x00,                                // No parameter
  };
  parser.ProcessData(
      absl::string_view(subscribe_update, sizeof(subscribe_update)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_UPDATE has end_object but no end_group");
}

TEST_F(MoqtMessageSpecificTest, ObjectAckNegativeDelta) {
  MoqtControlParser parser(kRawQuic, visitor_);
  char object_ack[] = {
      0x71, 0x84,        // type
      0x01, 0x10, 0x20,  // subscribe ID, group, object
      0x40, 0x81,        // -0x40 time delta
  };
  parser.ProcessData(absl::string_view(object_ack, sizeof(object_ack)), false);
  EXPECT_EQ(visitor_.parsing_error_, std::nullopt);
  ASSERT_EQ(visitor_.messages_received_, 1);
  MoqtObjectAck message =
      std::get<MoqtObjectAck>(visitor_.last_message_.value());
  EXPECT_EQ(message.subscribe_id, 0x01);
  EXPECT_EQ(message.group_id, 0x10);
  EXPECT_EQ(message.object_id, 0x20);
  EXPECT_EQ(message.delta_from_deadline,
            quic::QuicTimeDelta::FromMicroseconds(-0x40));
}

TEST_F(MoqtMessageSpecificTest, AllMessagesTogether) {
  char buffer[5000];
  MoqtControlParser parser(kRawQuic, visitor_);
  size_t write = 0;
  size_t read = 0;
  int fully_received = 0;
  std::unique_ptr<TestMessageBase> prev_message = nullptr;
  for (MoqtMessageType type : kMessageTypes) {
    // Each iteration, process from the halfway point of one message to the
    // halfway point of the next.
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

TEST_F(MoqtMessageSpecificTest, DatagramSuccessful) {
  ObjectDatagramMessage message;
  MoqtObject object;
  absl::string_view payload = ParseDatagram(message.PacketSample(), object);
  TestMessageBase::MessageStructuredData object_metadata =
      TestMessageBase::MessageStructuredData(object);
  EXPECT_TRUE(message.EqualFieldValues(object_metadata));
  EXPECT_EQ(payload, "foo");
}

TEST_F(MoqtMessageSpecificTest, WrongMessageInDatagram) {
  StreamHeaderSubgroupMessage message;
  MoqtObject object;
  absl::string_view payload = ParseDatagram(message.PacketSample(), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, TruncatedDatagram) {
  ObjectDatagramMessage message;
  message.set_wire_image_size(4);
  MoqtObject object;
  absl::string_view payload = ParseDatagram(message.PacketSample(), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, VeryTruncatedDatagram) {
  char message = 0x40;
  MoqtObject object;
  absl::string_view payload =
      ParseDatagram(absl::string_view(&message, sizeof(message)), object);
  EXPECT_TRUE(payload.empty());
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkInvalidContentExists) {
  MoqtControlParser parser(kRawQuic, visitor_);
  SubscribeOkMessage subscribe_ok;
  subscribe_ok.SetInvalidContentExists();
  parser.ProcessData(subscribe_ok.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_OK ContentExists has invalid value");
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkInvalidDeliveryOrder) {
  MoqtControlParser parser(kRawQuic, visitor_);
  SubscribeOkMessage subscribe_ok;
  subscribe_ok.SetInvalidDeliveryOrder();
  parser.ProcessData(subscribe_ok.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Invalid group order value in SUBSCRIBE_OK");
}

TEST_F(MoqtMessageSpecificTest, SubscribeDoneInvalidContentExists) {
  MoqtControlParser parser(kRawQuic, visitor_);
  SubscribeDoneMessage subscribe_done;
  subscribe_done.SetInvalidContentExists();
  parser.ProcessData(subscribe_done.PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_DONE ContentExists has invalid value");
}

TEST_F(MoqtMessageSpecificTest, PaddingStream) {
  MoqtDataParser parser(&visitor_);
  std::string buffer(32, '\0');
  quic::QuicDataWriter writer(buffer.size(), buffer.data());
  ASSERT_TRUE(writer.WriteVarInt62(
      static_cast<uint64_t>(MoqtDataStreamType::kPadding)));
  for (int i = 0; i < 100; ++i) {
    parser.ProcessData(buffer, false);
    ASSERT_EQ(visitor_.messages_received_, 0);
    ASSERT_EQ(visitor_.parsing_error_, std::nullopt);
  }
}

}  // namespace moqt::test
