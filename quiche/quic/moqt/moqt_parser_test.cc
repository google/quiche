// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_parser.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"
#include "quiche/quic/moqt/test_tools/moqt_parser_test_visitor.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_status_utils.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"

namespace moqt::test {

namespace {

using ::quiche::test::IsOkAndHolds;
using ::quiche::test::StatusIs;
using ::testing::AnyOf;
using ::testing::HasSubstr;

constexpr std::array kMessageTypes{
    MoqtMessageType::kRequestOk,
    MoqtMessageType::kRequestError,
    MoqtMessageType::kSubscribe,
    MoqtMessageType::kSubscribeOk,
    MoqtMessageType::kRequestUpdate,
    MoqtMessageType::kUnsubscribe,
    MoqtMessageType::kPublishDone,
    MoqtMessageType::kTrackStatus,
    MoqtMessageType::kPublishNamespace,
    MoqtMessageType::kPublishNamespaceDone,
    MoqtMessageType::kNamespace,
    MoqtMessageType::kNamespaceDone,
    MoqtMessageType::kPublishNamespaceCancel,
    MoqtMessageType::kGoAway,
    MoqtMessageType::kSubscribeNamespace,
    MoqtMessageType::kMaxRequestId,
    MoqtMessageType::kFetch,
    MoqtMessageType::kFetchCancel,
    MoqtMessageType::kFetchOk,
    MoqtMessageType::kRequestsBlocked,
    MoqtMessageType::kPublish,
    MoqtMessageType::kObjectAck,
    MoqtMessageType::kSetup,
};

using GeneralizedMessageType =
    std::variant<MoqtMessageType, MoqtDataStreamType>;
}  // namespace

struct MoqtParserTestParams {
  MoqtParserTestParams(
      MoqtMessageType message_type, bool uses_web_transport,
      quic::Perspective perspective = quic::Perspective::IS_SERVER)
      : message_type(message_type),
        uses_web_transport(uses_web_transport),
        perspective(perspective) {}
  explicit MoqtParserTestParams(MoqtDataStreamType message_type)
      : message_type(message_type),
        uses_web_transport(true),
        perspective(quic::Perspective::IS_SERVER) {}

  GeneralizedMessageType message_type;
  bool uses_web_transport;
  quic::Perspective perspective;
};

std::vector<MoqtParserTestParams> GetMoqtParserTestParams() {
  std::vector<MoqtParserTestParams> params;

  for (MoqtMessageType message_type : kMessageTypes) {
    if (message_type == MoqtMessageType::kSetup) {
      for (const bool uses_web_transport : {false, true}) {
        for (const quic::Perspective perspective :
             {quic::Perspective::IS_CLIENT, quic::Perspective::IS_SERVER}) {
          params.push_back(MoqtParserTestParams(
              message_type, uses_web_transport, perspective));
        }
      }
    } else {
      // All other types are processed the same for either perspective or
      // transport.
      params.push_back(MoqtParserTestParams(message_type, true,
                                            quic::Perspective::IS_SERVER));
    }
  }
  for (MoqtDataStreamType type : AllMoqtDataStreamTypes()) {
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
  return std::visit([](auto x) { return TypeFormatter(x); },
                    info.param.message_type) +
         "_" + (info.param.uses_web_transport ? "WebTransport" : "QUIC") + "_" +
         quic::PerspectiveToString(info.param.perspective);
}

std::optional<MoqtError> ExtractMoqtErrorForStatus(const absl::Status& status) {
  if (!absl::IsInvalidArgument(status)) {
    return std::nullopt;
  }
  return GetMoqtErrorForStatus(status).value_or(MoqtError::kProtocolViolation);
}

class MoqtParserTest
    : public quic::test::QuicTestWithParam<MoqtParserTestParams> {
 public:
  MoqtParserTest()
      : message_type_(GetParam().message_type),
        webtrans_(GetParam().uses_web_transport),
        perspective_(GetParam().perspective),
        control_stream_(/*stream_id=*/0),
        control_parser_(&control_stream_),
        message_parser_(kDefaultMoqtVersion, webtrans_, perspective_),
        data_stream_(/*stream_id=*/0),
        data_parser_(&data_stream_, &data_visitor_) {
    // The default object has priority 0x07, so setting this will let the
    // parser set the correct value when absent.
    data_parser_.set_default_publisher_priority(0x07);
  }

  bool IsDataStream() const {
    return std::holds_alternative<MoqtDataStreamType>(message_type_);
  }

  std::unique_ptr<TestMessageBase> MakeMessage() {
    if (IsDataStream()) {
      return CreateTestDataStream(std::get<MoqtDataStreamType>(message_type_));
    }
    return CreateTestMessage(std::get<MoqtMessageType>(message_type_),
                             webtrans_, FlipPerspective(perspective_));
  }

  void ProcessData(absl::string_view data, bool fin) {
    if (IsDataStream()) {
      data_stream_.Receive(data, fin);
      data_parser_.ReadAllData();
      return;
    }
    control_stream_.Receive(data, /*fin=*/false);
    for (;;) {
      absl::StatusOr<MoqtRawControlMessage> message =
          control_parser_.ReadNextMessage();
      if (!message.ok()) {
        if (!absl::IsUnavailable(message.status())) {
          control_parsing_error_ = message.status().message();
        }
        break;
      }
      absl::Status status =
          message_parser_.ParseMessage(*message, [&](auto message) {
            control_messages_.push_back(std::move(message));
            return absl::OkStatus();
          });
      if (!status.ok()) {
        control_parsing_error_ = status.message();
        break;
      }
    }
  }

 protected:
  size_t messages_received() const {
    return IsDataStream() ? data_visitor_.messages_received()
                          : control_messages_.size();
  }

  std::optional<TestMessageBase::MessageStructuredData> last_message() const {
    if (IsDataStream()) {
      return data_visitor_.last_message();
    }
    if (control_messages_.empty()) {
      return std::nullopt;
    }
    return control_messages_.back();
  }
  bool end_of_message() const {
    return IsDataStream() ? data_visitor_.end_of_message()
                          : !control_messages_.empty();
  }
  std::optional<std::string> parsing_error() const {
    return IsDataStream() ? data_visitor_.parsing_error()
                          : control_parsing_error_;
  }
  std::string object_payload() const {
    QUICHE_DCHECK(IsDataStream());
    return data_visitor_.object_payload();
  }

  GeneralizedMessageType message_type_;
  bool webtrans_;
  quic::Perspective perspective_;
  webtransport::test::InMemoryStream control_stream_;
  MoqtControlStreamParser control_parser_;
  MoqtControlMessageParser message_parser_;
  webtransport::test::InMemoryStream data_stream_;
  MoqtDataParser data_parser_;

 private:
  std::vector<TestMessageBase::MessageStructuredData> control_messages_;
  std::optional<std::string> control_parsing_error_;
  MoqtParserTestVisitor data_visitor_;
};

INSTANTIATE_TEST_SUITE_P(MoqtParserTests, MoqtParserTest,
                         testing::ValuesIn(GetMoqtParserTestParams()),
                         ParamNameFormatter);

TEST_P(MoqtParserTest, OneMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->MakeObjectEndOfStream();
  ProcessData(message->PacketSample(), true);
  ASSERT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneMessageWithLongVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->ExpandVarints();
  ProcessData(message->PacketSample(), false);
  EXPECT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  EXPECT_EQ(parsing_error(), std::nullopt);
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, TwoPartMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->MakeObjectEndOfStream();
  // The test Object message has payload for less then half the message length,
  // so splitting the message in half will prevent the first half from being
  // processed.
  size_t first_data_size = message->total_message_size() / 2;
  ProcessData(message->PacketSample().substr(0, first_data_size), false);
  EXPECT_EQ(messages_received(), 0);
  ProcessData(
      message->PacketSample().substr(
          first_data_size, message->total_message_size() - first_data_size),
      true);
  EXPECT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  EXPECT_FALSE(parsing_error().has_value());
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneByteAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->MakeObjectEndOfStream();
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    EXPECT_EQ(messages_received(), 0);
    EXPECT_FALSE(end_of_message());
    bool last = i == (message->total_message_size() - 1);
    ProcessData(message->PacketSample().substr(i, 1), last);
  }
  EXPECT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  EXPECT_FALSE(parsing_error().has_value());
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

// In OneByteAtATime, the message is received one byte at a time, and
// immediately processed; here, it is received all at once, but the stream
// receive buffer is represented as a sequence of one-byte chunks.
TEST_P(MoqtParserTest, OneByteAtATimePeek) {
  control_stream_.set_peek_one_byte_at_a_time(true);
  data_stream_.set_peek_one_byte_at_a_time(true);
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->MakeObjectEndOfStream();
  ProcessData(message->PacketSample(), true);
  ASSERT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, OneByteAtATimeLongerVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->ExpandVarints();
  message->MakeObjectEndOfStream();
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    EXPECT_EQ(messages_received(), 0);
    EXPECT_FALSE(end_of_message());
    bool last = i == (message->total_message_size() - 1);
    ProcessData(message->PacketSample().substr(i, 1), last);
  }
  EXPECT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  EXPECT_FALSE(parsing_error().has_value());
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, TwoBytesAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->MakeObjectEndOfStream();
  for (size_t i = 0; i < message->total_message_size(); i += 3) {
    EXPECT_EQ(messages_received(), 0);
    EXPECT_FALSE(end_of_message());
    bool last = (i + 3) >= message->total_message_size();
    ProcessData(message->PacketSample().substr(i, 3), last);
  }
  EXPECT_EQ(messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*last_message()));
  EXPECT_TRUE(end_of_message());
  EXPECT_FALSE(parsing_error().has_value());
  if (IsDataStream()) {
    EXPECT_EQ(object_payload(), "foo");
  }
}

TEST_P(MoqtParserTest, EarlyFin) {
  if (!IsDataStream()) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  size_t first_data_size = message->total_message_size() - 1;
  ProcessData(message->PacketSample().substr(0, first_data_size), true);
  EXPECT_EQ(messages_received(), 0);
  EXPECT_THAT(parsing_error(),
              AnyOf("FIN after incomplete message",
                    "FIN received at an unexpected point in the stream"));
}

TEST_P(MoqtParserTest, SeparateEarlyFin) {
  if (!IsDataStream()) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  size_t first_data_size = message->total_message_size() - 1;
  ProcessData(message->PacketSample().substr(0, first_data_size), false);
  ProcessData(absl::string_view(), true);
  EXPECT_EQ(messages_received(), 0);
  EXPECT_THAT(parsing_error(),
              AnyOf("FIN after incomplete message",
                    "FIN received at an unexpected point in the stream"));
}

TEST_P(MoqtParserTest, PayloadLengthTooLong) {
  if (IsDataStream()) {
    return;
  }
  MoqtMessageType type = std::get<MoqtMessageType>(message_type_);
  if (type == MoqtMessageType::kSubscribeOk ||
      type == MoqtMessageType::kFetchOk || type == MoqtMessageType::kPublish) {
    // These message types have extensions, which use the length field to
    // determine the size. It is therefore not processed correctly.
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->IncreasePayloadLengthByOne();
  ProcessData(message->PacketSample(), false);
  EXPECT_EQ(messages_received(), 0);
  EXPECT_TRUE(parsing_error().has_value());
}

TEST_P(MoqtParserTest, PayloadLengthTooShort) {
  if (IsDataStream()) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage();
  message->DecreasePayloadLengthByOne();
  ProcessData(message->PacketSample(), false);
  EXPECT_EQ(messages_received(), 0);
  EXPECT_TRUE(parsing_error().has_value());
}

// Tests for message-specific error cases, and behaviors for a single message
// type.
class MoqtMessageSpecificTest : public quic::test::QuicTest {
 public:
  MoqtMessageSpecificTest() {}

  absl::StatusOr<std::vector<AnyMoqtControlMessage>> ParseAllMessages(
      absl::string_view data,
      absl::string_view moqt_version = kDefaultMoqtVersion,
      bool uses_web_transport = true,
      quic::Perspective perspective = quic::Perspective::IS_SERVER) {
    webtransport::test::InMemoryStream stream(/*stream_id=*/0);
    stream.Receive(data, /*fin=*/true);
    MoqtControlStreamParser stream_parser(&stream);
    stream_parser.set_allow_fin(true);
    MoqtControlMessageParser message_parser(moqt_version, uses_web_transport,
                                            perspective);
    std::vector<AnyMoqtControlMessage> result;
    while (!stream_parser.fin_read()) {
      absl::StatusOr<MoqtRawControlMessage> raw_message =
          stream_parser.ReadNextMessage();
      // ParseAllMessages expects a sequence of complete messages.
      if (absl::IsUnavailable(raw_message.status())) {
        return absl::InvalidArgumentError("Incomplete control message");
      }
      QUICHE_RETURN_IF_ERROR(raw_message.status());
      QUICHE_RETURN_IF_ERROR(
          message_parser.ParseMessage(*raw_message, [&](auto message) {
            result.push_back(std::move(message));
            return absl::OkStatus();
          }));
    }
    return std::move(result);
  }

  static constexpr bool kWebTrans = true;
  static constexpr bool kRawQuic = false;
};

// Send the header + some payload, pure payload, then pure payload to end the
// message.
TEST_F(MoqtMessageSpecificTest, ThreePartObject) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(1, 1, true, false);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>(type);
  EXPECT_TRUE(message->SetPayloadLength(14));
  message->set_wire_image_size(message->total_message_size() - 11);
  stream.Receive(message->PacketSample(), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  EXPECT_TRUE(message->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_FALSE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload(), "foo");

  // second part
  stream.Receive("bar", false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  EXPECT_TRUE(message->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_FALSE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload(), "foobar");

  // third part includes FIN
  stream.Receive("deadbeef", true);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
  EXPECT_TRUE(data_visitor.fin_received());
  EXPECT_EQ(data_visitor.object_payload(), "foobardeadbeef");
  EXPECT_FALSE(data_visitor.parsing_error().has_value());
}

// Send the part of header, rest of header + payload, plus payload.
TEST_F(MoqtMessageSpecificTest, ThreePartObjectFirstIncomplete) {
  uint8_t payload_length = 51;
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(2, 1, false, false);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>(type);
  EXPECT_TRUE(message->SetPayloadLength(payload_length));

  // first part
  stream.Receive(message->PacketSample().substr(0, 4), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);

  // second part. Add padding to it.
  stream.Receive(
      message->PacketSample().substr(4, message->total_message_size() - 7),
      false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  EXPECT_TRUE(message->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_FALSE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload().length(), payload_length - 3);

  // third part includes FIN
  stream.Receive("bar", true);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 1);
  EXPECT_TRUE(message->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
  EXPECT_TRUE(data_visitor.fin_received());
  EXPECT_EQ(*data_visitor.object_payloads().crbegin(), "bar");
  EXPECT_FALSE(data_visitor.parsing_error().has_value());
}

TEST_F(MoqtMessageSpecificTest, ObjectSplitInExtension) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(2, 1, false, false);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>(type);

  // first part
  stream.Receive(message->PacketSample().substr(0, 10), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);

  // second part
  stream.Receive(
      message->PacketSample().substr(10, sizeof(message->total_message_size())),
      false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 1);
  EXPECT_TRUE(data_visitor.last_message().has_value() &&
              message->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderSubgroupFollowOn) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  // first part
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(0, 1, false, false);
  auto message1 = std::make_unique<StreamHeaderSubgroupMessage>(type);
  stream.Receive(message1->PacketSample(), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 1);
  EXPECT_TRUE(message1->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload(), "foo");
  EXPECT_FALSE(data_visitor.parsing_error().has_value());
  // second part
  data_visitor.object_payloads().clear();
  auto message2 = std::make_unique<StreamMiddlerSubgroupMessage>(type);
  stream.Receive(message2->PacketSample(), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 2);
  EXPECT_TRUE(message2->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload(), "bar");
  EXPECT_FALSE(data_visitor.parsing_error().has_value());
}

TEST_F(MoqtMessageSpecificTest, StreamHeaderSubgroupFollowOnExpandedVarInts) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  // first part
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(0, 1, false, false);
  auto message1 = std::make_unique<StreamHeaderSubgroupMessage>(type);
  message1->ExpandVarints();
  stream.Receive(message1->PacketSample(), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 1);
  EXPECT_TRUE(message1->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload(), "foo");
  EXPECT_FALSE(data_visitor.parsing_error().has_value());
  // second part
  data_visitor.object_payloads().clear();
  auto message2 = std::make_unique<StreamMiddlerSubgroupMessage>(type);
  message2->ExpandVarints();
  stream.Receive(message2->PacketSample(), false);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 2);
  EXPECT_TRUE(message2->EqualFieldValues(*data_visitor.last_message()));
  EXPECT_TRUE(data_visitor.end_of_message());
  EXPECT_EQ(data_visitor.object_payload(), "bar");
  EXPECT_FALSE(data_visitor.parsing_error().has_value());
}

TEST_F(MoqtMessageSpecificTest, ClientSetupMaxRequestIdAppearsTwice) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x0a,
      0x03,                          // 3 params
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x01, 0x32,                    // max_request_id = 50
      0x00, 0x32,                    // max_request_id = 50
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(setup, sizeof(setup)));
  EXPECT_THAT(parsed, StatusIs(absl::StatusCode::kInvalidArgument,
                               HasSubstr("Duplicate Setup Parameter")));
}

TEST_F(MoqtMessageSpecificTest, ServerSetupAuthorizationTokenTagRegister) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x0b,
      0x02,                                            // 2 params
      0x02, 0x32,                                      // max_request_id = 50
      0x01, 0x06, 0x01, 0x10, 0x00, 0x62, 0x61, 0x72,  // REGISTER 0x01
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(setup, sizeof(setup)),
                       kDefaultMoqtVersion, true, quic::Perspective::IS_CLIENT);
  // No error even though the registration exceeds the max cache size of 0.
  QUICHE_EXPECT_OK(parsed.status());
}

TEST_F(MoqtMessageSpecificTest, SetupPathFromServer) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x06,
      0x01,                          // 1 param
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(setup, sizeof(setup)),
                       kDefaultMoqtVersion, true, quic::Perspective::IS_CLIENT);
  ASSERT_THAT(parsed.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Setup parameter parsing error")));
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kInvalidPath);
}

TEST_F(MoqtMessageSpecificTest, SetupAuthorityFromServer) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x06,
      0x01,                          // 1 param
      0x05, 0x03, 0x66, 0x6f, 0x6f,  // authority = "foo"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(setup, sizeof(setup)),
                       kDefaultMoqtVersion, true, quic::Perspective::IS_CLIENT);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kInvalidAuthority);
}

TEST_F(MoqtMessageSpecificTest, SetupPathAppearsTwice) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x0b,
      0x02,                          // 2 params
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x00, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SetupPathOverWebtrans) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x06,
      0x01,                          // 1 param
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kWebTrans);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kInvalidPath);
}

TEST_F(MoqtMessageSpecificTest, SetupAuthorityOverWebtrans) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x06,
      0x01,                          // 1 param
      0x05, 0x03, 0x66, 0x6f, 0x6f,  // authority = "foo"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kWebTrans);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kInvalidAuthority);
}

TEST_F(MoqtMessageSpecificTest, SetupPathMissing) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x01,
      0x00,  // no param
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kInvalidPath);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupMaxRequestIdAppearsTwice) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x05, 0x02,  // 2 params
      0x02, 0x32,                    // max_request_id = 50
      0x00, 0x32,                    // max_request_id = 50
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic,
      quic::Perspective::IS_CLIENT);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ClientSetupMalformedPath) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x06,
      0x01,                          // 1 param
      0x01, 0x03, 0x66, 0x5c, 0x6f,  // path = "f\o"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kMalformedPath);
}

TEST_F(MoqtMessageSpecificTest, ClientSetupMalformedAuthority) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x0b,
      0x02,                          // 2 params
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x04, 0x03, 0x66, 0x5c, 0x6f,  // authority = "f\o"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kMalformedAuthority);
}

TEST_F(MoqtMessageSpecificTest, ServerSetupUnknownParameterIsOk) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x0b,
      0x02,                          // 2 params
      0x1f, 0x03, 0x62, 0x61, 0x72,  // 0x1f = "bar"
      0x00, 0x03, 0x62, 0x61, 0x72,  // 0x1f = "bar"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic,
      quic::Perspective::IS_CLIENT);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSetup message = std::get<MoqtSetup>((*parsed)[0]);
  EXPECT_EQ(message.parameters, SetupParameters());
}

TEST_F(MoqtMessageSpecificTest, SubscribeDeliveryTimeoutTwice) {
  char subscribe[] = {
      0x03, 0x00, 0x12, 0x01, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02,                          // two params
      0x02, 0x67, 0x10,              // delivery_timeout = 10000
      0x00, 0x67, 0x10,              // delivery_timeout = 10000
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeAuthorizationTokenTagDelete) {
  char subscribe[] = {
      0x03, 0x00, 0x10, 0x01, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // one param
      0x03, 0x02, 0x00, 0x00         // authorization_token = DELETE 0;
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  ASSERT_FALSE(message.parameters.authorization_tokens.empty());
  EXPECT_EQ(message.parameters.authorization_tokens[0].alias_type,
            AuthTokenAliasType::kDelete);
}

TEST_F(MoqtMessageSpecificTest, SubscribeAuthorizationTokenTagRegister) {
  char subscribe[] = {
      0x03, 0x00, 0x14, 0x01, 0x01, 0x03, 0x66, 0x6f,
      0x6f,                          // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // one param
      0x03, 0x06, 0x01, 0x10, 0x00, 0x62, 0x61, 0x72,  // REGISTER 0x01
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  ASSERT_FALSE(message.parameters.authorization_tokens.empty());
  EXPECT_EQ(message.parameters.authorization_tokens[0].alias_type,
            AuthTokenAliasType::kRegister);
}

TEST_F(MoqtMessageSpecificTest,
       SubscribeAuthorizationTokenTagUnknownAliasType) {
  char subscribe[] = {
      0x03, 0x00, 0x10, 0x01, 0x01,
      0x03, 0x66, 0x6f, 0x6f,        // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // one param
      0x03, 0x02, 0x04, 0x07,        // authorization_token type 4
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kKeyValueFormattingError);
}

TEST_F(MoqtMessageSpecificTest,
       SubscribeAuthorizationTokenTagUnknownTokenType) {
  char subscribe[] = {
      0x03, 0x00, 0x12, 0x01, 0x01, 0x03,
      0x66, 0x6f, 0x6f,                   // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,       // track_name = "abcd"
      0x01,                               // one param
      0x03, 0x04, 0x03, 0x01, 0x00, 0x00  // authorization_token type 1
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kKeyValueFormattingError);
}

TEST_F(MoqtMessageSpecificTest, SubscribeInvalidForward) {
  char subscribe[] = {
      0x03, 0x00, 0x0e, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 2 parameters
      0x10, 0x02                     // forward = 2
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, SubscribeInvalidFilter) {
  char subscribe[] = {
      0x03, 0x00, 0x0f, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x21, 0x01, 0x10               // filter_type = 0x10
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, PublishNamespaceAuthorizationTokenTwice) {
  char publish_namespace[] = {
      0x06, 0x00, 0x15, 0x02, 0x01, 0x03, 0x66,
      0x6f, 0x6f,                                // track_namespace = "foo"
      0x02,                                      // 2 params
      0x03, 0x05, 0x03, 0x00, 0x62, 0x61, 0x72,  // authorization = "bar"
      0x00, 0x05, 0x03, 0x00, 0x62, 0x61, 0x72,  // authorization = "bar"
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(publish_namespace, sizeof(publish_namespace)),
      kDefaultMoqtVersion, kWebTrans);
  EXPECT_TRUE(parsed.ok());
  EXPECT_EQ(parsed->size(), 1);
}

TEST_F(MoqtMessageSpecificTest, CannotAccessAfterError1) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  stream.Receive("\xff", /*fin=*/true);
  MoqtControlStreamParser parser(&stream);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(parser.ReadFirstMessageType().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(MoqtMessageSpecificTest, CannotAccessAfterError2) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  stream.Receive("\x03\xff\xff");
  MoqtControlStreamParser parser(&stream);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_THAT(parser.ReadFirstMessageType(),
              IsOkAndHolds(MoqtMessageType::kSubscribe));
}

TEST_F(MoqtMessageSpecificTest, FinMidType) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  stream.Receive("\xff", /*fin=*/true);
  MoqtControlStreamParser parser(&stream);
  parser.set_allow_fin(true);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(MoqtMessageSpecificTest, FinMidLength) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  stream.Receive(absl::string_view("\0\0", 2), /*fin=*/true);
  MoqtControlStreamParser parser(&stream);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(MoqtMessageSpecificTest, FinMidControlPayload) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  stream.Receive(absl::string_view("\x00\x00\xff ", 4), /*fin=*/false);
  MoqtControlStreamParser parser(&stream);
  ASSERT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kUnavailable));

  stream.Receive("test", /*fin=*/true);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("250 bytes left in the current message")));
}

TEST_F(MoqtMessageSpecificTest, FinMidDataPayload) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(0, 1, true, false);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>(type);
  stream.Receive(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      true);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  ASSERT_TRUE(data_visitor.parsing_error().has_value());
  EXPECT_THAT(
      data_visitor.parsing_error().value(),
      AnyOf(HasSubstr("FIN after incomplete message"),
            HasSubstr("FIN received at an unexpected point in the stream")));
}

TEST_F(MoqtMessageSpecificTest, FinMidExtension) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(0, 1, false, false);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>(type);
  // Read up to the extension body and then FIN.
  stream.Receive(message->PacketSample().substr(0, 7), true);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  ASSERT_TRUE(data_visitor.parsing_error().has_value());
  EXPECT_THAT(
      data_visitor.parsing_error().value(),
      AnyOf(HasSubstr("FIN after incomplete message"),
            HasSubstr("FIN received at an unexpected point in the stream")));
}

TEST_F(MoqtMessageSpecificTest, PartialPayloadThenFin) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(1, 1, false, false);
  auto message = std::make_unique<StreamHeaderSubgroupMessage>(type);
  stream.Receive(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      false);
  parser.ReadAllData();
  stream.Receive(absl::string_view(), true);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  ASSERT_TRUE(data_visitor.parsing_error().has_value());
  EXPECT_THAT(
      data_visitor.parsing_error().value(),
      AnyOf(HasSubstr("FIN after incomplete message"),
            HasSubstr("FIN received at an unexpected point in the stream")));
}

TEST_F(MoqtMessageSpecificTest, FinMidVarint) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  stream.Receive("\x40", true);
  parser.ReadAllData();
  EXPECT_EQ(data_visitor.messages_received(), 0);
  ASSERT_TRUE(data_visitor.parsing_error().has_value());
  EXPECT_THAT(
      data_visitor.parsing_error().value(),
      AnyOf(HasSubstr("FIN after incomplete message"),
            HasSubstr("FIN received at an unexpected point in the stream")));
}

TEST_F(MoqtMessageSpecificTest, ControlStreamFinWhenAllowed) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtControlStreamParser parser(&stream);
  parser.set_allow_fin(true);
  stream.Receive(absl::string_view("\0\0\0", 3), true);
  EXPECT_FALSE(parser.fin_read());
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kOk));
  EXPECT_TRUE(parser.fin_read());
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
  EXPECT_TRUE(parser.fin_read());
}

TEST_F(MoqtMessageSpecificTest, ControlStreamFinWhenAllowedSeparateFin) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtControlStreamParser parser(&stream);
  parser.set_allow_fin(true);
  stream.Receive(absl::string_view("\0\0\0", 3), false);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kOk));
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kUnavailable));
  EXPECT_FALSE(parser.fin_read());

  stream.Receive(absl::string_view(), true);
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kUnavailable));
  EXPECT_TRUE(parser.fin_read());
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(MoqtMessageSpecificTest, ControlStreamFinWhenDisallowed) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtControlStreamParser parser(&stream);
  stream.Receive(absl::string_view(), true);
  EXPECT_FALSE(parser.fin_read());
  EXPECT_THAT(parser.ReadNextMessage().status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("FIN on a control stream")));
}

TEST_F(MoqtMessageSpecificTest, ControlStreamReadType) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtControlStreamParser parser(&stream);
  stream.Receive("\x03", false);
  absl::StatusOr<MoqtMessageType> type = parser.ReadFirstMessageType();
  EXPECT_THAT(type, IsOkAndHolds(MoqtMessageType::kSubscribe));
}

TEST_F(MoqtMessageSpecificTest, ControlStreamFinBeforeType) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtControlStreamParser parser(&stream);
  stream.Receive("", true);
  absl::StatusOr<MoqtMessageType> type = parser.ReadFirstMessageType();
  EXPECT_EQ(type.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST_F(MoqtMessageSpecificTest, ControlStreamFinInTheMiddleOfType) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtControlStreamParser parser(&stream);
  stream.Receive("\xff", true);
  absl::StatusOr<MoqtMessageType> type = parser.ReadFirstMessageType();
  EXPECT_EQ(type.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST_F(MoqtMessageSpecificTest, InvalidObjectStatus) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor data_visitor;
  MoqtDataParser parser(&stream, &data_visitor);
  char stream_header_subgroup[] = {
      0x15,                    // type field
      0x04, 0x05, 0x08,        // varints
      0x07,                    // publisher priority
      0x06, 0x00, 0x00, 0x0f,  // object middler; status = 0x0f
  };
  stream.Receive(
      absl::string_view(stream_header_subgroup, sizeof(stream_header_subgroup)),
      false);
  parser.ReadAllData();
  ASSERT_TRUE(data_visitor.parsing_error().has_value());
  EXPECT_THAT(data_visitor.parsing_error().value(),
              HasSubstr("Invalid object status provided"));
}

TEST_F(MoqtMessageSpecificTest, Setup2KB) {
  char big_message[2 * kMaxMessageHeaderSize];
  quic::QuicDataWriter writer(sizeof(big_message), big_message);
  writer.WriteMoqVarInt(static_cast<uint64_t>(MoqtMessageType::kSetup));
  writer.WriteUInt16(8 + kMaxMessageHeaderSize);
  writer.WriteMoqVarInt(0x1);                    // version
  writer.WriteMoqVarInt(0x1);                    // num_params
  writer.WriteMoqVarInt(0xbeef);                 // unknown param
  writer.WriteMoqVarInt(kMaxMessageHeaderSize);  // very long parameter
  writer.WriteRepeatedByte(0x04, kMaxMessageHeaderSize);
  // Send incomplete message
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(big_message, writer.length()),
                       kDefaultMoqtVersion, true, quic::Perspective::IS_CLIENT);
  EXPECT_THAT(
      parsed.status(),
      StatusIs(absl::StatusCode::kInvalidArgument,
               HasSubstr("control message exceeds the maximum allowed size")));
}

TEST_F(MoqtMessageSpecificTest, UnknownMessageType) {
  char message[7];
  quic::QuicDataWriter writer(sizeof(message), message);
  writer.WriteMoqVarInt(0xbeef);  // unknown message type
  writer.WriteUInt16(0x1);        // length
  writer.WriteMoqVarInt(0x1);     // payload
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(message, writer.length()));
  EXPECT_THAT(parsed.status(),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Unknown control message type 0xbeef")));
}

TEST_F(MoqtMessageSpecificTest, SubscribeNoParameters) {
  char subscribe[] = {
      0x03, 0x00, 0x0c, 0x01,        // request_id = 1
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x00,                          // 0 parameters
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  EXPECT_FALSE(message.parameters.delivery_timeout.has_value());
  EXPECT_FALSE(message.parameters.forward_has_value());
  EXPECT_FALSE(message.parameters.subscription_filter.has_value());
  EXPECT_FALSE(message.parameters.group_order.has_value());
  EXPECT_FALSE(message.parameters.oack_window_size.has_value());
  EXPECT_TRUE(message.parameters.authorization_tokens.empty());
  EXPECT_FALSE(message.parameters.expires.has_value());
  EXPECT_FALSE(message.parameters.subscriber_priority);
  EXPECT_FALSE(message.parameters.largest_object.has_value());
  EXPECT_FALSE(message.parameters.new_group_request.has_value());
}

TEST_F(MoqtMessageSpecificTest, SubscribeUnknownParameter) {
  char subscribe[] = {
      0x03, 0x00, 0x0f, 0x01,        // request_id = 1
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 0 parameters
      0x40, 0x60, 0x01,              // unknown parameter = 0x60
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, LargestObject) {
  char subscribe[] = {
      0x03, 0x00, 0x0f, 0x01,        // request_id = 1
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x21, 0x01, 0x02,              // filter_type = kLargestObject
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  ASSERT_TRUE(message.parameters.subscription_filter.has_value());
  SubscriptionFilter& filter = *message.parameters.subscription_filter;
  EXPECT_TRUE(filter.type() == MoqtFilterType::kLargestObject);
}

TEST_F(MoqtMessageSpecificTest, InvalidDeliveryOrder) {
  char subscribe[] = {
      0x03, 0x00, 0x0e, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x22, 0x03,                    // invalid group order = 3
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, NextGroupStart) {
  char subscribe[] = {
      0x03, 0x00, 0x0f, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x21, 0x01, 0x01,              // filter_type = kNextGroupStart
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  ASSERT_TRUE(message.parameters.subscription_filter.has_value());
  SubscriptionFilter& filter = *message.parameters.subscription_filter;
  EXPECT_TRUE(filter.type() == MoqtFilterType::kNextGroupStart);
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRange) {
  char subscribe[] = {
      0x03, 0x00, 0x12, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x21, 0x04, 0x04, 0x04, 0x01,
      0x03  // filter_type = kAbsoluteRange
            // (4,1) to 7
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  ASSERT_TRUE(message.parameters.subscription_filter.has_value());
  SubscriptionFilter& filter = *message.parameters.subscription_filter;
  EXPECT_TRUE(filter.type() == MoqtFilterType::kAbsoluteRange &&
              filter.start() == Location(4, 1) && filter.end_group() == 7);
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeEndGroupTooLow) {
  char subscribe[] = {
      0x03, 0x00, 0x12, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x21, 0x04, 0x04, 0x04, 0x01, 0xff, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff  // filter_type = kAbsoluteRange
                                          // (4,1) to 3
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kKeyValueFormattingError);
}

TEST_F(MoqtMessageSpecificTest, AbsoluteRangeExactlyOneGroup) {
  char subscribe[] = {
      0x03, 0x00, 0x12, 0x01,        // id
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x01,                          // 1 parameter
      0x21, 0x04, 0x04, 0x04, 0x01,
      0x00  // filter_type = kAbsoluteRange
            // (4,1) to 4
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe, sizeof(subscribe)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtSubscribe message = std::get<MoqtSubscribe>((*parsed)[0]);
  EXPECT_EQ(message.parameters.subscription_filter->end_group(), 4);
}

TEST_F(MoqtMessageSpecificTest, RequestUpdateEndGroupTooLow) {
  char request_update[] = {
      0x02, 0x00, 0x09, 0x02, 0x00,  // request IDs
      0x01, 0x21, 0x04, 0x04, 0x04, 0x01, 0xff,
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // filter
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(request_update, sizeof(request_update)),
      kDefaultMoqtVersion, kRawQuic);
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kKeyValueFormattingError);
}

TEST_F(MoqtMessageSpecificTest, ObjectAckNegativeDelta) {
  char object_ack[] = {
      0xb1, 0x84, 0x00, 0x05,  // type
      0x01, 0x10, 0x20,        // subscribe ID, group, object
      0x80, 0x81,              // -0x40 time delta
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(object_ack, sizeof(object_ack)),
                       kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1);
  MoqtObjectAck message = std::get<MoqtObjectAck>((*parsed)[0]);
  EXPECT_EQ(message.subscribe_id, 0x01);
  EXPECT_EQ(message.group_id, 0x10);
  EXPECT_EQ(message.object_id, 0x20);
  EXPECT_EQ(message.delta_from_deadline,
            quic::QuicTimeDelta::FromMicroseconds(-0x40));
}

TEST_F(MoqtMessageSpecificTest, AllMessagesTogether) {
  std::string buffer;
  for (MoqtMessageType type : kMessageTypes) {
    std::unique_ptr<TestMessageBase> message =
        CreateTestMessage(type, kRawQuic);
    buffer += message->PacketSample();
  }
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(buffer, kDefaultMoqtVersion, kRawQuic);
  ASSERT_TRUE(parsed.ok());
}

TEST_F(MoqtMessageSpecificTest, DatagramSuccessful) {
  for (MoqtDatagramType datagram_type : AllMoqtDatagramTypes()) {
    ObjectDatagramMessage message(datagram_type);
    MoqtObject object;
    bool use_default_priority;
    std::optional<absl::string_view> payload =
        ParseDatagram(message.PacketSample(), object, use_default_priority);
    EXPECT_EQ(use_default_priority, datagram_type.has_default_priority());
    ASSERT_TRUE(payload.has_value());
    if (use_default_priority) {
      object.publisher_priority = message.publisher_priority();
    }
    TestMessageBase::MessageStructuredData object_metadata =
        TestMessageBase::MessageStructuredData(object);
    EXPECT_TRUE(message.EqualFieldValues(object_metadata));
    if (datagram_type.has_status()) {
      EXPECT_EQ(payload, "");
    } else {
      EXPECT_EQ(payload, "foo");
    }
  }
}

TEST_F(MoqtMessageSpecificTest, DatagramSuccessfulExpandVarints) {
  for (MoqtDatagramType datagram_type : AllMoqtDatagramTypes()) {
    ObjectDatagramMessage message(datagram_type);
    message.ExpandVarints();
    MoqtObject object;
    bool check_priority;
    std::optional<absl::string_view> payload =
        ParseDatagram(message.PacketSample(), object, check_priority);
    EXPECT_EQ(check_priority, datagram_type.has_default_priority());
    ASSERT_TRUE(payload.has_value());
    if (check_priority) {
      object.publisher_priority = message.publisher_priority();
    }
    TestMessageBase::MessageStructuredData object_metadata =
        TestMessageBase::MessageStructuredData(object);
    EXPECT_TRUE(message.EqualFieldValues(object_metadata));
    if (datagram_type.has_status()) {
      EXPECT_EQ(payload, "");
    } else {
      EXPECT_EQ(payload, "foo");
    }
  }
}

TEST_F(MoqtMessageSpecificTest, WrongMessageInDatagram) {
  char payload[] = {0x33, 0x10, 0x20};
  MoqtObject object;
  bool check_priority;
  EXPECT_EQ(ParseDatagram(absl::string_view(payload, sizeof(payload)), object,
                          check_priority),
            std::nullopt);
}

TEST_F(MoqtMessageSpecificTest, TruncatedDatagram) {
  ObjectDatagramMessage message(
      MoqtDatagramType(false, true, false, false, false));
  message.set_wire_image_size(4);
  MoqtObject object;
  bool check_priority;
  EXPECT_EQ(ParseDatagram(message.PacketSample(), object, check_priority),
            std::nullopt);
}

TEST_F(MoqtMessageSpecificTest, VeryTruncatedDatagram) {
  char message = 0x40;
  MoqtObject object;
  bool check_priority;
  EXPECT_EQ(ParseDatagram(absl::string_view(&message, sizeof(message)), object,
                          check_priority),
            std::nullopt);
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkInvalidDeliveryOrder) {
  SubscribeOkMessage subscribe_ok;
  subscribe_ok.SetInvalidDeliveryOrder();
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(subscribe_ok.PacketSample(), kDefaultMoqtVersion,
                       /*uses_web_transport=*/false);
  EXPECT_FALSE(parsed.ok());
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
  EXPECT_THAT(parsed.status().message(),
              HasSubstr("Invalid SUBSCRIBE_OK track extensions"));
}

TEST_F(MoqtMessageSpecificTest, SubscribeOkExpirationIsZero) {
  char subscribe_ok[] = {
      0x04, 0x00, 0x05, 0x02, 0x01,  // request_id = 2, track_alias = 1
      0x01, 0x08, 0x00               // expires = 0
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(absl::string_view(subscribe_ok, sizeof(subscribe_ok)),
                       kDefaultMoqtVersion, /*uses_web_transport=*/false);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1u);
  MoqtSubscribeOk message = std::get<MoqtSubscribeOk>((*parsed)[0]);
  EXPECT_EQ(message.parameters.expires, quic::QuicTimeDelta::Infinite());
}

TEST_F(MoqtMessageSpecificTest, FetchWholeGroup) {
  FetchMessage fetch;
  fetch.SetEndObject(5, std::nullopt);
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(fetch.PacketSample(), kDefaultMoqtVersion,
                       /*uses_web_transport=*/false);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1u);
  MoqtFetch parse_result = std::get<MoqtFetch>((*parsed)[0]);
  auto standalone = std::get<StandaloneFetch>(parse_result.fetch);
  EXPECT_EQ(standalone.end_location, Location(5, kMaxObjectId));
}

TEST_F(MoqtMessageSpecificTest, FetchInvalidRange) {
  FetchMessage fetch;
  fetch.SetEndObject(1, 1);
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(fetch.PacketSample(), kDefaultMoqtVersion,
                       /*uses_web_transport=*/false);
  EXPECT_FALSE(parsed.ok());
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
  EXPECT_THAT(parsed.status().message(),
              HasSubstr("End object comes before start object in FETCH"));
}

TEST_F(MoqtMessageSpecificTest, FetchInvalidRange2) {
  FetchMessage fetch;
  fetch.SetEndObject(0, std::nullopt);
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(fetch.PacketSample(), kDefaultMoqtVersion,
                       /*uses_web_transport=*/false);
  EXPECT_FALSE(parsed.ok());
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
  EXPECT_THAT(parsed.status().message(),
              HasSubstr("End object comes before start object in FETCH"));
}

TEST_F(MoqtMessageSpecificTest, PaddingStream) {
  MoqtParserTestVisitor visitor;
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtDataParser parser(&stream, &visitor);
  std::string buffer(32, '\0');
  quic::QuicDataWriter writer(buffer.size(), buffer.data());
  ASSERT_TRUE(writer.WriteMoqVarInt(MoqtDataStreamType::Padding().value()));
  for (int i = 0; i < 100; ++i) {
    stream.Receive(buffer, false);
    parser.ReadAllData();
    ASSERT_EQ(visitor.messages_received(), 0);
    ASSERT_EQ(visitor.parsing_error(), std::nullopt);
  }
}

// All messages with TrackNamespace use ReadTrackNamespace too check this. Use
// PUBLISH_NAMESPACE.
TEST_F(MoqtMessageSpecificTest, NamespaceTooSmall) {
  char publish_namespace[7] = {
      0x06, 0x00, 0x04, 0x02,  // request_id = 2
      0x01, 0x00,              // one empty namespace element
      0x00,                    // no parameters
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(publish_namespace, sizeof(publish_namespace)),
      kDefaultMoqtVersion, /*uses_web_transport=*/false);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1u);

  --publish_namespace[2];  // Remove one element.
  --publish_namespace[4];
  parsed = ParseAllMessages(
      absl::string_view(publish_namespace, sizeof(publish_namespace) - 1),
      kDefaultMoqtVersion, /*uses_web_transport=*/false);
  EXPECT_FALSE(parsed.ok());
  EXPECT_THAT(parsed.status().message(),
              HasSubstr("Invalid number of namespace elements"));
}

TEST_F(MoqtMessageSpecificTest, NamespaceTooLarge) {
  char publish_namespace[39] = {
      0x06, 0x00, 0x23, 0x02,  // type, length = 35, request_id = 2
      0x20,                    // 32 namespace elements. This is the maximum.
  };
  // 32 empty namespace elements + no parameters.
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(publish_namespace, sizeof(publish_namespace) - 1),
      kDefaultMoqtVersion, /*uses_web_transport=*/false);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1u);

  ++publish_namespace[2];  // Add one element.
  ++publish_namespace[4];
  parsed = ParseAllMessages(
      absl::string_view(publish_namespace, sizeof(publish_namespace)),
      kDefaultMoqtVersion, /*uses_web_transport=*/false);
  EXPECT_FALSE(parsed.ok());
  EXPECT_THAT(parsed.status().message(),
              HasSubstr("Invalid number of namespace elements"));
}

TEST_F(MoqtMessageSpecificTest, RelativeJoiningFetch) {
  RelativeJoiningFetchMessage message;
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(message.PacketSample(), kDefaultMoqtVersion,
                       /*uses_web_transport=*/false);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1u);
  EXPECT_TRUE(std::holds_alternative<MoqtFetch>((*parsed)[0]));
}

TEST_F(MoqtMessageSpecificTest, AbsoluteJoiningFetch) {
  AbsoluteJoiningFetchMessage message;
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed =
      ParseAllMessages(message.PacketSample(), kDefaultMoqtVersion,
                       /*uses_web_transport=*/false);
  ASSERT_TRUE(parsed.ok());
  ASSERT_EQ(parsed->size(), 1u);
  EXPECT_TRUE(std::holds_alternative<MoqtFetch>((*parsed)[0]));
}

TEST_F(MoqtMessageSpecificTest, InvalidSubscribeNamespaceOption) {
  char subscribe_namespace[] = {
      0x11, 0x00, 0x11, 0x01,                    // request_id = 1
      0x01, 0x03, 0x66, 0x6f, 0x6f,              // namespace = "foo"
      0x03,                                      // subscribe_options invalid
      0x02,                                      // 2 parameters
      0x03, 0x05, 0x03, 0x00, 0x62, 0x61, 0x72,  // authorization_tag = "bar"
      0x0d, 0x01,                                // forward = true
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(subscribe_namespace, sizeof(subscribe_namespace)),
      kDefaultMoqtVersion, /*uses_web_transport=*/false);
  EXPECT_FALSE(parsed.ok());
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
}

TEST_F(MoqtMessageSpecificTest, ParseKeyValuePairListIntegerOverflow) {
  char setup[] = {
      0xaf, 0x00, 0x00, 0x0c,  // kSetup, length = 12
      0x02,                    // num_params
      0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  // type_diff = max
      0x00,  // string length = 0
      0x01,  // type_diff = 1 (overflows)
  };
  absl::StatusOr<std::vector<AnyMoqtControlMessage>> parsed = ParseAllMessages(
      absl::string_view(setup, sizeof(setup)), kDefaultMoqtVersion, kRawQuic);
  EXPECT_FALSE(parsed.ok());
  EXPECT_EQ(ExtractMoqtErrorForStatus(parsed.status()),
            MoqtError::kProtocolViolation);
  EXPECT_THAT(parsed.status().message(),
              HasSubstr("Integer overflow encountered"));
}

class MoqtDataParserStateMachineTest : public quic::test::QuicTest {
 protected:
  MoqtDataParserStateMachineTest()
      : stream_(/*stream_id=*/0), parser_(&stream_, &visitor_) {}

  webtransport::test::InMemoryStream stream_;
  MoqtParserTestVisitor visitor_;
  MoqtDataParser parser_;
};

TEST_F(MoqtDataParserStateMachineTest, ReadAll) {
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(0, 1, false, false);
  stream_.Receive(StreamHeaderSubgroupMessage(type).PacketSample());
  stream_.Receive(StreamMiddlerSubgroupMessage(type).PacketSample());
  parser_.ReadAllData();
  ASSERT_EQ(visitor_.messages_received(), 2);
  EXPECT_EQ(visitor_.object_payloads()[0], "foo");
  EXPECT_EQ(visitor_.object_payloads()[1], "bar");
  stream_.Receive("", /*fin=*/true);
  parser_.ReadAllData();
  EXPECT_EQ(visitor_.parsing_error(), std::nullopt);
  EXPECT_TRUE(visitor_.fin_received());
}

TEST_F(MoqtDataParserStateMachineTest, ReadObjects) {
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(0, 1, true, false);
  stream_.Receive(StreamHeaderSubgroupMessage(type).PacketSample());
  stream_.Receive(StreamMiddlerSubgroupMessage(type).PacketSample(),
                  /*fin=*/true);
  parser_.ReadAtMostOneObject();
  ASSERT_EQ(visitor_.messages_received(), 1);
  EXPECT_EQ(visitor_.object_payloads()[0], "foo");
  parser_.ReadAtMostOneObject();
  ASSERT_EQ(visitor_.messages_received(), 2);
  EXPECT_EQ(visitor_.object_payloads()[1], "bar");
  EXPECT_EQ(visitor_.parsing_error(), std::nullopt);
  EXPECT_TRUE(visitor_.fin_received());
}

TEST_F(MoqtDataParserStateMachineTest, ReadTypeThenObjects) {
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(1, 1, false, false);
  stream_.Receive(StreamHeaderSubgroupMessage(type).PacketSample());
  stream_.Receive(StreamMiddlerSubgroupMessage(type).PacketSample(),
                  /*fin=*/true);
  parser_.ReadStreamType();
  ASSERT_EQ(visitor_.messages_received(), 0);
  EXPECT_TRUE(parser_.stream_type().has_value() &&
              parser_.stream_type()->IsSubgroup());
  parser_.ReadAtMostOneObject();
  ASSERT_EQ(visitor_.messages_received(), 1);
  EXPECT_EQ(visitor_.object_payloads()[0], "foo");
  parser_.ReadAtMostOneObject();
  ASSERT_EQ(visitor_.messages_received(), 2);
  EXPECT_EQ(visitor_.object_payloads()[1], "bar");
  EXPECT_EQ(visitor_.parsing_error(), std::nullopt);
  EXPECT_TRUE(visitor_.fin_received());
}

TEST_F(MoqtDataParserStateMachineTest, ReadTypeThenObjectsFetch) {
  for (MoqtFetchSerialization serialization : AllMoqtFetchSerializations()) {
    SCOPED_TRACE(testing::Message() << "flags: " << serialization.value());
    MoqtParserTestVisitor visitor;
    webtransport::test::InMemoryStream stream(/*stream_id=*/0);
    MoqtDataParser parser(&stream, &visitor);
    StreamHeaderFetchMessage header;
    StreamMiddlerFetchMessage middler(serialization);
    stream.Receive(header.PacketSample());
    stream.Receive(middler.PacketSample(), /*fin=*/true);
    parser.ReadStreamType();
    ASSERT_EQ(visitor.messages_received(), 0);
    parser.ReadAtMostOneObject();
    ASSERT_EQ(visitor.messages_received(), 1);
    EXPECT_TRUE(header.EqualFieldValues(visitor.last_message().value()));
    EXPECT_EQ(visitor.object_payloads()[0], "foo");
    parser.ReadAtMostOneObject();
    ASSERT_EQ(visitor.messages_received(), 2);
    EXPECT_TRUE(middler.EqualFieldValues(visitor.last_message().value()));
    EXPECT_EQ(visitor.object_payloads()[1], "bar");
    EXPECT_EQ(visitor.parsing_error(), std::nullopt);
    EXPECT_TRUE(visitor.fin_received());
  }
}

TEST_F(MoqtDataParserStateMachineTest, StreamHeaderFetchRefersToPrior) {
  char data[] = {0x05, 0x01, 0x00};
  // Iterate through the 5 serializations that refer to the prior object.
  for (char value : {0x0f, 0x17, 0x1b, 0x1d, 0x1e}) {
    data[2] = value;
    MoqtParserTestVisitor visitor;
    webtransport::test::InMemoryStream stream(/*stream_id=*/0);
    MoqtDataParser parser(&stream, &visitor);
    stream.Receive(absl::string_view(data, sizeof(data)));
    parser.ReadStreamType();
    parser.ReadAtMostOneObject();
    EXPECT_EQ(visitor.parsing_error(),
              "Invalid serialization flags for first object");
  }
}

TEST_F(MoqtDataParserStateMachineTest, DatagramThenPriorSubgroupId) {
  char data[] = {0x05, 0x01, 0x5c, 0x05, 0x01,  // datagram (5, 1)
                 0x80, 0x03, 0x61, 0x61, 0x61,  // priority, payload
                 0xff};  // serialization flag to be overwritten
  // Iterate through the 2 serializations that refer to the prior subgroup.
  for (char value : {0x01, 0x02}) {
    data[10] = value;
    MoqtParserTestVisitor visitor;
    webtransport::test::InMemoryStream stream(/*stream_id=*/0);
    MoqtDataParser parser(&stream, &visitor);
    stream.Receive(absl::string_view(data, sizeof(data)));
    parser.ReadStreamType();
    parser.ReadAtMostOneObject();
    parser.ReadAtMostOneObject();
    EXPECT_EQ(visitor.parsing_error(),
              "reference to subgroup ID of prior datagram");
  }
}

TEST_F(MoqtDataParserStateMachineTest, InvalidNonexistentRange) {
  char data[] = {0x05, 0x01, 0x80, 0x80};
  stream_.Receive(absl::string_view(data, sizeof(data)));
  parser_.ReadStreamType();
  parser_.ReadAtMostOneObject();
  EXPECT_EQ(visitor_.parsing_error(), "Invalid serialization flags");
}

TEST_F(MoqtDataParserStateMachineTest, InvalidNonexistentRangeUnknownRange) {
  char data[] = {0x05, 0x01, 0x81, 0x8c};
  stream_.Receive(absl::string_view(data, sizeof(data)));
  parser_.ReadStreamType();
  parser_.ReadAtMostOneObject();
  EXPECT_EQ(visitor_.parsing_error(), "Invalid serialization flags");
}

TEST_F(MoqtDataParserStateMachineTest, IgnoresEndRangeIndicators) {
  // Header, Range Indicator, Middler
  stream_.Receive(StreamHeaderFetchMessage().PacketSample());
  char data[] = {0x80, 0x8c, 0x05, 0x07,   // non-existent range
                 0x81, 0x0c, 0x05, 0x09};  // unknown range
  stream_.Receive(absl::string_view(data, sizeof(data)));
  std::optional<MoqtFetchSerialization> serialization =
      MoqtFetchSerialization::FromValue(0x40);  // Datagram + explicit object ID
  ASSERT_TRUE(serialization.has_value());
  StreamMiddlerFetchMessage middler(*serialization);
  stream_.Receive(middler.PacketSample(), /*fin=*/true);
  parser_.ReadAllData();
  EXPECT_EQ(visitor_.messages_received(), 2);
  // TODO(martinduke): Once Issue #1506 is resolved, check that the values
  // are reported correctly.
}

TEST_F(MoqtDataParserStateMachineTest, IntegerOverflowObjectId) {
  MoqtDataStreamType type = MoqtDataStreamType::Subgroup(
      0, 1, /*no_extension_headers=*/true, /*default_priority=*/false);
  stream_.Receive(StreamHeaderSubgroupMessage(type).PacketSample());
  char buffer[32];
  quic::QuicDataWriter writer(sizeof(buffer), buffer);
  ASSERT_TRUE(writer.WriteMoqVarInt(std::numeric_limits<uint64_t>::max() - 5));
  ASSERT_TRUE(
      writer.WriteBytes("\x03"
                        "bar",
                        4));
  stream_.Receive(absl::string_view(buffer, writer.length()));
  parser_.ReadAllData();
  EXPECT_EQ(visitor_.parsing_error(),
            "Integer overflow when parsing object ID");
}

}  // namespace moqt::test
