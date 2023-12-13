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
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt::test {

namespace {

bool IsObjectMessage(MoqtMessageType type) {
  return (type == MoqtMessageType::kObjectWithPayloadLength ||
          type == MoqtMessageType::kObjectWithoutPayloadLength);
}

std::vector<MoqtMessageType> message_types = {
    MoqtMessageType::kObjectWithPayloadLength,
    MoqtMessageType::kObjectWithoutPayloadLength,
    MoqtMessageType::kClientSetup,
    MoqtMessageType::kServerSetup,
    MoqtMessageType::kSubscribeRequest,
    MoqtMessageType::kSubscribeOk,
    MoqtMessageType::kSubscribeError,
    MoqtMessageType::kUnsubscribe,
    MoqtMessageType::kSubscribeFin,
    MoqtMessageType::kSubscribeRst,
    MoqtMessageType::kAnnounce,
    MoqtMessageType::kAnnounceOk,
    MoqtMessageType::kAnnounceError,
    MoqtMessageType::kUnannounce,
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
  void OnClientSetupMessage(const MoqtClientSetup& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtClientSetup client_setup = message;
    if (client_setup.path.has_value()) {
      string0_ = std::string(*client_setup.path);
      client_setup.path = absl::string_view(string0_);
    }
    last_message_ = TestMessageBase::MessageStructuredData(client_setup);
  }
  void OnServerSetupMessage(const MoqtServerSetup& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtServerSetup server_setup = message;
    last_message_ = TestMessageBase::MessageStructuredData(server_setup);
  }
  void OnSubscribeRequestMessage(const MoqtSubscribeRequest& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeRequest subscribe_request = message;
    string0_ = std::string(subscribe_request.track_namespace);
    subscribe_request.track_namespace = absl::string_view(string0_);
    string1_ = std::string(subscribe_request.track_name);
    subscribe_request.track_name = absl::string_view(string1_);
    if (subscribe_request.authorization_info.has_value()) {
      string2_ = std::string(*subscribe_request.authorization_info);
      subscribe_request.authorization_info = absl::string_view(string2_);
    }
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_request);
  }
  void OnSubscribeOkMessage(const MoqtSubscribeOk& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeOk subscribe_ok = message;
    string0_ = std::string(subscribe_ok.track_namespace);
    subscribe_ok.track_namespace = absl::string_view(string0_);
    string1_ = std::string(subscribe_ok.track_name);
    subscribe_ok.track_name = absl::string_view(string1_);
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_ok);
  }
  void OnSubscribeErrorMessage(const MoqtSubscribeError& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeError subscribe_error = message;
    string0_ = std::string(subscribe_error.track_namespace);
    subscribe_error.track_namespace = absl::string_view(string0_);
    string1_ = std::string(subscribe_error.track_name);
    subscribe_error.track_name = absl::string_view(string1_);
    string1_ = std::string(subscribe_error.reason_phrase);
    subscribe_error.reason_phrase = absl::string_view(string1_);
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_error);
  }
  void OnUnsubscribeMessage(const MoqtUnsubscribe& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtUnsubscribe unsubscribe = message;
    string0_ = std::string(unsubscribe.track_namespace);
    unsubscribe.track_namespace = absl::string_view(string0_);
    string1_ = std::string(unsubscribe.track_name);
    unsubscribe.track_name = absl::string_view(string1_);
    last_message_ = TestMessageBase::MessageStructuredData(unsubscribe);
  }
  void OnSubscribeFinMessage(const MoqtSubscribeFin& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeFin subscribe_fin = message;
    string0_ = std::string(subscribe_fin.track_namespace);
    subscribe_fin.track_namespace = absl::string_view(string0_);
    string1_ = std::string(subscribe_fin.track_name);
    subscribe_fin.track_name = absl::string_view(string1_);
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_fin);
  }
  void OnSubscribeRstMessage(const MoqtSubscribeRst& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeRst subscribe_rst = message;
    string0_ = std::string(subscribe_rst.track_namespace);
    subscribe_rst.track_namespace = absl::string_view(string0_);
    string1_ = std::string(subscribe_rst.track_name);
    subscribe_rst.track_name = absl::string_view(string1_);
    string2_ = std::string(subscribe_rst.reason_phrase);
    subscribe_rst.reason_phrase = absl::string_view(string2_);
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_rst);
  }
  void OnAnnounceMessage(const MoqtAnnounce& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtAnnounce announce = message;
    string0_ = std::string(announce.track_namespace);
    announce.track_namespace = absl::string_view(string0_);
    if (announce.authorization_info.has_value()) {
      string1_ = std::string(*announce.authorization_info);
      announce.authorization_info = absl::string_view(string1_);
    }
    last_message_ = TestMessageBase::MessageStructuredData(announce);
  }
  void OnAnnounceOkMessage(const MoqtAnnounceOk& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtAnnounceOk announce_ok = message;
    string0_ = std::string(announce_ok.track_namespace);
    announce_ok.track_namespace = absl::string_view(string0_);
    last_message_ = TestMessageBase::MessageStructuredData(announce_ok);
  }
  void OnAnnounceErrorMessage(const MoqtAnnounceError& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtAnnounceError announce_error = message;
    string0_ = std::string(announce_error.track_namespace);
    announce_error.track_namespace = absl::string_view(string0_);
    string1_ = std::string(announce_error.reason_phrase);
    announce_error.reason_phrase = absl::string_view(string1_);
    last_message_ = TestMessageBase::MessageStructuredData(announce_error);
  }
  void OnUnannounceMessage(const MoqtUnannounce& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtUnannounce unannounce = message;
    string0_ = std::string(unannounce.track_namespace);
    unannounce.track_namespace = absl::string_view(string0_);
    last_message_ = TestMessageBase::MessageStructuredData(unannounce);
  }
  void OnGoAwayMessage(const MoqtGoAway& message) override {
    got_goaway_ = true;
    end_of_message_ = true;
    messages_received_++;
    MoqtGoAway goaway = message;
    string0_ = std::string(goaway.new_session_uri);
    goaway.new_session_uri = absl::string_view(string0_);
    last_message_ = TestMessageBase::MessageStructuredData(goaway);
  }
  void OnParsingError(absl::string_view reason) override {
    QUIC_LOG(INFO) << "Parsing error: " << reason;
    parsing_error_ = reason;
  }

  std::optional<absl::string_view> object_payload_;
  bool end_of_message_ = false;
  bool got_goaway_ = false;
  std::optional<absl::string_view> parsing_error_;
  uint64_t messages_received_ = 0;
  std::optional<TestMessageBase::MessageStructuredData> last_message_;
  // Stored strings for last_message_. The visitor API does not promise the
  // memory pointed to by string_views is persistent.
  std::string string0_, string1_, string2_;
};

class MoqtParserTest
    : public quic::test::QuicTestWithParam<MoqtParserTestParams> {
 public:
  MoqtParserTest()
      : message_type_(GetParam().message_type),
        webtrans_(GetParam().uses_web_transport),
        parser_(GetParam().uses_web_transport, visitor_) {}

  std::unique_ptr<TestMessageBase> MakeMessage(MoqtMessageType message_type) {
    switch (message_type) {
      case MoqtMessageType::kObjectWithPayloadLength:
        return std::make_unique<ObjectMessageWithLength>();
      case MoqtMessageType::kObjectWithoutPayloadLength:
        return std::make_unique<ObjectMessageWithoutLength>();
      case MoqtMessageType::kClientSetup:
        return std::make_unique<ClientSetupMessage>(webtrans_);
      case MoqtMessageType::kServerSetup:
        return std::make_unique<ClientSetupMessage>(webtrans_);
      case MoqtMessageType::kSubscribeRequest:
        return std::make_unique<SubscribeRequestMessage>();
      case MoqtMessageType::kSubscribeOk:
        return std::make_unique<SubscribeOkMessage>();
      case MoqtMessageType::kSubscribeError:
        return std::make_unique<SubscribeErrorMessage>();
      case MoqtMessageType::kUnsubscribe:
        return std::make_unique<UnsubscribeMessage>();
      case MoqtMessageType::kSubscribeFin:
        return std::make_unique<SubscribeFinMessage>();
      case MoqtMessageType::kSubscribeRst:
        return std::make_unique<SubscribeRstMessage>();
      case MoqtMessageType::kAnnounce:
        return std::make_unique<AnnounceMessage>();
      case moqt::MoqtMessageType::kAnnounceOk:
        return std::make_unique<AnnounceOkMessage>();
      case moqt::MoqtMessageType::kAnnounceError:
        return std::make_unique<AnnounceErrorMessage>();
      case moqt::MoqtMessageType::kUnannounce:
        return std::make_unique<UnannounceMessage>();
      case moqt::MoqtMessageType::kGoAway:
        return std::make_unique<GoAwayMessage>();
      default:
        return nullptr;
    }
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
  if (message_type_ == MoqtMessageType::kObjectWithoutPayloadLength) {
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
  if (message_type_ == MoqtMessageType::kObjectWithoutPayloadLength) {
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
  parser_.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() / 2),
      true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "FIN after incomplete message");
}

TEST_P(MoqtParserTest, SeparateEarlyFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  parser_.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() / 2),
      false);
  parser_.ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "End of stream before complete message");
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

TEST_F(MoqtMessageSpecificTest, ObjectNoLengthSeparateFin) {
  // OBJECT can return on an unknown-length message even without receiving a
  // FIN.
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<ObjectMessageWithoutLength>();
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
  auto message = std::make_unique<ObjectMessageWithoutLength>();
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
  auto message = std::make_unique<ObjectMessageWithoutLength>();

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
  EXPECT_EQ(visitor_.object_payload_->length(), 95);

  // third part includes FIN
  parser.ProcessData("bar", true);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(*visitor_.last_message_));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_F(MoqtMessageSpecificTest, SetupRoleAppearsTwice) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions
      0x03,                          // 3 params
      0x00, 0x01, 0x03,              // role = both
      0x00, 0x01, 0x03,              // role = both
      0x01, 0x03, 0x66, 0x6f, 0x6f   // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "ROLE parameter appears twice in SETUP");
}

TEST_F(MoqtMessageSpecificTest, SetupRoleIsMissing) {
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
}

TEST_F(MoqtMessageSpecificTest, SetupPathAppearsTwice) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x03,                          // 3 params
      0x00, 0x01, 0x03,              // role = both
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH parameter appears twice in CLIENT_SETUP");
}

TEST_F(MoqtMessageSpecificTest, SetupPathOverWebtrans) {
  MoqtParser parser(kWebTrans, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x02,                          // 2 params
      0x00, 0x01, 0x03,              // role = both
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "WebTransport connection is using PATH parameter in SETUP");
}

TEST_F(MoqtMessageSpecificTest, SetupPathMissing) {
  MoqtParser parser(kRawQuic, visitor_);
  char setup[] = {
      0x40, 0x40, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x01,                          // 1 param
      0x00, 0x01, 0x03,              // role = both
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH SETUP parameter missing from Client message over QUIC");
}

TEST_F(MoqtMessageSpecificTest, SubscribeRequestAuthorizationInfoTwice) {
  MoqtParser parser(kWebTrans, visitor_);
  char subscribe_request[] = {
      0x03, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02, 0x04,                    // start_group = 4 (relative previous)
      0x01, 0x01,                    // start_object = 1 (absolute)
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x02,                          // two params
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice in SUBSCRIBE_REQUEST");
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
}

TEST_F(MoqtMessageSpecificTest, FinMidPayload) {
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<ObjectMessageWithLength>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Received FIN mid-payload");
}

TEST_F(MoqtMessageSpecificTest, PartialPayloadThenFin) {
  MoqtParser parser(kRawQuic, visitor_);
  auto message = std::make_unique<ObjectMessageWithLength>();
  parser.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      false);
  parser.ProcessData(absl::string_view(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "End of stream before complete OBJECT PAYLOAD");
}

TEST_F(MoqtMessageSpecificTest, DataAfterFin) {
  MoqtParser parser(kRawQuic, visitor_);
  parser.ProcessData(absl::string_view(), true);  // Find FIN
  parser.ProcessData("foo", false);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "Data after end of stream");
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
  char subscribe_request[] = {
      0x03, 0x03, 0x66, 0x6f, 0x6f,  // track_name = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x00,                          // start_group = none
      0x01, 0x01,                    // start_object = 1 (absolute)
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "START_GROUP must not be None in SUBSCRIBE_REQUEST");
}

TEST_F(MoqtMessageSpecificTest, StartObjectIsNone) {
  MoqtParser parser(kRawQuic, visitor_);
  char subscribe_request[] = {
      0x03, 0x03, 0x66, 0x6f, 0x6f,  // track_name = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02, 0x04,                    // start_group = 4 (relative previous)
      0x00,                          // start_object = none
      0x00,                          // end_group = none
      0x00,                          // end_object = none
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "START_OBJECT must not be None in SUBSCRIBE_REQUEST");
}

TEST_F(MoqtMessageSpecificTest, EndGroupIsNoneEndObjectIsNoNone) {
  MoqtParser parser(kRawQuic, visitor_);
  char subscribe_request[] = {
      0x03, 0x03, 0x66, 0x6f, 0x6f,  // track_name = "foo"
      0x04, 0x61, 0x62, 0x63, 0x64,  // track_name = "abcd"
      0x02, 0x04,                    // start_group = 4 (relative previous)
      0x01, 0x01,                    // start_object = 1 (absolute)
      0x00,                          // end_group = none
      0x01, 0x01,                    // end_object = 1 (absolute)
      0x01,                          // 1 parameter
      0x02, 0x03, 0x62, 0x61, 0x72,  // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "SUBSCRIBE_REQUEST end_group and end_object must be both None "
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
    if (type == MoqtMessageType::kObjectWithoutPayloadLength) {
      continue;  // Cannot be followed with another message.
    }
    std::unique_ptr<TestMessageBase> message;
    switch (type) {
      case MoqtMessageType::kObjectWithPayloadLength:
        message = std::make_unique<ObjectMessageWithLength>();
        break;
      case MoqtMessageType::kObjectWithoutPayloadLength:
        continue;  // Cannot be followed with another message;
      case MoqtMessageType::kClientSetup:
        message = std::make_unique<ClientSetupMessage>(kRawQuic);
        break;
      case MoqtMessageType::kServerSetup:
        message = std::make_unique<ClientSetupMessage>(kRawQuic);
        break;
      case MoqtMessageType::kSubscribeRequest:
        message = std::make_unique<SubscribeRequestMessage>();
        break;
      case MoqtMessageType::kSubscribeOk:
        message = std::make_unique<SubscribeOkMessage>();
        break;
      case MoqtMessageType::kSubscribeError:
        message = std::make_unique<SubscribeErrorMessage>();
        break;
      case MoqtMessageType::kUnsubscribe:
        message = std::make_unique<UnsubscribeMessage>();
        break;
      case MoqtMessageType::kSubscribeFin:
        message = std::make_unique<SubscribeFinMessage>();
        break;
      case MoqtMessageType::kSubscribeRst:
        message = std::make_unique<SubscribeRstMessage>();
        break;
      case MoqtMessageType::kAnnounce:
        message = std::make_unique<AnnounceMessage>();
        break;
      case moqt::MoqtMessageType::kAnnounceOk:
        message = std::make_unique<AnnounceOkMessage>();
        break;
      case moqt::MoqtMessageType::kAnnounceError:
        message = std::make_unique<AnnounceErrorMessage>();
        break;
      case moqt::MoqtMessageType::kUnannounce:
        message = std::make_unique<UnannounceMessage>();
        break;
      case moqt::MoqtMessageType::kGoAway:
        message = std::make_unique<GoAwayMessage>();
        break;
      default:
        message = nullptr;
        break;
    }
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

}  // namespace moqt::test
