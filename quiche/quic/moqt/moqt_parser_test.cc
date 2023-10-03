// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_parser.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace moqt::test {

struct MoqtParserTestParams {
  MoqtParserTestParams(MoqtMessageType message_type,
                       quic::Perspective perspective, bool uses_web_transport)
      : message_type(message_type),
        perspective(perspective),
        uses_web_transport(uses_web_transport) {}
  MoqtMessageType message_type;
  quic::Perspective perspective;
  bool uses_web_transport;
};

std::vector<MoqtParserTestParams> GetMoqtParserTestParams() {
  std::vector<MoqtParserTestParams> params;
  std::vector<MoqtMessageType> message_types = {
      MoqtMessageType::kObject,           MoqtMessageType::kSetup,
      MoqtMessageType::kSubscribeRequest, MoqtMessageType::kSubscribeOk,
      MoqtMessageType::kSubscribeError,   MoqtMessageType::kAnnounce,
      MoqtMessageType::kAnnounceOk,       MoqtMessageType::kAnnounceError,
      MoqtMessageType::kGoAway,
  };
  std::vector<quic::Perspective> perspectives = {
      quic::Perspective::IS_SERVER,
      quic::Perspective::IS_CLIENT,
  };
  std::vector<bool> uses_web_transport_bool = {
      false,
      true,
  };
  for (const MoqtMessageType message_type : message_types) {
    if (message_type == MoqtMessageType::kSetup) {
      for (const quic::Perspective perspective : perspectives) {
        for (const bool uses_web_transport : uses_web_transport_bool) {
          params.push_back(MoqtParserTestParams(message_type, perspective,
                                                uses_web_transport));
        }
      }
    } else {
      // All other types are processed the same for either perspective or
      // transport.
      params.push_back(MoqtParserTestParams(
          message_type, quic::Perspective::IS_SERVER, true));
    }
  }
  return params;
}

std::string ParamNameFormatter(
    const testing::TestParamInfo<MoqtParserTestParams>& info) {
  return MoqtMessageTypeToString(info.param.message_type) + "_" +
         (info.param.perspective == quic::Perspective::IS_SERVER ? "Server"
                                                                 : "Client") +
         "_" + (info.param.uses_web_transport ? "WebTransport" : "QUIC");
}

class MoqtParserTestVisitor : public MoqtParserVisitor {
 public:
  ~MoqtParserTestVisitor() = default;

  void OnObjectMessage(const MoqtObject& message, absl::string_view payload,
                       bool end_of_message) override {
    object_payload_ = payload;
    end_of_message_ = end_of_message;
    messages_received_++;
    last_message_ = TestMessageBase::MessageStructuredData(message);
  }
  void OnSetupMessage(const MoqtSetup& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSetup setup = message;
    if (setup.path.has_value()) {
      string0_ = std::string(setup.path.value());
      setup.path = absl::string_view(string0_);
    }
    last_message_ = TestMessageBase::MessageStructuredData(setup);
  }
  void OnSubscribeRequestMessage(const MoqtSubscribeRequest& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeRequest subscribe_request = message;
    string0_ = std::string(subscribe_request.full_track_name);
    subscribe_request.full_track_name = absl::string_view(string0_);
    if (subscribe_request.authorization_info.has_value()) {
      string1_ = std::string(subscribe_request.authorization_info.value());
      subscribe_request.authorization_info = absl::string_view(string1_);
    }
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_request);
  }
  void OnSubscribeOkMessage(const MoqtSubscribeOk& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeOk subscribe_ok = message;
    string0_ = std::string(subscribe_ok.full_track_name);
    subscribe_ok.full_track_name = absl::string_view(string0_);
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_ok);
  }
  void OnSubscribeErrorMessage(const MoqtSubscribeError& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtSubscribeError subscribe_error = message;
    string0_ = std::string(subscribe_error.full_track_name);
    subscribe_error.full_track_name = absl::string_view(string0_);
    string1_ = std::string(subscribe_error.reason_phrase);
    subscribe_error.reason_phrase = absl::string_view(string1_);
    last_message_ = TestMessageBase::MessageStructuredData(subscribe_error);
  }
  void OnUnsubscribeMessage(const MoqtUnsubscribe& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtUnsubscribe unsubscribe = message;
    string0_ = std::string(unsubscribe.full_track_name);
    unsubscribe.full_track_name = absl::string_view(string0_);
    last_message_ = TestMessageBase::MessageStructuredData(unsubscribe);
  }
  void OnAnnounceMessage(const MoqtAnnounce& message) override {
    end_of_message_ = true;
    messages_received_++;
    MoqtAnnounce announce = message;
    string0_ = std::string(announce.track_namespace);
    announce.track_namespace = absl::string_view(string0_);
    if (announce.authorization_info.has_value()) {
      string1_ = std::string(announce.authorization_info.value());
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
  void OnGoAwayMessage() override {
    got_goaway_ = true;
    end_of_message_ = true;
    messages_received_++;
    last_message_ = TestMessageBase::MessageStructuredData();
  }
  void OnParsingError(absl::string_view reason) override {
    QUIC_LOG(INFO) << "Parsing error: " << reason;
    parsing_error_ = reason;
  }

  absl::optional<absl::string_view> object_payload_;
  bool end_of_message_ = false;
  bool got_goaway_ = false;
  absl::optional<absl::string_view> parsing_error_;
  uint64_t messages_received_ = 0;
  absl::optional<TestMessageBase::MessageStructuredData> last_message_;
  // Stored strings for last_message_. The visitor API does not promise the
  // memory pointed to by string_views is persistent.
  std::string string0_, string1_;
};

class MoqtParserTest
    : public quic::test::QuicTestWithParam<MoqtParserTestParams> {
 public:
  MoqtParserTest()
      : message_type_(GetParam().message_type),
        is_client_(GetParam().perspective == quic::Perspective::IS_CLIENT),
        webtrans_(GetParam().uses_web_transport),
        parser_(GetParam().perspective, GetParam().uses_web_transport,
                visitor_) {}

  std::unique_ptr<TestMessageBase> MakeMessage(MoqtMessageType message_type) {
    switch (message_type) {
      case MoqtMessageType::kObject:
        return std::make_unique<ObjectMessage>();
      case MoqtMessageType::kSetup:
        return std::make_unique<SetupMessage>(is_client_, webtrans_);
      case MoqtMessageType::kSubscribeRequest:
        return std::make_unique<SubscribeRequestMessage>();
      case MoqtMessageType::kSubscribeOk:
        return std::make_unique<SubscribeOkMessage>();
      case MoqtMessageType::kSubscribeError:
        return std::make_unique<SubscribeErrorMessage>();
      case MoqtMessageType::kAnnounce:
        return std::make_unique<AnnounceMessage>();
      case moqt::MoqtMessageType::kAnnounceOk:
        return std::make_unique<AnnounceOkMessage>();
      case moqt::MoqtMessageType::kAnnounceError:
        return std::make_unique<AnnounceErrorMessage>();
      case moqt::MoqtMessageType::kGoAway:
        return std::make_unique<GoAwayMessage>();
      default:
        return nullptr;
    }
  }

  MoqtParserTestVisitor visitor_;
  MoqtMessageType message_type_;
  bool is_client_;
  bool webtrans_;
  MoqtParser parser_;
};

INSTANTIATE_TEST_SUITE_P(MoqtParserTests, MoqtParserTest,
                         testing::ValuesIn(GetMoqtParserTestParams()),
                         ParamNameFormatter);

TEST_P(MoqtParserTest, OneMessage) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (message_type_ == MoqtMessageType::kObject) {
    // Check payload message.
    EXPECT_TRUE(visitor_.object_payload_.has_value());
    EXPECT_EQ(*(visitor_.object_payload_), "foo");
  }
}

TEST_P(MoqtParserTest, OneMessageWithLongVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->ExpandVarints();
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (message_type_ == MoqtMessageType::kObject) {
    // Check payload message.
    EXPECT_EQ(visitor_.object_payload_, "foo");
  }
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, MessageNoLengthWithFin) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->set_message_size(0);
  parser_.ProcessData(message->PacketSample(), true);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (message_type_ == MoqtMessageType::kObject) {
    // Check payload message.
    EXPECT_TRUE(visitor_.object_payload_.has_value());
    EXPECT_EQ(*(visitor_.object_payload_), "foo");
  }
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, MessageNoLengthSeparateFinObjectOrGoAway) {
  // OBJECT and GOAWAY can return on a zero-length message even without
  // receiving a FIN.
  if (message_type_ != MoqtMessageType::kObject &&
      message_type_ != MoqtMessageType::kGoAway) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->set_message_size(0);
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  if (message_type_ == MoqtMessageType::kGoAway) {
    EXPECT_TRUE(visitor_.got_goaway_);
    EXPECT_TRUE(visitor_.end_of_message_);
    return;
  }
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "foo");
  EXPECT_FALSE(visitor_.end_of_message_);

  parser_.ProcessData(absl::string_view(), true);  // send the FIN
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "");
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, MessageNoLengthSeparateFinOtherTypes) {
  if (message_type_ == MoqtMessageType::kObject ||
      message_type_ == MoqtMessageType::kGoAway) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->set_message_size(0);
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  parser_.ProcessData(absl::string_view(), true);  // send the FIN
  EXPECT_EQ(visitor_.messages_received_, 1);

  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
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
      false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  if (message_type_ == MoqtMessageType::kObject) {
    EXPECT_EQ(visitor_.object_payload_, "foo");
  }
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

// Send the header + some payload, pure payload, then pure payload to end the
// message.
TEST_P(MoqtParserTest, ThreePartObject) {
  if (message_type_ != MoqtMessageType::kObject) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->set_message_size(0);
  // The test Object message has payload for less then half the message length,
  // so splitting the message in half will prevent the first half from being
  // processed.
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "foo");

  // second part
  parser_.ProcessData("bar", false);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");

  // third part includes FIN
  parser_.ProcessData("deadbeef", true);
  EXPECT_EQ(visitor_.messages_received_, 3);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "deadbeef");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

// Send the part of header, rest of header + payload, plus payload.
TEST_P(MoqtParserTest, ThreePartObjectFirstIncomplete) {
  if (message_type_ != MoqtMessageType::kObject) {
    return;
  }
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->set_message_size(0);

  // first part
  parser_.ProcessData(message->PacketSample().substr(0, 4), false);
  EXPECT_EQ(visitor_.messages_received_, 0);

  // second part. Add padding to it.
  message->set_wire_image_size(100);
  parser_.ProcessData(
      message->PacketSample().substr(4, message->total_message_size() - 4),
      false);
  EXPECT_EQ(visitor_.messages_received_, 1);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_FALSE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(visitor_.object_payload_->length(), 94);

  // third part includes FIN
  parser_.ProcessData("bar", true);
  EXPECT_EQ(visitor_.messages_received_, 2);
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_TRUE(visitor_.object_payload_.has_value());
  EXPECT_EQ(*(visitor_.object_payload_), "bar");
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, OneByteAtATime) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->set_message_size(0);
  constexpr size_t kObjectPrePayloadSize = 6;
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    parser_.ProcessData(message->PacketSample().substr(i, 1), false);
    if (message_type_ == MoqtMessageType::kGoAway &&
        i == message->total_message_size() - 1) {
      // OnGoAway() is called before FIN.
      EXPECT_EQ(visitor_.messages_received_, 1);
      EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
      EXPECT_TRUE(visitor_.end_of_message_);
      break;
    }
    if (message_type_ != MoqtMessageType::kObject ||
        i < kObjectPrePayloadSize) {
      // OBJECTs will have to buffer for the first 5 bytes (until the varints
      // are done). The sixth byte is a bare OBJECT header, so the parser does
      // not notify the visitor.
      EXPECT_EQ(visitor_.messages_received_, 0);
    } else {
      // OBJECT payload processing.
      EXPECT_EQ(visitor_.messages_received_, i - kObjectPrePayloadSize + 1);
      EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
      EXPECT_TRUE(visitor_.object_payload_.has_value());
      if (i == 5) {
        EXPECT_EQ(visitor_.object_payload_->length(), 0);
      } else {
        EXPECT_EQ(visitor_.object_payload_->length(), 1);
        EXPECT_EQ((*visitor_.object_payload_)[0],
                  message->PacketSample().substr(i, 1)[0]);
      }
    }
    EXPECT_FALSE(visitor_.end_of_message_);
  }
  // Send FIN
  parser_.ProcessData(absl::string_view(), true);
  if (message_type_ == MoqtMessageType::kObject) {
    EXPECT_EQ(visitor_.messages_received_,
              message->total_message_size() - kObjectPrePayloadSize + 1);
  } else {
    EXPECT_EQ(visitor_.messages_received_, 1);
  }
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, OneByteAtATimeLongerVarints) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  message->ExpandVarints();
  message->set_message_size(0);
  constexpr size_t kObjectPrePayloadSize = 28;
  for (size_t i = 0; i < message->total_message_size(); ++i) {
    parser_.ProcessData(message->PacketSample().substr(i, 1), false);
    if (message_type_ == MoqtMessageType::kGoAway &&
        i == message->total_message_size() - 1) {
      // OnGoAway() is called before FIN.
      EXPECT_EQ(visitor_.messages_received_, 1);
      EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
      EXPECT_TRUE(visitor_.end_of_message_);
      break;
    }
    if (message_type_ != MoqtMessageType::kObject ||
        i < kObjectPrePayloadSize) {
      // OBJECTs will have to buffer for the first 5 bytes (until the varints
      // are done). The sixth byte is a bare OBJECT header, so the parser does
      // not notify the visitor.
      EXPECT_EQ(visitor_.messages_received_, 0);
    } else {
      // OBJECT payload processing.
      EXPECT_EQ(visitor_.messages_received_, i - kObjectPrePayloadSize + 1);
      EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
      EXPECT_TRUE(visitor_.object_payload_.has_value());
      if (i == 5) {
        EXPECT_EQ(visitor_.object_payload_->length(), 0);
      } else {
        EXPECT_EQ(visitor_.object_payload_->length(), 1);
        EXPECT_EQ((*visitor_.object_payload_)[0],
                  message->PacketSample().substr(i, 1)[0]);
      }
    }
    EXPECT_FALSE(visitor_.end_of_message_);
  }
  // Send FIN
  parser_.ProcessData(absl::string_view(), true);
  if (message_type_ == MoqtMessageType::kObject) {
    EXPECT_EQ(visitor_.messages_received_,
              message->total_message_size() - kObjectPrePayloadSize + 1);
  } else {
    EXPECT_EQ(visitor_.messages_received_, 1);
  }
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, OneByteAtATimeKnownLength) {
  std::unique_ptr<TestMessageBase> message = MakeMessage(message_type_);
  constexpr size_t kObjectPrePayloadSize = 6;
  // Send all but the last byte
  for (size_t i = 0; i < message->total_message_size() - 1; ++i) {
    parser_.ProcessData(message->PacketSample().substr(i, 1), false);
    if (message_type_ != MoqtMessageType::kObject ||
        i < kObjectPrePayloadSize) {
      // OBJECTs will have to buffer for the first 5 bytes (until the varints
      // are done). The sixth byte is a bare OBJECT header, so the parser does
      // not notify the visitor.
      EXPECT_EQ(visitor_.messages_received_, 0);
    } else {
      // OBJECT payload processing.
      EXPECT_EQ(visitor_.messages_received_, i - kObjectPrePayloadSize + 1);
      EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
      EXPECT_TRUE(visitor_.object_payload_.has_value());
      if (i == 5) {
        EXPECT_EQ(visitor_.object_payload_->length(), 0);
      } else {
        EXPECT_EQ(visitor_.object_payload_->length(), 1);
        EXPECT_EQ((*visitor_.object_payload_)[0],
                  message->PacketSample().substr(i, 1)[0]);
      }
    }
    EXPECT_FALSE(visitor_.end_of_message_);
  }
  // Send last byte
  parser_.ProcessData(
      message->PacketSample().substr(message->total_message_size() - 1, 1),
      false);
  if (message_type_ == MoqtMessageType::kObject) {
    EXPECT_EQ(visitor_.messages_received_,
              message->total_message_size() - kObjectPrePayloadSize);
    EXPECT_EQ(visitor_.object_payload_->length(), 1);
    EXPECT_EQ((*visitor_.object_payload_)[0],
              message->PacketSample().substr(message->total_message_size() - 1,
                                             1)[0]);
  } else {
    EXPECT_EQ(visitor_.messages_received_, 1);
  }
  EXPECT_TRUE(message->EqualFieldValues(visitor_.last_message_.value()));
  EXPECT_TRUE(visitor_.end_of_message_);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
}

TEST_P(MoqtParserTest, LengthTooShort) {
  if (message_type_ == MoqtMessageType::kGoAway ||
      message_type_ == MoqtMessageType::kAnnounceOk) {
    // GOAWAY already has length zero. ANNOUNCE_OK works for any message length.
    return;
  }
  auto message = MakeMessage(message_type_);
  if (message_type_ == MoqtMessageType::kSetup &&
      GetParam().perspective == quic::Perspective::IS_CLIENT) {
    // Unless varints are longer than necessary, the message is only one byte
    // long.
    message->ExpandVarints();
  }
  size_t truncate = (message_type_ == MoqtMessageType::kObject) ? 4 : 1;
  message->set_message_size(message->message_size() - truncate);
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Not able to parse message given specified length");
}

// Buffered packets are a different code path, so test them separately.
TEST_P(MoqtParserTest, LengthTooShortInBufferedPacket) {
  if (message_type_ == MoqtMessageType::kGoAway ||
      message_type_ == MoqtMessageType::kAnnounceOk) {
    // GOAWAY already has length zero. ANNOUNCE_OK works for any message length.
    return;
  }
  auto message = MakeMessage(message_type_);
  if (message_type_ == MoqtMessageType::kSetup &&
      GetParam().perspective == quic::Perspective::IS_CLIENT) {
    // Unless varints are longer than necessary, the message is only one byte
    // long.
    message->ExpandVarints();
  }
  EXPECT_EQ(visitor_.messages_received_, 0);
  size_t truncate = (message_type_ == MoqtMessageType::kObject) ? 5 : 2;
  message->set_message_size(message->message_size() - truncate + 1);
  parser_.ProcessData(
      message->PacketSample().substr(0, message->total_message_size() - 1),
      false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_FALSE(visitor_.parsing_error_.has_value());
  // send the last byte
  parser_.ProcessData(
      message->PacketSample().substr(message->total_message_size() - 1, 1),
      false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Not able to parse buffered message given specified length");
}

TEST_P(MoqtParserTest, LengthTooLong) {
  if (message_type_ == MoqtMessageType::kAnnounceOk ||
      message_type_ == MoqtMessageType::kObject ||
      message_type_ == MoqtMessageType::kSetup ||
      message_type_ == MoqtMessageType::kSubscribeRequest ||
      message_type_ == MoqtMessageType::kAnnounce) {
    // OBJECT and ANNOUNCE_OK work for any message length.
    // SETUP, SUBSCRIBE_REQUEST, and ANNOUNCE have parameters, so an additional
    // byte will cause the message to be interpreted as being too short.
    return;
  }
  auto message = MakeMessage(message_type_);
  message->set_message_size(message->message_size() + 1);
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(visitor_.messages_received_, 0);
  if (message_type_ == MoqtMessageType::kGoAway) {
    EXPECT_EQ(*visitor_.parsing_error_, "GOAWAY has data following");
  } else {
    EXPECT_EQ(*visitor_.parsing_error_, "Specified message length too long");
  }
}

TEST_P(MoqtParserTest, LengthExceedsBufferSize) {
  if (message_type_ == MoqtMessageType::kObject) {
    // OBJECT works for any length.
    return;
  }
  auto message = MakeMessage(message_type_);
  message->set_message_size(kMaxMessageHeaderSize + 1);
  parser_.ProcessData(message->PacketSample(), false);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(visitor_.messages_received_, 0);
  if (message_type_ == MoqtMessageType::kGoAway) {
    EXPECT_EQ(*visitor_.parsing_error_, "GOAWAY has data following");
  } else {
    EXPECT_EQ(*visitor_.parsing_error_, "Message too long");
  }
}

// Tests for message-specific error cases.
class MoqtParserErrorTest : public quic::test::QuicTest {
 public:
  MoqtParserErrorTest() {}

  MoqtParserTestVisitor visitor_;

  static constexpr bool kWebTrans = true;
  static constexpr bool kRawQuic = false;
};

TEST_F(MoqtParserErrorTest, SetupRoleAppearsTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kRawQuic, visitor_);
  char setup[] = {
      0x01, 0x0e, 0x02, 0x01, 0x02,  // versions
      0x00, 0x01, 0x03,              // role = both
      0x00, 0x01, 0x03,              // role = both
      0x01, 0x03, 0x66, 0x6f, 0x6f   // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "ROLE parameter appears twice in SETUP");
}

TEST_F(MoqtParserErrorTest, SetupRoleIsMissing) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kRawQuic, visitor_);
  char setup[] = {
      0x01, 0x08, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "ROLE SETUP parameter missing from Client message");
}

TEST_F(MoqtParserErrorTest, SetupPathFromServer) {
  MoqtParser parser(quic::Perspective::IS_CLIENT, kRawQuic, visitor_);
  char setup[] = {
      0x01, 0x06,
      0x01,                          // version = 1
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "PATH parameter sent by server in SETUP");
}

TEST_F(MoqtParserErrorTest, SetupPathAppearsTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kRawQuic, visitor_);
  char setup[] = {
      0x01, 0x10, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x00, 0x01, 0x03,              // role = both
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_, "PATH parameter appears twice in SETUP");
}

TEST_F(MoqtParserErrorTest, SetupPathOverWebtrans) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char setup[] = {
      0x01, 0x0b, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x00, 0x01, 0x03,              // role = both
      0x01, 0x03, 0x66, 0x6f, 0x6f,  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "WebTransport connection is using PATH parameter in SETUP");
}

TEST_F(MoqtParserErrorTest, SetupPathMissing) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kRawQuic, visitor_);
  char setup[] = {
      0x01, 0x06, 0x02, 0x01, 0x02,  // versions = 1, 2
      0x00, 0x01, 0x03,              // role = both
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "PATH SETUP parameter missing from Client message over QUIC");
}

TEST_F(MoqtParserErrorTest, SetupRoleTooLong) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kRawQuic, visitor_);
  char setup[] = {
      0x01, 0x0e, 0x02, 0x01, 0x02,  // versions
      // role = both
      0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01,
      0x03, 0x66, 0x6f, 0x6f  // path = "foo"
  };
  parser.ProcessData(absl::string_view(setup, sizeof(setup)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "Cannot parse explicit length integers longer than 8 bytes");
}

TEST_F(MoqtParserErrorTest, SubscribeRequestGroupSequenceTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char subscribe_request[] = {
      0x03, 0x12, 0x03, 0x66, 0x6f, 0x6f,  // track_name = "foo"
      0x00, 0x01, 0x01,                    // group_sequence = 1
      0x00, 0x01, 0x01,                    // group_sequence = 1
      0x01, 0x01, 0x02,                    // object_sequence = 2
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "GROUP_SEQUENCE parameter appears twice in SUBSCRIBE_REQUEST");
}

TEST_F(MoqtParserErrorTest, SubscribeRequestObjectSequenceTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char subscribe_request[] = {
      0x03, 0x12, 0x03, 0x66, 0x6f, 0x6f,  // track_name = "foo"
      0x00, 0x01, 0x01,                    // group_sequence = 1
      0x01, 0x01, 0x02,                    // object_sequence = 2
      0x01, 0x01, 0x02,                    // object_sequence = 2
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "OBJECT_SEQUENCE parameter appears twice in SUBSCRIBE_REQUEST");
}

TEST_F(MoqtParserErrorTest, SubscribeRequestAuthorizationInfoTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char subscribe_request[] = {
      0x03, 0x14, 0x03, 0x66, 0x6f, 0x6f,  // track_name = "foo"
      0x00, 0x01, 0x01,                    // group_sequence = 1
      0x01, 0x01, 0x02,                    // object_sequence = 2
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(
      absl::string_view(subscribe_request, sizeof(subscribe_request)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice in SUBSCRIBE_REQUEST");
}

TEST_F(MoqtParserErrorTest, AnnounceGroupSequenceTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x0f, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
      0x00, 0x01, 0x01,                    // group_sequence = 1
      0x00, 0x01, 0x01,                    // group_sequence = 1
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "GROUP_SEQUENCE parameter appears twice in ANNOUNCE");
}

TEST_F(MoqtParserErrorTest, AnnounceObjectSequenceTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x0e, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x01, 0x01, 0x02,                    // object_sequence = 2
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
      0x01, 0x01, 0x02,                    // object_sequence = 2
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "OBJECT_SEQUENCE parameter appears twice in ANNOUNCE");
}

TEST_F(MoqtParserErrorTest, AnnounceAuthorizationInfoTwice) {
  MoqtParser parser(quic::Perspective::IS_SERVER, kWebTrans, visitor_);
  char announce[] = {
      0x06, 0x0e, 0x03, 0x66, 0x6f, 0x6f,  // track_namespace = "foo"
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
      0x02, 0x03, 0x62, 0x61, 0x72,        // authorization_info = "bar"
  };
  parser.ProcessData(absl::string_view(announce, sizeof(announce)), false);
  EXPECT_EQ(visitor_.messages_received_, 0);
  EXPECT_TRUE(visitor_.parsing_error_.has_value());
  EXPECT_EQ(*visitor_.parsing_error_,
            "AUTHORIZATION_INFO parameter appears twice in ANNOUNCE");
}

}  // namespace moqt::test
