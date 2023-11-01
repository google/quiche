// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_framer.h"

#include <memory>
#include <string>
#include <vector>

#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/test_tools/moqt_test_message.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace moqt::test {

struct MoqtFramerTestParams {
  MoqtFramerTestParams(MoqtMessageType message_type, bool uses_web_transport)
      : message_type(message_type), uses_web_transport(uses_web_transport) {}
  MoqtMessageType message_type;
  bool uses_web_transport;
};

std::vector<MoqtFramerTestParams> GetMoqtFramerTestParams() {
  std::vector<MoqtFramerTestParams> params;
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
  std::vector<bool> uses_web_transport_bool = {
      false,
      true,
  };
  for (const MoqtMessageType message_type : message_types) {
    if (message_type == MoqtMessageType::kClientSetup) {
      for (const bool uses_web_transport : uses_web_transport_bool) {
        params.push_back(
            MoqtFramerTestParams(message_type, uses_web_transport));
      }
    } else {
      // All other types are processed the same for either perspective or
      // transport.
      params.push_back(MoqtFramerTestParams(message_type, true));
    }
  }
  return params;
}

std::string ParamNameFormatter(
    const testing::TestParamInfo<MoqtFramerTestParams>& info) {
  return MoqtMessageTypeToString(info.param.message_type) + "_" +
         (info.param.uses_web_transport ? "WebTransport" : "QUIC");
}

class MoqtFramerTest
    : public quic::test::QuicTestWithParam<MoqtFramerTestParams> {
 public:
  MoqtFramerTest()
      : message_type_(GetParam().message_type),
        webtrans_(GetParam().uses_web_transport),
        buffer_allocator_(quiche::SimpleBufferAllocator::Get()),
        framer_(buffer_allocator_, GetParam().uses_web_transport) {}

  std::unique_ptr<TestMessageBase> MakeMessage(MoqtMessageType message_type) {
    switch (message_type) {
      case MoqtMessageType::kObjectWithPayloadLength:
        return std::make_unique<ObjectMessageWithLength>();
      case MoqtMessageType::kObjectWithoutPayloadLength:
        return std::make_unique<ObjectMessageWithoutLength>();
      case MoqtMessageType::kClientSetup:
        return std::make_unique<ClientSetupMessage>(webtrans_);
      case MoqtMessageType::kServerSetup:
        return std::make_unique<ServerSetupMessage>();
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

  quiche::QuicheBuffer SerializeMessage(
      TestMessageBase::MessageStructuredData& structured_data) {
    switch (message_type_) {
      case MoqtMessageType::kObjectWithPayloadLength:
      case MoqtMessageType::kObjectWithoutPayloadLength: {
        auto data = std::get<MoqtObject>(structured_data);
        return framer_.SerializeObject(data, "foo");
      }
      case MoqtMessageType::kClientSetup: {
        auto data = std::get<MoqtClientSetup>(structured_data);
        return framer_.SerializeClientSetup(data);
      }
      case MoqtMessageType::kServerSetup: {
        auto data = std::get<MoqtServerSetup>(structured_data);
        return framer_.SerializeServerSetup(data);
      }
      case MoqtMessageType::kSubscribeRequest: {
        auto data = std::get<MoqtSubscribeRequest>(structured_data);
        return framer_.SerializeSubscribeRequest(data);
      }
      case MoqtMessageType::kSubscribeOk: {
        auto data = std::get<MoqtSubscribeOk>(structured_data);
        return framer_.SerializeSubscribeOk(data);
      }
      case MoqtMessageType::kSubscribeError: {
        auto data = std::get<MoqtSubscribeError>(structured_data);
        return framer_.SerializeSubscribeError(data);
      }
      case MoqtMessageType::kUnsubscribe: {
        auto data = std::get<MoqtUnsubscribe>(structured_data);
        return framer_.SerializeUnsubscribe(data);
      }
      case MoqtMessageType::kSubscribeFin: {
        auto data = std::get<MoqtSubscribeFin>(structured_data);
        return framer_.SerializeSubscribeFin(data);
      }
      case MoqtMessageType::kSubscribeRst: {
        auto data = std::get<MoqtSubscribeRst>(structured_data);
        return framer_.SerializeSubscribeRst(data);
      }
      case MoqtMessageType::kAnnounce: {
        auto data = std::get<MoqtAnnounce>(structured_data);
        return framer_.SerializeAnnounce(data);
      }
      case moqt::MoqtMessageType::kAnnounceOk: {
        auto data = std::get<MoqtAnnounceOk>(structured_data);
        return framer_.SerializeAnnounceOk(data);
      }
      case moqt::MoqtMessageType::kAnnounceError: {
        auto data = std::get<MoqtAnnounceError>(structured_data);
        return framer_.SerializeAnnounceError(data);
      }
      case MoqtMessageType::kUnannounce: {
        auto data = std::get<MoqtUnannounce>(structured_data);
        return framer_.SerializeUnannounce(data);
      }
      case moqt::MoqtMessageType::kGoAway: {
        auto data = std::get<MoqtGoAway>(structured_data);
        return framer_.SerializeGoAway(data);
      }
    }
  }

  MoqtMessageType message_type_;
  bool webtrans_;
  quiche::SimpleBufferAllocator* buffer_allocator_;
  MoqtFramer framer_;
};

INSTANTIATE_TEST_SUITE_P(MoqtFramerTests, MoqtFramerTest,
                         testing::ValuesIn(GetMoqtFramerTestParams()),
                         ParamNameFormatter);

TEST_P(MoqtFramerTest, OneMessage) {
  auto message = MakeMessage(message_type_);
  auto structured_data = message->structured_data();
  auto buffer = SerializeMessage(structured_data);
  EXPECT_EQ(buffer.size(), message->total_message_size());
  EXPECT_EQ(buffer.AsStringView(), message->PacketSample());
}

}  // namespace moqt::test
