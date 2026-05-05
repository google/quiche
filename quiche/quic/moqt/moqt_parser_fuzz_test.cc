// Copyright (c) 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <array>
#include <string>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/test_tools/moqt_parser_test_visitor.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"

namespace moqt::test {
namespace {

void MoqtControlParserNeverCrashes(bool is_data_stream, bool uses_web_transport,
                                   absl::string_view stream_data, bool fin) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor visitor(/*enable_logging=*/false);

  MoqtControlStreamParser control_stream_parser(&stream);
  MoqtControlMessageParser control_message_parser(kDefaultMoqtVersion,
                                                  uses_web_transport);
  MoqtDataParser data_parser(&stream, &visitor);

  if (is_data_stream) {
    stream.Receive(stream_data, /*fin=*/fin);
    data_parser.ReadAllData();
  } else {
    stream.Receive(stream_data, /*fin=*/false);
    while (true) {
      absl::StatusOr<MoqtRawControlMessage> message =
          control_stream_parser.ReadNextMessage();
      if (!message.ok()) {
        break;
      }
      (void)control_message_parser.ParseMessage(
          *message, [](auto) { return absl::OkStatus(); });
    }
  }
}

FUZZ_TEST(MoqtParserTest, MoqtControlParserNeverCrashes)
    .WithDomains(fuzztest::Arbitrary<bool>(), fuzztest::Arbitrary<bool>(),
                 fuzztest::Arbitrary<std::string>(),
                 fuzztest::Arbitrary<bool>());

// Regression test for b/446307507.
TEST(MoqtParserTest,
     MoqtControlParserNeverCrashesRegressionQuicTimeFromMillisecondsOverflow) {
  static constexpr auto kStreamData = std::to_array<char>({
      0x02, 0x00, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x25, 0x01, 0x02,
      0xcd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x6e, 0xc7,
      0x02, 0x61, 0x8a, 0x00, 0x00, 0x09, 0x09, 0x09, 0x80,
  });

  MoqtControlParserNeverCrashes(
      /*is_data_stream=*/false,
      /*uses_web_transport=*/false,
      /*stream_data=*/std::string(kStreamData.begin(), kStreamData.end()),
      /*fin=*/true);
}

}  // namespace
}  // namespace moqt::test
