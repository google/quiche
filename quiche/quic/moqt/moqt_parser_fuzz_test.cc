// Copyright (c) 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/test_tools/moqt_parser_test_visitor.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"
#include "quiche/web_transport/test_tools/in_memory_stream.h"

namespace moqt::test {
namespace {

void MoqtControlParserNeverCrashes(bool is_data_stream, bool uses_web_transport,
                                   absl::string_view stream_data, bool fin) {
  webtransport::test::InMemoryStream stream(/*stream_id=*/0);
  MoqtParserTestVisitor visitor(/*enable_logging=*/false);

  MoqtControlParser control_parser(uses_web_transport, &stream, visitor);
  MoqtDataParser data_parser(&stream, &visitor);

  if (is_data_stream) {
    stream.Receive(stream_data, /*fin=*/fin);
    data_parser.ReadAllData();
  } else {
    stream.Receive(stream_data, /*fin=*/false);
    control_parser.ReadAndDispatchMessages();
  }
}

FUZZ_TEST(MoqtParserTest, MoqtControlParserNeverCrashes)
    .WithDomains(fuzztest::Arbitrary<bool>(), fuzztest::Arbitrary<bool>(),
                 fuzztest::Arbitrary<std::string>(),
                 fuzztest::Arbitrary<bool>());

}  // namespace
}  // namespace moqt::test
