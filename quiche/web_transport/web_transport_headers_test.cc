// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/web_transport_headers.h"

#include "absl/status/status.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace webtransport {
namespace {

using ::quiche::test::IsOkAndHolds;
using ::quiche::test::StatusIs;
using ::testing::ElementsAre;
using ::testing::HasSubstr;

TEST(WebTransportHeaders, ParseSubprotocolRequestHeader) {
  EXPECT_THAT(ParseSubprotocolRequestHeader("test"),
              IsOkAndHolds(ElementsAre("test")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("moqt-draft01, moqt-draft02"),
              IsOkAndHolds(ElementsAre("moqt-draft01", "moqt-draft02")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("moqt-draft01; a=b, moqt-draft02"),
              IsOkAndHolds(ElementsAre("moqt-draft01", "moqt-draft02")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("moqt-draft01, moqt-draft02; a=b"),
              IsOkAndHolds(ElementsAre("moqt-draft01", "moqt-draft02")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("\"test\""),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found string instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("42"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found integer instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("a, (b)"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found a nested list instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("a, (b c)"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found a nested list instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("foo, ?1, bar"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found boolean instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("(a"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("parse the header as an sf-list")));
}

TEST(WebTransportHeaders, SerializeSubprotocolRequestHeader) {
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"test"}),
              IsOkAndHolds("test"));
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"foo", "bar"}),
              IsOkAndHolds("foo, bar"));
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"moqt-draft01", "a/b/c"}),
              IsOkAndHolds("moqt-draft01, a/b/c"));
  EXPECT_THAT(
      SerializeSubprotocolRequestHeader({"abcd", "0123", "efgh"}),
      StatusIs(absl::StatusCode::kInvalidArgument, "Invalid token: 0123"));
}

}  // namespace
}  // namespace webtransport
