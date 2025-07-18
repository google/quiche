// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/web_transport_headers.h"

#include <initializer_list>
#include <string>
#include <vector>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace webtransport {
namespace {

using ::quiche::test::IsOkAndHolds;
using ::quiche::test::StatusIs;
using ::testing::ElementsAre;
using ::testing::HasSubstr;

TEST(WebTransportHeaders, ParseSubprotocolRequestHeader) {
  EXPECT_THAT(ParseSubprotocolRequestHeader("\"test\""),
              IsOkAndHolds(ElementsAre("test")));
  EXPECT_THAT(
      ParseSubprotocolRequestHeader(R"("moqt-draft01", "moqt-draft02")"),
      IsOkAndHolds(ElementsAre("moqt-draft01", "moqt-draft02")));
  EXPECT_THAT(
      ParseSubprotocolRequestHeader(R"("moqt-draft01"; a=b, "moqt-draft02")"),
      IsOkAndHolds(ElementsAre("moqt-draft01", "moqt-draft02")));
  EXPECT_THAT(
      ParseSubprotocolRequestHeader(R"("moqt-draft01", "moqt-draft02"; a=b)"),
      IsOkAndHolds(ElementsAre("moqt-draft01", "moqt-draft02")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("test"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found token instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("42"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found integer instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("\"a\", (b)"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found a nested list instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("\"a\", (b c)"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found a nested list instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("\"foo\", ?1, bar"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found boolean instead")));
  EXPECT_THAT(ParseSubprotocolRequestHeader("(a"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("parse the header as an sf-list")));
}

TEST(WebTransportHeaders, SerializeSubprotocolRequestHeader) {
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"test"}),
              IsOkAndHolds(R"("test")"));
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"foo", "bar"}),
              IsOkAndHolds(R"("foo", "bar")"));
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"a\"b", "a/b/c"}),
              IsOkAndHolds(R"("a\"b", "a/b/c")"));
  EXPECT_THAT(SerializeSubprotocolRequestHeader({"abcd", "\n", "efgh"}),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(WebTransportHeader, ParseSubprotocolResponseHeader) {
  EXPECT_THAT(ParseSubprotocolResponseHeader("\"foo\""), IsOkAndHolds("foo"));
  EXPECT_THAT(ParseSubprotocolResponseHeader("\"foo\"; a=b"),
              IsOkAndHolds("foo"));
  EXPECT_THAT(
      ParseSubprotocolResponseHeader("1234"),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("found integer")));
  EXPECT_THAT(
      ParseSubprotocolResponseHeader("(a"),
      StatusIs(absl::StatusCode::kInvalidArgument, HasSubstr("parse sf-item")));
}

TEST(WebTransportHeader, SerializeSubprotocolResponseHeader) {
  EXPECT_THAT(SerializeSubprotocolResponseHeader("foo"),
              IsOkAndHolds("\"foo\""));
  EXPECT_THAT(SerializeSubprotocolResponseHeader("moqt-draft01"),
              IsOkAndHolds("\"moqt-draft01\""));
  EXPECT_THAT(SerializeSubprotocolResponseHeader("\xff"),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(WebTransportHeader, ParseInitHeader) {
  WebTransportInitHeader expected_header;
  expected_header.initial_unidi_limit = 100;
  expected_header.initial_incoming_bidi_limit = 200;
  expected_header.initial_outgoing_bidi_limit = 400;
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=100"),
              IsOkAndHolds(expected_header));
  EXPECT_THAT(ParseInitHeader("br=300, bl=200, u=100, br=400"),
              IsOkAndHolds(expected_header));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200; foo=bar, u=100"),
              IsOkAndHolds(expected_header));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=100.0"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found decimal instead")));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=?1"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found boolean instead")));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=(a b)"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found a nested list instead")));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=:abcd:"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("found byte sequence instead")));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=-1"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("negative value")));
  EXPECT_THAT(ParseInitHeader("br=400, bl=200, u=18446744073709551615"),
              StatusIs(absl::StatusCode::kInvalidArgument,
                       HasSubstr("Failed to parse")));
}

TEST(WebTransportHeaders, SerializeInitHeader) {
  EXPECT_THAT(SerializeInitHeader(WebTransportInitHeader{}),
              IsOkAndHolds("u=0, bl=0, br=0"));

  WebTransportInitHeader test_header;
  test_header.initial_unidi_limit = 100;
  test_header.initial_incoming_bidi_limit = 200;
  test_header.initial_outgoing_bidi_limit = 400;
  EXPECT_THAT(SerializeInitHeader(test_header),
              IsOkAndHolds("u=100, bl=200, br=400"));
}

// Helper to sidestep the fact that calling ValidateSubprotocolList directly
// with an initializer list is ambiguous.
bool ValidateSubprotocolListHelper(
    std::initializer_list<absl::string_view> list) {
  return ValidateSubprotocolList(list);
}

TEST(WebTransportHeaders, ValidateSubprotocolName) {
  EXPECT_TRUE(ValidateSubprotocolName("test"));
  EXPECT_TRUE(ValidateSubprotocolName("123"));
  EXPECT_FALSE(ValidateSubprotocolName("\n"));
  EXPECT_FALSE(ValidateSubprotocolName(""));

  EXPECT_TRUE(ValidateSubprotocolListHelper({}));
  EXPECT_TRUE(ValidateSubprotocolListHelper({"a", "b", "c"}));
  EXPECT_FALSE(ValidateSubprotocolListHelper({"a", "\n", "c"}));
  EXPECT_FALSE(ValidateSubprotocolListHelper({"a", "b", "a"}));

  std::vector<std::string> vec = {"a", "b"};
  EXPECT_TRUE(ValidateSubprotocolList(vec));
  vec.push_back("b");
  EXPECT_FALSE(ValidateSubprotocolList(vec));
}

}  // namespace
}  // namespace webtransport
