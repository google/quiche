#include "http2/adapter/header_validator.h"

#include "absl/strings/str_cat.h"
#include "common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {

TEST(HeaderValidatorTest, HeaderNameEmpty) {
  HeaderValidator v;
  HeaderValidator::HeaderStatus status = v.ValidateSingleHeader("", "value");
  EXPECT_EQ(HeaderValidator::HEADER_NAME_EMPTY, status);
}

TEST(HeaderValidatorTest, HeaderValueEmpty) {
  HeaderValidator v;
  HeaderValidator::HeaderStatus status = v.ValidateSingleHeader("name", "");
  EXPECT_EQ(HeaderValidator::HEADER_OK, status);
}

TEST(HeaderValidatorTest, NameHasInvalidChar) {
  HeaderValidator v;
  for (const bool is_pseudo_header : {true, false}) {
    // These characters should be allowed. (Not exhaustive.)
    for (const char* c : {"!", "3", "a", "_", "|", "~"}) {
      const std::string name = is_pseudo_header ? absl::StrCat(":met", c, "hod")
                                                : absl::StrCat("na", c, "me");
      HeaderValidator::HeaderStatus status =
          v.ValidateSingleHeader(name, "value");
      EXPECT_EQ(HeaderValidator::HEADER_OK, status);
    }
    // These should not. (Not exhaustive.)
    for (const char* c : {"\\", "<", ";", "[", "=", " ", "\r", "\n", ",", "\"",
                          "\x1F", "\x91"}) {
      const std::string name = is_pseudo_header ? absl::StrCat(":met", c, "hod")
                                                : absl::StrCat("na", c, "me");
      HeaderValidator::HeaderStatus status =
          v.ValidateSingleHeader(name, "value");
      EXPECT_EQ(HeaderValidator::HEADER_NAME_INVALID_CHAR, status);
    }
    // Uppercase characters in header names should not be allowed.
    const std::string uc_name = is_pseudo_header ? ":Method" : "Name";
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader(uc_name, "value");
    EXPECT_EQ(HeaderValidator::HEADER_NAME_INVALID_CHAR, status);
  }
}

TEST(HeaderValidatorTest, ValueHasInvalidChar) {
  HeaderValidator v;
  // These characters should be allowed. (Not exhaustive.)
  for (const char* c :
       {"!", "3", "a", "_", "|", "~", "\\", "<", ";", "[", "=", "A", "\t"}) {
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader("name", absl::StrCat("val", c, "ue"));
    EXPECT_EQ(HeaderValidator::HEADER_OK, status);
  }
  // These should not.
  for (const char* c : {"\r", "\n"}) {
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader("name", absl::StrCat("val", c, "ue"));
    EXPECT_EQ(HeaderValidator::HEADER_VALUE_INVALID_CHAR, status);
  }
}

TEST(HeaderValidatorTest, StatusHasInvalidChar) {
  HeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    // When `:status` has a non-digit value, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_VALUE_INVALID_CHAR,
              v.ValidateSingleHeader(":status", "bar"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is too short, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_VALUE_INVALID_CHAR,
              v.ValidateSingleHeader(":status", "10"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is too long, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_VALUE_INVALID_CHAR,
              v.ValidateSingleHeader(":status", "9000"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is just right, validation will succeed.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "400"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
  }
}

TEST(HeaderValidatorTest, RequestPseudoHeaders) {
  HeaderValidator v;
  const absl::string_view headers[] = {":authority", ":method", ":path",
                                       ":scheme"};
  for (absl::string_view to_skip : headers) {
    v.StartHeaderBlock();
    for (absl::string_view to_add : headers) {
      if (to_add != to_skip) {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  v.ValidateSingleHeader(to_add, "foo"));
      }
    }
    // When any pseudo-header is missing, final validation will fail.
    EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }

  // When all pseudo-headers are present, final validation will succeed.
  v.StartHeaderBlock();
  for (absl::string_view to_add : headers) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add, "foo"));
  }
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // When an extra pseudo-header is present, final validation will fail.
  v.StartHeaderBlock();
  for (absl::string_view to_add : headers) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add, "foo"));
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":extra", "blah"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // When a required pseudo-header is repeated, final validation will fail.
  for (absl::string_view to_repeat : headers) {
    v.StartHeaderBlock();
    for (absl::string_view to_add : headers) {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add, "foo"));
      if (to_add == to_repeat) {
        EXPECT_EQ(HeaderValidator::HEADER_OK,
                  v.ValidateSingleHeader(to_add, "foo"));
      }
    }
    EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));
  }
}

TEST(HeaderValidatorTest, WebsocketPseudoHeaders) {
  HeaderValidator v;
  const absl::string_view headers[] = {":authority", ":method", ":path",
                                       ":scheme"};
  v.StartHeaderBlock();
  for (absl::string_view to_add : headers) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add, "foo"));
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // For now, `:protocol` is treated as an extra pseudo-header.
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));
}

TEST(HeaderValidatorTest, ResponsePseudoHeaders) {
  HeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    // When `:status` is missing, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader("foo", "bar"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When all pseudo-headers are present, final validation will succeed.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_TRUE(v.FinishHeaderBlock(type));
    EXPECT_EQ("199", v.status_header());

    // When `:status` is repeated, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "299"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When an extra pseudo-header is present, final validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":status", "199"));
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(":extra", "blorp"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));
  }
}

TEST(HeaderValidatorTest, ResponseTrailerPseudoHeaders) {
  HeaderValidator v;

  // When no pseudo-headers are present, validation will succeed.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader("foo", "bar"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE_TRAILER));

  // When any pseudo-header is present, final validation will fail.
  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "200"));
  EXPECT_EQ(HeaderValidator::HEADER_OK, v.ValidateSingleHeader("foo", "bar"));
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::RESPONSE_TRAILER));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
