#include "http2/adapter/header_validator.h"

#include "absl/strings/str_cat.h"
#include "absl/types/optional.h"
#include "common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {

using ::testing::Optional;

TEST(HeaderValidatorTest, HeaderNameEmpty) {
  HeaderValidator v;
  HeaderValidator::HeaderStatus status = v.ValidateSingleHeader("", "value");
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
}

TEST(HeaderValidatorTest, HeaderValueEmpty) {
  HeaderValidator v;
  HeaderValidator::HeaderStatus status = v.ValidateSingleHeader("name", "");
  EXPECT_EQ(HeaderValidator::HEADER_OK, status);
}

TEST(HeaderValidatorTest, ExceedsMaxSize) {
  HeaderValidator v;
  v.SetMaxFieldSize(64u);
  HeaderValidator::HeaderStatus status =
      v.ValidateSingleHeader("name", "value");
  EXPECT_EQ(HeaderValidator::HEADER_OK, status);
  status = v.ValidateSingleHeader(
      "name2",
      "Antidisestablishmentariansism is supercalifragilisticexpialodocious.");
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_TOO_LONG, status);
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
      EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
    }
    // Uppercase characters in header names should not be allowed.
    const std::string uc_name = is_pseudo_header ? ":Method" : "Name";
    HeaderValidator::HeaderStatus status =
        v.ValidateSingleHeader(uc_name, "value");
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
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
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID, status);
  }
}

TEST(HeaderValidatorTest, StatusHasInvalidChar) {
  HeaderValidator v;

  for (HeaderType type : {HeaderType::RESPONSE, HeaderType::RESPONSE_100}) {
    // When `:status` has a non-digit value, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(":status", "bar"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is too short, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
              v.ValidateSingleHeader(":status", "10"));
    EXPECT_FALSE(v.FinishHeaderBlock(type));

    // When `:status` is too long, validation will fail.
    v.StartHeaderBlock();
    EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
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
  // At this point, `:protocol` is treated as an extra pseudo-header.
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  // Future header blocks may send the `:protocol` pseudo-header for CONNECT
  // requests.
  v.AllowConnect();

  v.StartHeaderBlock();
  for (absl::string_view to_add : headers) {
    EXPECT_EQ(HeaderValidator::HEADER_OK,
              v.ValidateSingleHeader(to_add, "foo"));
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // The method is "foo", not "CONNECT", so `:protocol` is still treated as an
  // extra pseudo-header.
  EXPECT_FALSE(v.FinishHeaderBlock(HeaderType::REQUEST));

  v.StartHeaderBlock();
  for (absl::string_view to_add : headers) {
    if (to_add == ":method") {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add, "CONNECT"));
    } else {
      EXPECT_EQ(HeaderValidator::HEADER_OK,
                v.ValidateSingleHeader(to_add, "foo"));
    }
  }
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":protocol", "websocket"));
  // After allowing the method, `:protocol` is acepted for CONNECT requests.
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::REQUEST));
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

TEST(HeaderValidatorTest, Response204) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, Response204WithContentLengthZero) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "0"));
  EXPECT_TRUE(v.FinishHeaderBlock(HeaderType::RESPONSE));
}

TEST(HeaderValidatorTest, Response204WithContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader(":status", "204"));
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("x-content", "is not present"));
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "1"));
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

TEST(HeaderValidatorTest, ValidContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), absl::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "41"));
  EXPECT_THAT(v.content_length(), Optional(41));

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), absl::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "42"));
  EXPECT_THAT(v.content_length(), Optional(42));
}

TEST(HeaderValidatorTest, InvalidContentLength) {
  HeaderValidator v;

  v.StartHeaderBlock();
  EXPECT_EQ(v.content_length(), absl::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", ""));
  EXPECT_EQ(v.content_length(), absl::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "nan"));
  EXPECT_EQ(v.content_length(), absl::nullopt);
  EXPECT_EQ(HeaderValidator::HEADER_FIELD_INVALID,
            v.ValidateSingleHeader("content-length", "-42"));
  EXPECT_EQ(v.content_length(), absl::nullopt);
  // End on a positive note.
  EXPECT_EQ(HeaderValidator::HEADER_OK,
            v.ValidateSingleHeader("content-length", "42"));
  EXPECT_THAT(v.content_length(), Optional(42));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
