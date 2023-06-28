#include "quiche/balsa/header_properties.h"

#include "quiche/common/platform/api/quiche_test.h"

namespace quiche::header_properties::test {
namespace {

TEST(HeaderPropertiesTest, IsMultivaluedHeaderIsCaseInsensitive) {
  EXPECT_TRUE(IsMultivaluedHeader("content-encoding"));
  EXPECT_TRUE(IsMultivaluedHeader("Content-Encoding"));
  EXPECT_TRUE(IsMultivaluedHeader("set-cookie"));
  EXPECT_TRUE(IsMultivaluedHeader("sEt-cOOkie"));
  EXPECT_TRUE(IsMultivaluedHeader("X-Goo" /**/ "gle-Cache-Control"));
  EXPECT_TRUE(IsMultivaluedHeader("access-control-expose-HEADERS"));

  EXPECT_FALSE(IsMultivaluedHeader("set-cook"));
  EXPECT_FALSE(IsMultivaluedHeader("content-length"));
  EXPECT_FALSE(IsMultivaluedHeader("Content-Length"));
}

TEST(HeaderPropertiesTest, IsInvalidHeaderKeyChar) {
  EXPECT_TRUE(IsInvalidHeaderKeyChar(0x00));
  EXPECT_TRUE(IsInvalidHeaderKeyChar(0x06));
  EXPECT_TRUE(IsInvalidHeaderKeyChar(0x09));
  EXPECT_TRUE(IsInvalidHeaderKeyChar(0x1F));
  EXPECT_TRUE(IsInvalidHeaderKeyChar(0x7F));
  EXPECT_TRUE(IsInvalidHeaderKeyChar(' '));
  EXPECT_TRUE(IsInvalidHeaderKeyChar('"'));
  EXPECT_TRUE(IsInvalidHeaderKeyChar('\t'));
  EXPECT_TRUE(IsInvalidHeaderKeyChar('\r'));
  EXPECT_TRUE(IsInvalidHeaderKeyChar('\n'));
  EXPECT_TRUE(IsInvalidHeaderKeyChar('}'));

  EXPECT_FALSE(IsInvalidHeaderKeyChar('a'));
  EXPECT_FALSE(IsInvalidHeaderKeyChar('B'));
  EXPECT_FALSE(IsInvalidHeaderKeyChar('7'));
  EXPECT_FALSE(IsInvalidHeaderKeyChar(0x42));
  EXPECT_FALSE(IsInvalidHeaderKeyChar(0x7C));
  EXPECT_FALSE(IsInvalidHeaderKeyChar(0x7E));
}

TEST(HeaderPropertiesTest, IsInvalidHeaderKeyCharAllowDoubleQuote) {
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x00));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x06));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x09));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x1F));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x7F));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote(' '));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote('\t'));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote('\r'));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote('\n'));
  EXPECT_TRUE(IsInvalidHeaderKeyCharAllowDoubleQuote('}'));

  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote('"'));
  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote('a'));
  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote('B'));
  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote('7'));
  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x42));
  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x7C));
  EXPECT_FALSE(IsInvalidHeaderKeyCharAllowDoubleQuote(0x7E));
}

TEST(HeaderPropertiesTest, IsInvalidHeaderChar) {
  EXPECT_TRUE(IsInvalidHeaderChar(0x00));
  EXPECT_TRUE(IsInvalidHeaderChar(0x06));
  EXPECT_TRUE(IsInvalidHeaderChar(0x1F));
  EXPECT_TRUE(IsInvalidHeaderChar(0x7F));

  EXPECT_FALSE(IsInvalidHeaderChar(0x09));
  EXPECT_FALSE(IsInvalidHeaderChar(' '));
  EXPECT_FALSE(IsInvalidHeaderChar('\t'));
  EXPECT_FALSE(IsInvalidHeaderChar('\r'));
  EXPECT_FALSE(IsInvalidHeaderChar('\n'));
  EXPECT_FALSE(IsInvalidHeaderChar('a'));
  EXPECT_FALSE(IsInvalidHeaderChar('B'));
  EXPECT_FALSE(IsInvalidHeaderChar('7'));
  EXPECT_FALSE(IsInvalidHeaderChar(0x42));
  EXPECT_FALSE(IsInvalidHeaderChar(0x7D));
}

TEST(HeaderPropertiesTest, KeyMoreRestrictiveThanValue) {
  for (int c = 0; c < 255; ++c) {
    if (IsInvalidHeaderChar(c)) {
      EXPECT_TRUE(IsInvalidHeaderKeyChar(c)) << c;
    }
  }
}

TEST(HeaderPropertiesTest, HasInvalidHeaderChars) {
  const char with_null[] = "Here's l\x00king at you, kid";
  EXPECT_TRUE(HasInvalidHeaderChars(std::string(with_null, sizeof(with_null))));
  EXPECT_TRUE(HasInvalidHeaderChars("Why's \x06 afraid of \x07? \x07\x08\x09"));
  EXPECT_TRUE(HasInvalidHeaderChars("\x1Flower power"));
  EXPECT_TRUE(HasInvalidHeaderChars("\x7Flowers more powers"));

  EXPECT_FALSE(HasInvalidHeaderChars("Plenty of space"));
  EXPECT_FALSE(HasInvalidHeaderChars("Keeping \tabs"));
  EXPECT_FALSE(HasInvalidHeaderChars("Al\right"));
  EXPECT_FALSE(HasInvalidHeaderChars("\new day"));
  EXPECT_FALSE(HasInvalidHeaderChars("\x42 is a nice character"));
}

}  // namespace
}  // namespace quiche::header_properties::test
