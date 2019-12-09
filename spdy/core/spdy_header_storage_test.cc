#include "net/third_party/quiche/src/spdy/core/spdy_header_storage.h"

#include "net/third_party/quiche/src/spdy/platform/api/spdy_test.h"

namespace spdy {
namespace test {

TEST(JoinTest, JoinEmpty) {
  std::vector<SpdyStringPiece> empty;
  SpdyStringPiece separator = ", ";
  char buf[10] = "";
  size_t written = Join(buf, empty, separator);
  EXPECT_EQ(0u, written);
}

TEST(JoinTest, JoinOne) {
  std::vector<SpdyStringPiece> v = {"one"};
  SpdyStringPiece separator = ", ";
  char buf[15];
  size_t written = Join(buf, v, separator);
  EXPECT_EQ(3u, written);
  EXPECT_EQ("one", SpdyStringPiece(buf, written));
}

TEST(JoinTest, JoinMultiple) {
  std::vector<SpdyStringPiece> v = {"one", "two", "three"};
  SpdyStringPiece separator = ", ";
  char buf[15];
  size_t written = Join(buf, v, separator);
  EXPECT_EQ(15u, written);
  EXPECT_EQ("one, two, three", SpdyStringPiece(buf, written));
}

}  // namespace test
}  // namespace spdy
