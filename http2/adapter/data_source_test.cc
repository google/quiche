#include "http2/adapter/data_source.h"

#include "common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

TEST(StringDataSourceTest, EmptyString) {
  StringDataSource source("");

  EXPECT_EQ(source.state(), DataSource::DONE);
  EXPECT_THAT(source.NextData(), testing::IsEmpty());
}

TEST(StringDataSourceTest, PartialConsume) {
  StringDataSource source("I'm a HTTP message body. Really!");

  EXPECT_EQ(source.state(), DataSource::READY);
  EXPECT_THAT(source.NextData(), testing::Not(testing::IsEmpty()));
  source.Consume(6);
  EXPECT_EQ(source.state(), DataSource::READY);
  EXPECT_THAT(source.NextData(), testing::StartsWith("HTTP"));

  source.Consume(0);
  EXPECT_EQ(source.state(), DataSource::READY);
  EXPECT_THAT(source.NextData(), testing::StartsWith("HTTP"));

  // Consumes more than the remaining bytes available.
  source.Consume(50);
  EXPECT_THAT(source.NextData(), testing::IsEmpty())
      << "next data: " << source.NextData();
  EXPECT_EQ(source.state(), DataSource::DONE);
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
