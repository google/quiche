#include "quiche/http2/adapter/nghttp2_data_provider.h"

#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {

const size_t kFrameHeaderSize = 9;

// Verifies that a nghttp2_data_provider derived from a DataFrameSource works
// correctly with nghttp2-style callbacks when the amount of data read is less
// than what the source provides.
TEST(DataProviderTest, ReadLessThanSourceProvides) {
  DataSavingVisitor visitor;
  TestDataFrameSource source(visitor, true);
  source.AppendPayload("Example payload");
  source.EndData();
  auto provider = MakeDataProvider(&source);
  uint32_t data_flags = 0;
  const int32_t kStreamId = 1;
  const size_t kReadLength = 10;
  // Read callback selects a payload length given an upper bound.
  ssize_t result =
      provider->read_callback(nullptr, kStreamId, nullptr, kReadLength,
                              &data_flags, &provider->source, nullptr);
  ASSERT_EQ(kReadLength, result);
  EXPECT_EQ(NGHTTP2_DATA_FLAG_NO_COPY, data_flags);

  const uint8_t framehd[kFrameHeaderSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  // Sends the frame header and some payload bytes.
  int send_result = callbacks::DataFrameSourceSendCallback(
      nullptr, nullptr, framehd, result, &provider->source, nullptr);
  EXPECT_EQ(0, send_result);
  // Data accepted by the visitor includes a frame header and kReadLength bytes
  // of payload.
  EXPECT_EQ(visitor.data().size(), kFrameHeaderSize + kReadLength);
}

// Verifies that a nghttp2_data_provider derived from a DataFrameSource works
// correctly with nghttp2-style callbacks when the amount of data read is more
// than what the source provides.
TEST(DataProviderTest, ReadMoreThanSourceProvides) {
  DataSavingVisitor visitor;
  const absl::string_view kPayload = "Example payload";
  TestDataFrameSource source(visitor, true);
  source.AppendPayload(kPayload);
  source.EndData();
  auto provider = MakeDataProvider(&source);
  uint32_t data_flags = 0;
  const int32_t kStreamId = 1;
  const size_t kReadLength = 30;
  // Read callback selects a payload length given an upper bound.
  ssize_t result =
      provider->read_callback(nullptr, kStreamId, nullptr, kReadLength,
                              &data_flags, &provider->source, nullptr);
  ASSERT_EQ(kPayload.size(), result);
  EXPECT_EQ(NGHTTP2_DATA_FLAG_NO_COPY | NGHTTP2_DATA_FLAG_EOF, data_flags);

  const uint8_t framehd[kFrameHeaderSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  // Sends the frame header and some payload bytes.
  int send_result = callbacks::DataFrameSourceSendCallback(
      nullptr, nullptr, framehd, result, &provider->source, nullptr);
  EXPECT_EQ(0, send_result);
  // Data accepted by the visitor includes a frame header and the entire
  // payload.
  EXPECT_EQ(visitor.data().size(), kFrameHeaderSize + kPayload.size());
}

// Verifies that a nghttp2_data_provider derived from a DataFrameSource works
// correctly with nghttp2-style callbacks when the source is blocked.
TEST(DataProviderTest, ReadFromBlockedSource) {
  DataSavingVisitor visitor;
  // Source has no payload, but also no fin, so it's blocked.
  TestDataFrameSource source(visitor, false);
  auto provider = MakeDataProvider(&source);
  uint32_t data_flags = 0;
  const int32_t kStreamId = 1;
  const size_t kReadLength = 10;
  ssize_t result =
      provider->read_callback(nullptr, kStreamId, nullptr, kReadLength,
                              &data_flags, &provider->source, nullptr);
  // Read operation is deferred, since the source is blocked.
  EXPECT_EQ(NGHTTP2_ERR_DEFERRED, result);
}

// Verifies that a nghttp2_data_provider derived from a DataFrameSource works
// correctly with nghttp2-style callbacks when the source provides only fin and
// no data.
TEST(DataProviderTest, ReadFromZeroLengthSource) {
  DataSavingVisitor visitor;
  // Empty payload and fin=true indicates the source is done.
  TestDataFrameSource source(visitor, true);
  source.EndData();
  auto provider = MakeDataProvider(&source);
  uint32_t data_flags = 0;
  const int32_t kStreamId = 1;
  const size_t kReadLength = 10;
  ssize_t result =
      provider->read_callback(nullptr, kStreamId, nullptr, kReadLength,
                              &data_flags, &provider->source, nullptr);
  ASSERT_EQ(0, result);
  EXPECT_EQ(NGHTTP2_DATA_FLAG_NO_COPY | NGHTTP2_DATA_FLAG_EOF, data_flags);

  const uint8_t framehd[kFrameHeaderSize] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
  int send_result = callbacks::DataFrameSourceSendCallback(
      nullptr, nullptr, framehd, result, &provider->source, nullptr);
  EXPECT_EQ(0, send_result);
  // Data accepted by the visitor includes a frame header with fin and zero
  // bytes of payload.
  EXPECT_EQ(visitor.data().size(), kFrameHeaderSize);
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
