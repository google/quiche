#include "quiche/http2/adapter/nghttp2_util.h"

#include <memory>
#include <string>

#include "quiche/http2/adapter/nghttp2_test_utils.h"
#include "quiche/http2/adapter/test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

// This send callback assumes |source|'s pointer is a TestDataSource, and
// |user_data| is a std::string.
int FakeSendCallback(nghttp2_session*, nghttp2_frame* /*frame*/,
                     const uint8_t* framehd, size_t length,
                     nghttp2_data_source* source, void* user_data) {
  auto* dest = static_cast<std::string*>(user_data);
  // Appends the frame header to the string.
  absl::StrAppend(dest, ToStringView(framehd, 9));
  auto* test_source = static_cast<TestDataSource*>(source->ptr);
  absl::string_view payload = test_source->ReadNext(length);
  // Appends the frame payload to the string.
  absl::StrAppend(dest, payload);
  return 0;
}

TEST(MakeZeroCopyDataFrameSource, EmptyPayload) {
  std::string result;

  const absl::string_view kEmptyBody = "";
  TestDataSource body1{kEmptyBody};
  // The TestDataSource is wrapped in the nghttp2_data_provider data type.
  nghttp2_data_provider provider = body1.MakeDataProvider();

  // This call transforms it back into a DataFrameSource, which is compatible
  // with the Http2Adapter API.
  std::unique_ptr<DataFrameSource> frame_source =
      MakeZeroCopyDataFrameSource(provider, &result, FakeSendCallback);
  auto [length, eof] = frame_source->SelectPayloadLength(100);
  EXPECT_EQ(length, 0);
  EXPECT_TRUE(eof);
  frame_source->Send("ninebytes", 0);
  EXPECT_EQ(result, "ninebytes");
}

TEST(MakeZeroCopyDataFrameSource, ShortPayload) {
  std::string result;

  const absl::string_view kShortBody =
      "<html><head><title>Example Page!</title></head>"
      "<body><div><span><table><tr><th><blink>Wow!!"
      "</blink></th></tr></table></span></div></body>"
      "</html>";
  TestDataSource body1{kShortBody};
  // The TestDataSource is wrapped in the nghttp2_data_provider data type.
  nghttp2_data_provider provider = body1.MakeDataProvider();

  // This call transforms it back into a DataFrameSource, which is compatible
  // with the Http2Adapter API.
  std::unique_ptr<DataFrameSource> frame_source =
      MakeZeroCopyDataFrameSource(provider, &result, FakeSendCallback);
  auto [length, eof] = frame_source->SelectPayloadLength(200);
  EXPECT_EQ(length, kShortBody.size());
  EXPECT_TRUE(eof);
  frame_source->Send("ninebytes", length);
  EXPECT_EQ(result, absl::StrCat("ninebytes", kShortBody));
}

TEST(MakeZeroCopyDataFrameSource, MultiFramePayload) {
  std::string result;

  const absl::string_view kShortBody =
      "<html><head><title>Example Page!</title></head>"
      "<body><div><span><table><tr><th><blink>Wow!!"
      "</blink></th></tr></table></span></div></body>"
      "</html>";
  TestDataSource body1{kShortBody};
  // The TestDataSource is wrapped in the nghttp2_data_provider data type.
  nghttp2_data_provider provider = body1.MakeDataProvider();

  // This call transforms it back into a DataFrameSource, which is compatible
  // with the Http2Adapter API.
  std::unique_ptr<DataFrameSource> frame_source =
      MakeZeroCopyDataFrameSource(provider, &result, FakeSendCallback);
  auto ret = frame_source->SelectPayloadLength(50);
  EXPECT_EQ(ret.first, 50);
  EXPECT_FALSE(ret.second);
  frame_source->Send("ninebyte1", ret.first);

  ret = frame_source->SelectPayloadLength(50);
  EXPECT_EQ(ret.first, 50);
  EXPECT_FALSE(ret.second);
  frame_source->Send("ninebyte2", ret.first);

  ret = frame_source->SelectPayloadLength(50);
  EXPECT_EQ(ret.first, 44);
  EXPECT_TRUE(ret.second);
  frame_source->Send("ninebyte3", ret.first);

  EXPECT_EQ(result,
            "ninebyte1<html><head><title>Example Page!</title></head><bo"
            "ninebyte2dy><div><span><table><tr><th><blink>Wow!!</blink><"
            "ninebyte3/th></tr></table></span></div></body></html>");
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
