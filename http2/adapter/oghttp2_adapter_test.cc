#include "http2/adapter/oghttp2_adapter.h"

#include "http2/adapter/mock_http2_visitor.h"
#include "http2/adapter/test_frame_sequence.h"
#include "http2/adapter/test_utils.h"
#include "common/platform/api/quiche_test.h"
#include "common/platform/api/quiche_test_helpers.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

class OgHttp2AdapterTest : public testing::Test {
 protected:
  void SetUp() override {
    OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
    adapter_ = OgHttp2Adapter::Create(http2_visitor_, options);
  }

  testing::StrictMock<MockHttp2Visitor> http2_visitor_;
  std::unique_ptr<OgHttp2Adapter> adapter_;
};

TEST_F(OgHttp2AdapterTest, ProcessBytes) {
  testing::InSequence seq;
  EXPECT_CALL(http2_visitor_, OnFrameHeader(0, 0, 4, 0));
  EXPECT_CALL(http2_visitor_, OnSettingsStart());
  EXPECT_CALL(http2_visitor_, OnSettingsEnd());
  EXPECT_CALL(http2_visitor_, OnFrameHeader(0, 8, 6, 0));
  EXPECT_CALL(http2_visitor_, OnPing(17, false));
  adapter_->ProcessBytes(
      TestFrameSequence().ClientPreface().Ping(17).Serialize());
}

TEST_F(OgHttp2AdapterTest, SubmitMetadata) {
  EXPECT_QUICHE_BUG(adapter_->SubmitMetadata(3, true), "Not implemented");
}

TEST_F(OgHttp2AdapterTest, GetPeerConnectionWindow) {
  const int peer_window = adapter_->GetPeerConnectionWindow();
  EXPECT_GT(peer_window, 0);
}

TEST_F(OgHttp2AdapterTest, MarkDataConsumedForStream) {
  EXPECT_QUICHE_BUG(adapter_->MarkDataConsumedForStream(1, 11),
                    "Stream 1 not found");
}

TEST_F(OgHttp2AdapterTest, TestSerialize) {
  EXPECT_TRUE(adapter_->session().want_read());
  EXPECT_FALSE(adapter_->session().want_write());

  adapter_->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  EXPECT_TRUE(adapter_->session().want_write());

  adapter_->SubmitPriorityForStream(3, 1, 255, true);
  adapter_->SubmitRst(3, Http2ErrorCode::CANCEL);
  adapter_->SubmitPing(42);
  adapter_->SubmitGoAway(13, Http2ErrorCode::NO_ERROR, "");
  adapter_->SubmitWindowUpdate(3, 127);
  EXPECT_TRUE(adapter_->session().want_write());

  EXPECT_THAT(
      adapter_->GetBytesToWrite(absl::nullopt),
      EqualsFrames(
          {spdy::SpdyFrameType::SETTINGS, spdy::SpdyFrameType::PRIORITY,
           spdy::SpdyFrameType::RST_STREAM, spdy::SpdyFrameType::PING,
           spdy::SpdyFrameType::GOAWAY, spdy::SpdyFrameType::WINDOW_UPDATE}));
  EXPECT_FALSE(adapter_->session().want_write());
}

TEST_F(OgHttp2AdapterTest, TestPartialSerialize) {
  EXPECT_FALSE(adapter_->session().want_write());

  adapter_->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  adapter_->SubmitGoAway(13, Http2ErrorCode::NO_ERROR, "And don't come back!");
  adapter_->SubmitPing(42);
  EXPECT_TRUE(adapter_->session().want_write());

  const std::string first_part = adapter_->GetBytesToWrite(10);
  EXPECT_TRUE(adapter_->session().want_write());
  const std::string second_part = adapter_->GetBytesToWrite(absl::nullopt);
  EXPECT_FALSE(adapter_->session().want_write());
  EXPECT_THAT(
      absl::StrCat(first_part, second_part),
      EqualsFrames({spdy::SpdyFrameType::SETTINGS, spdy::SpdyFrameType::GOAWAY,
                    spdy::SpdyFrameType::PING}));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
