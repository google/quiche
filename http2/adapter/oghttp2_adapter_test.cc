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

using spdy::SpdyFrameType;

class OgHttp2AdapterTest : public testing::Test {
 protected:
  void SetUp() override {
    OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
    adapter_ = OgHttp2Adapter::Create(http2_visitor_, options);
  }

  DataSavingVisitor http2_visitor_;
  std::unique_ptr<OgHttp2Adapter> adapter_;
};

TEST_F(OgHttp2AdapterTest, IsServerSession) {
  EXPECT_TRUE(adapter_->IsServerSession());
}

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

  adapter_->Send();
  EXPECT_THAT(
      http2_visitor_.data(),
      EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::PRIORITY,
                    SpdyFrameType::RST_STREAM, SpdyFrameType::PING,
                    SpdyFrameType::GOAWAY, SpdyFrameType::WINDOW_UPDATE}));
  EXPECT_FALSE(adapter_->session().want_write());
}

TEST_F(OgHttp2AdapterTest, TestPartialSerialize) {
  EXPECT_FALSE(adapter_->session().want_write());

  adapter_->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  adapter_->SubmitGoAway(13, Http2ErrorCode::NO_ERROR, "And don't come back!");
  adapter_->SubmitPing(42);
  EXPECT_TRUE(adapter_->session().want_write());

  http2_visitor_.set_send_limit(20);
  adapter_->Send();
  EXPECT_TRUE(adapter_->session().want_write());
  adapter_->Send();
  EXPECT_TRUE(adapter_->session().want_write());
  adapter_->Send();
  EXPECT_FALSE(adapter_->session().want_write());
  EXPECT_THAT(http2_visitor_.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY,
                            SpdyFrameType::PING}));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
