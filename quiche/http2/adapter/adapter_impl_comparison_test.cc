#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/nghttp2_adapter.h"
#include "quiche/http2/adapter/oghttp2_adapter.h"
#include "quiche/http2/adapter/recording_http2_visitor.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/spdy/core/spdy_protocol.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

TEST(AdapterImplComparisonTest, ClientHandlesFrames) {
  RecordingHttp2Visitor nghttp2_visitor;
  std::unique_ptr<NgHttp2Adapter> nghttp2_adapter =
      NgHttp2Adapter::CreateClientAdapter(nghttp2_visitor);

  RecordingHttp2Visitor oghttp2_visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  std::unique_ptr<OgHttp2Adapter> oghttp2_adapter =
      OgHttp2Adapter::Create(oghttp2_visitor, options);

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();

  nghttp2_adapter->ProcessBytes(initial_frames);
  oghttp2_adapter->ProcessBytes(initial_frames);

  EXPECT_EQ(nghttp2_visitor.GetEventSequence(),
            oghttp2_visitor.GetEventSequence());

  // TODO(b/181586191): Consider consistent behavior for delivering events on
  // non-existent streams between nghttp2_adapter and oghttp2_adapter.
}

TEST(AdapterImplComparisonTest, ServerHandlesFrames) {
  RecordingHttp2Visitor nghttp2_visitor;
  std::unique_ptr<NgHttp2Adapter> nghttp2_adapter =
      NgHttp2Adapter::CreateServerAdapter(nghttp2_visitor);

  RecordingHttp2Visitor oghttp2_visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kServer;
  std::unique_ptr<OgHttp2Adapter> oghttp2_adapter =
      OgHttp2Adapter::Create(oghttp2_visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(42)
                                 .WindowUpdate(0, 1000)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .Headers(3,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .RstStream(3, Http2ErrorCode::CANCEL)
                                 .Ping(47)
                                 .Serialize();

  nghttp2_adapter->ProcessBytes(frames);
  oghttp2_adapter->ProcessBytes(frames);

  EXPECT_EQ(nghttp2_visitor.GetEventSequence(),
            oghttp2_visitor.GetEventSequence());
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
