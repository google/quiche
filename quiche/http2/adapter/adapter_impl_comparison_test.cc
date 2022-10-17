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

TEST(AdapterImplComparisonTest, SubmitWindowUpdateBumpsWindow) {
  RecordingHttp2Visitor nghttp2_visitor;
  std::unique_ptr<NgHttp2Adapter> nghttp2_adapter =
      NgHttp2Adapter::CreateClientAdapter(nghttp2_visitor);

  RecordingHttp2Visitor oghttp2_visitor;
  OgHttp2Adapter::Options options;
  options.perspective = Perspective::kClient;
  std::unique_ptr<OgHttp2Adapter> oghttp2_adapter =
      OgHttp2Adapter::Create(oghttp2_visitor, options);

  int result;

  const std::vector<Header> request_headers =
      ToHeaders({{":method", "POST"},
                 {":scheme", "https"},
                 {":authority", "example.com"},
                 {":path", "/"}});
  const int kInitialFlowControlWindow = 65535;
  const int kConnectionWindowIncrease = 192 * 1024;

  const int32_t nghttp2_stream_id =
      nghttp2_adapter->SubmitRequest(request_headers, nullptr, nullptr);

  // Both the connection and stream flow control windows are increased.
  nghttp2_adapter->SubmitWindowUpdate(0, kConnectionWindowIncrease);
  nghttp2_adapter->SubmitWindowUpdate(nghttp2_stream_id,
                                      kConnectionWindowIncrease);
  result = nghttp2_adapter->Send();
  EXPECT_EQ(0, result);
  int nghttp2_window = nghttp2_adapter->GetReceiveWindowSize();
  EXPECT_EQ(kInitialFlowControlWindow + kConnectionWindowIncrease,
            nghttp2_window);

  const int32_t oghttp2_stream_id =
      oghttp2_adapter->SubmitRequest(request_headers, nullptr, nullptr);
  // Both the connection and stream flow control windows are increased.
  oghttp2_adapter->SubmitWindowUpdate(0, kConnectionWindowIncrease);
  oghttp2_adapter->SubmitWindowUpdate(oghttp2_stream_id,
                                      kConnectionWindowIncrease);
  result = oghttp2_adapter->Send();
  EXPECT_EQ(0, result);
  int oghttp2_window = oghttp2_adapter->GetReceiveWindowSize();
  EXPECT_EQ(kInitialFlowControlWindow + kConnectionWindowIncrease,
            oghttp2_window);

  // nghttp2 and oghttp2 agree on the advertised window.
  EXPECT_EQ(nghttp2_window, oghttp2_window);

  ASSERT_EQ(nghttp2_stream_id, oghttp2_stream_id);

  const int kMaxFrameSize = 16 * 1024;
  const std::string body_chunk(kMaxFrameSize, 'a');
  auto sequence = TestFrameSequence();
  sequence.ServerPreface().Headers(nghttp2_stream_id, {{":status", "200"}},
                                   /*fin=*/false);
  // This loop generates enough DATA frames to consume the window increase.
  const int kNumFrames = kConnectionWindowIncrease / kMaxFrameSize;
  for (int i = 0; i < kNumFrames; ++i) {
    sequence.Data(nghttp2_stream_id, body_chunk);
  }
  const std::string frames = sequence.Serialize();

  nghttp2_adapter->ProcessBytes(frames);
  // Marking the data consumed causes a window update, which is reflected in the
  // advertised window size.
  nghttp2_adapter->MarkDataConsumedForStream(nghttp2_stream_id,
                                             kNumFrames * kMaxFrameSize);
  result = nghttp2_adapter->Send();
  EXPECT_EQ(0, result);
  nghttp2_window = nghttp2_adapter->GetReceiveWindowSize();

  oghttp2_adapter->ProcessBytes(frames);
  // Marking the data consumed causes a window update, which is reflected in the
  // advertised window size.
  oghttp2_adapter->MarkDataConsumedForStream(oghttp2_stream_id,
                                             kNumFrames * kMaxFrameSize);
  result = oghttp2_adapter->Send();
  EXPECT_EQ(0, result);
  oghttp2_window = oghttp2_adapter->GetReceiveWindowSize();

  const int kMinExpectation =
      (kInitialFlowControlWindow + kConnectionWindowIncrease) / 2;
  EXPECT_GT(nghttp2_window, kMinExpectation);
  EXPECT_GT(oghttp2_window, kMinExpectation);
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
