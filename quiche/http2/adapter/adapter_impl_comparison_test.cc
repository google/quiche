#include <memory>
#include <string>
#include <vector>

#include "quiche/http2/adapter/http2_protocol.h"
#include "quiche/http2/adapter/mock_http2_visitor.h"
#include "quiche/http2/adapter/nghttp2_adapter.h"
#include "quiche/http2/adapter/oghttp2_adapter.h"
#include "quiche/http2/adapter/recording_http2_visitor.h"
#include "quiche/http2/adapter/test_frame_sequence.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using ::testing::Each;
using ::testing::InvokeWithoutArgs;

enum class Impl {
  kNgHttp2,
  kOgHttp2,
};

class ComparisonTest : public ::quiche::test::QuicheTest {
 public:
  std::vector<Impl> implementations() {
    return {Impl::kNgHttp2, Impl::kOgHttp2};
  }

  std::unique_ptr<Http2Adapter> CreateAdapter(Http2VisitorInterface& visitor,
                                              Impl impl, Perspective p) {
    switch (impl) {
      case Impl::kNgHttp2:
        if (p == Perspective::kClient) {
          return NgHttp2Adapter::CreateClientAdapter(visitor);
        } else {
          return NgHttp2Adapter::CreateServerAdapter(visitor);
        }
      case Impl::kOgHttp2:
        OgHttp2Adapter::Options options;
        options.perspective = p;
        return OgHttp2Adapter::Create(visitor, options);
    }
    return nullptr;  // Unreachable unless enum is corrupted.
  }
};

// Verifies that the implementations consider the same set of characters valid
// in paths.
TEST_F(ComparisonTest, PathCharValidation) {
  // Iterates over all character values.
  for (int i = std::numeric_limits<char>::min();
       i < std::numeric_limits<char>::max(); ++i) {
    const char c = static_cast<char>(i);

    // Constructs a path with the desired character.
    const std::string path_value =
        absl::StrCat("/aaa", absl::string_view(&c, 1), "bbb");

    SCOPED_TRACE(absl::StrCat("Path: [", absl::CEscape(path_value), "]"));

    // Constructs a request with the desired :path pseudoheader.
    const std::string frames = TestFrameSequence()
                                   .ClientPreface()
                                   .Headers(1,
                                            {{":method", "GET"},
                                             {":scheme", "https"},
                                             {":authority", "example.com"},
                                             {":path", path_value},
                                             {"name", "value"}},
                                            /*fin=*/true)
                                   .Serialize();
    // Accumulates frame validation results.
    std::vector<bool> frame_valid_results;
    bool frame_valid = true;

    testing::NiceMock<MockHttp2Visitor> visitor;
    ON_CALL(visitor, OnInvalidFrame)
        .WillByDefault(InvokeWithoutArgs([&frame_valid]() {
          // Records that the frame was not valid.
          frame_valid = false;
          return true;
        }));

    for (Impl impl : implementations()) {
      frame_valid = true;
      auto adapter = CreateAdapter(visitor, impl, Perspective::kServer);
      const int64_t result = adapter->ProcessBytes(frames);
      EXPECT_EQ(frames.size(), static_cast<size_t>(result));
      frame_valid_results.push_back(frame_valid);
    }
    // All implementations should agree on whether the frame was valid.
    EXPECT_THAT(frame_valid_results, Each(frame_valid_results.back()));
  }
}

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
      nghttp2_adapter->SubmitRequest(request_headers, true, nullptr);

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
      oghttp2_adapter->SubmitRequest(request_headers, true, nullptr);
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
