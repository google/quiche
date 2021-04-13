#include "http2/adapter/nghttp2_session.h"

#include "http2/adapter/mock_http2_visitor.h"
#include "http2/adapter/nghttp2_callbacks.h"
#include "http2/adapter/nghttp2_util.h"
#include "http2/adapter/test_frame_sequence.h"
#include "common/platform/api/quiche_test.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

class DataSavingVisitor : public testing::StrictMock<MockHttp2Visitor> {
 public:
  void Save(absl::string_view data) { absl::StrAppend(&data_, data); }

  const std::string& data() { return data_; }

 private:
  std::string data_;
};

ssize_t SaveSessionOutput(nghttp2_session* session,
                          const uint8_t* data,
                          size_t length,
                          int flags,
                          void* user_data) {
  auto visitor = static_cast<DataSavingVisitor*>(user_data);
  visitor->Save(ToStringView(data, length));
  return length;
}

class NgHttp2SessionTest : public testing::Test {
 public:
  nghttp2_option* CreateOptions() {
    nghttp2_option* options;
    nghttp2_option_new(&options);
    nghttp2_option_set_no_auto_window_update(options, 1);
    return options;
  }

  nghttp2_session_callbacks* CreateCallbacks() {
    nghttp2_session_callbacks* callbacks = callbacks::Create();
    nghttp2_session_callbacks_set_send_callback(callbacks, &SaveSessionOutput);
    return callbacks;
  }

  DataSavingVisitor visitor_;
};

TEST_F(NgHttp2SessionTest, ClientConstruction) {
  NgHttp2Session session(Perspective::kClient, CreateCallbacks(),
                         CreateOptions(), &visitor_);
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kDefaultInitialStreamWindowSize);
  EXPECT_NE(session.raw_ptr(), nullptr);
}

TEST_F(NgHttp2SessionTest, ClientHandlesFrames) {
  NgHttp2Session session(Perspective::kClient, CreateCallbacks(),
                         CreateOptions(), &visitor_);

  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
  ASSERT_GT(visitor_.data().size(), 0);

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor_, OnSettingsStart());
  EXPECT_CALL(visitor_, OnSettingsEnd());

  EXPECT_CALL(visitor_, OnPing(42, false));
  EXPECT_CALL(visitor_, OnWindowUpdate(0, 1000));

  const ssize_t initial_result = session.ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), initial_result);

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kDefaultInitialStreamWindowSize + 1000);
  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));

  const std::vector<Header> headers1 = {{":method", "GET"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}};
  const auto nvs1 = GetRequestNghttp2Nvs(headers1);

  const std::vector<Header> headers2 = {{":method", "GET"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/two"}};
  const auto nvs2 = GetRequestNghttp2Nvs(headers2);

  const std::vector<Header> headers3 = {{":method", "GET"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/three"}};
  const auto nvs3 = GetRequestNghttp2Nvs(headers3);

  const int32_t stream_id1 = nghttp2_submit_request(
      session.raw_ptr(), nullptr, nvs1.data(), nvs1.size(), nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  const int32_t stream_id2 = nghttp2_submit_request(
      session.raw_ptr(), nullptr, nvs2.data(), nvs2.size(), nullptr, nullptr);
  ASSERT_GT(stream_id2, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id2;

  const int32_t stream_id3 = nghttp2_submit_request(
      session.raw_ptr(), nullptr, nvs3.data(), nvs3.size(), nullptr, nullptr);
  ASSERT_GT(stream_id3, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id3;

  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .RstStream(3, Http2ErrorCode::INTERNAL_ERROR)
          .GoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!")
          .Serialize();

  EXPECT_CALL(visitor_, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor_,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor_, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor_, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor_, OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor_, OnAbortStream(3, Http2ErrorCode::INTERNAL_ERROR));
  EXPECT_CALL(visitor_,
              OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!"));
  const ssize_t stream_result = session.ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);
  ASSERT_EQ(0, nghttp2_session_send(session.raw_ptr()));
}

TEST_F(NgHttp2SessionTest, ServerConstruction) {
  NgHttp2Session session(Perspective::kServer, CreateCallbacks(),
                         CreateOptions(), &visitor_);
  EXPECT_TRUE(session.want_read());
  EXPECT_FALSE(session.want_write());
  EXPECT_EQ(session.GetRemoteWindowSize(), kDefaultInitialStreamWindowSize);
  EXPECT_NE(session.raw_ptr(), nullptr);
}

TEST_F(NgHttp2SessionTest, ServerHandlesFrames) {
  NgHttp2Session session(Perspective::kServer, CreateCallbacks(),
                         CreateOptions(), &visitor_);

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
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor_, OnSettingsStart());
  EXPECT_CALL(visitor_, OnSettingsEnd());

  EXPECT_CALL(visitor_, OnPing(42, false));
  EXPECT_CALL(visitor_, OnWindowUpdate(0, 1000));
  EXPECT_CALL(visitor_, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor_, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor_, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor_, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor_, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor_, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":method", "GET"));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":scheme", "http"));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor_, OnHeaderForStream(3, ":path", "/this/is/request/two"));
  EXPECT_CALL(visitor_, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor_, OnEndStream(3));
  EXPECT_CALL(visitor_, OnRstStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor_, OnAbortStream(3, Http2ErrorCode::CANCEL));
  EXPECT_CALL(visitor_, OnPing(47, false));

  const ssize_t result = session.ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_EQ(session.GetRemoteWindowSize(),
            kDefaultInitialStreamWindowSize + 1000);
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
