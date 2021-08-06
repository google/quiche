#include "http2/adapter/oghttp2_adapter.h"

#include "absl/strings/str_join.h"
#include "http2/adapter/mock_http2_visitor.h"
#include "http2/adapter/oghttp2_util.h"
#include "http2/adapter/test_frame_sequence.h"
#include "http2/adapter/test_utils.h"
#include "common/platform/api/quiche_test.h"
#include "common/platform/api/quiche_test_helpers.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using testing::_;

enum FrameType {
  DATA,
  HEADERS,
  PRIORITY,
  RST_STREAM,
  SETTINGS,
  PUSH_PROMISE,
  PING,
  GOAWAY,
  WINDOW_UPDATE,
  CONTINUATION,
};

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

TEST(OgHttp2AdapterClientTest, ClientHandlesTrailers) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                  spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .Headers(1, {{"final-status", "A-OK"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "final-status", "A-OK"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::NO_ERROR));

  const size_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->session().want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientHandlesMetadata) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                  spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Metadata(0, "Example connection metadata")
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Metadata(1, "Example stream metadata")
          .Data(1, "This is the response body.", true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::NO_ERROR));

  const size_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->session().want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientRstStreamWhileHandlingHeaders) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                  spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"))
      .WillOnce(testing::DoAll(
          testing::InvokeWithoutArgs([&adapter]() {
            adapter->SubmitRst(1, Http2ErrorCode::REFUSED_STREAM);
          }),
          testing::Return(Http2VisitorInterface::HEADER_RST_STREAM)));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));

  const size_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, stream_id1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::NO_ERROR));

  EXPECT_TRUE(adapter->session().want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterClientTest, ClientConnectionErrorWhileHandlingHeaders) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                  spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"))
      .WillOnce(
          testing::Return(Http2VisitorInterface::HEADER_CONNECTION_ERROR));
  EXPECT_CALL(visitor, OnConnectionError());
  // Note: OgHttp2Adapter continues processing bytes until the input is
  // complete.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));

  const size_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->session().want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientRejectsHeaders) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                  spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1))
      .WillOnce(testing::Return(false));
  // Rejecting headers leads to a connection error.
  EXPECT_CALL(visitor, OnConnectionError());
  // Note: OgHttp2Adapter continues processing bytes until the input is
  // complete.
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));

  const size_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_result, stream_frames.size());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->session().want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

// TODO(birenroy): Validate headers and re-enable this test. The library should
// invoke OnErrorDebug() with an error message for the invalid header. The
// library should also invoke OnInvalidFrame() for the invalid HEADERS frame.
TEST(OgHttp2AdapterClientTest, DISABLED_ClientHandlesInvalidTrailers) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const char* kSentinel1 = "arbitrary pointer 1";
  const int32_t stream_id1 =
      adapter->SubmitRequest(headers1, nullptr, const_cast<char*>(kSentinel1));
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                  spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.")
          .Headers(1, {{":bad-status", "9000"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 26, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 26));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the response body."));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));

  // Bad status trailer will cause a PROTOCOL_ERROR. The header is never
  // delivered in an OnHeaderForStream callback.

  const size_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, stream_id1, 4, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->session().want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
}

TEST_F(OgHttp2AdapterTest, SubmitMetadata) {
  auto source = absl::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter_->SubmitMetadata(1, std::move(source));
  EXPECT_TRUE(adapter_->session().want_write());

  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(http2_visitor_, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      http2_visitor_.data(),
      EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                    static_cast<spdy::SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter_->session().want_write());
}

TEST_F(OgHttp2AdapterTest, SubmitConnectionMetadata) {
  auto source = absl::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter_->SubmitMetadata(0, std::move(source));
  EXPECT_TRUE(adapter_->session().want_write());

  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(kMetadataFrameType, 0, _, 0x4));
  EXPECT_CALL(http2_visitor_, OnFrameSent(kMetadataFrameType, 0, _, 0x4, 0));

  int result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(
      http2_visitor_.data(),
      EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                    static_cast<spdy::SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter_->session().want_write());
}

TEST_F(OgHttp2AdapterTest, GetSendWindowSize) {
  const int peer_window = adapter_->GetSendWindowSize();
  EXPECT_EQ(peer_window, kInitialFlowControlWindowSize);
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

  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(PRIORITY, 3, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(PRIORITY, 3, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(RST_STREAM, 3, _, 0x0, 0x8));
  EXPECT_CALL(http2_visitor_, OnCloseStream(3, Http2ErrorCode::NO_ERROR));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(PING, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(GOAWAY, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(WINDOW_UPDATE, 3, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(WINDOW_UPDATE, 3, _, 0x0, 0));

  int result = adapter_->Send();
  EXPECT_EQ(0, result);
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
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  int result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter_->session().want_write());
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(GOAWAY, 0, _, 0x0, 0));
  result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter_->session().want_write());
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(PING, 0, _, 0x0, 0));
  result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_FALSE(adapter_->session().want_write());
  EXPECT_THAT(http2_visitor_.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY,
                            SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterServerTest, ClientSendsContinuation) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->session().want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true,
                                          /*add_continuation=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 1));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 4));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const size_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);
}

TEST(OgHttp2AdapterServerTest, ClientSendsMetadataWithContinuation) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->session().want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Metadata(0, "Example connection metadata in multiple frames", true)
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/false,
                   /*add_continuation=*/true)
          .Metadata(1,
                    "Some stream metadata that's also sent in multiple frames",
                    true)
          .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Metadata on stream 0
  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataForStream(0, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(0));

  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, CONTINUATION, 4));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  // Metadata on stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 0));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, kMetadataFrameType, 4));
  EXPECT_CALL(visitor, OnBeginMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataForStream(1, _));
  EXPECT_CALL(visitor, OnMetadataEndForStream(1));

  const size_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);
  EXPECT_EQ(TestFrameSequence::MetadataBlockForPayload(
                "Example connection metadata in multiple frames"),
            absl::StrJoin(visitor.GetMetadata(0), ""));
  EXPECT_EQ(TestFrameSequence::MetadataBlockForPayload(
                "Some stream metadata that's also sent in multiple frames"),
            absl::StrJoin(visitor.GetMetadata(1), ""));
}

TEST(OgHttp2AdapterServerTest, ServerSendsInvalidTrailers) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->session().want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "GET"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));

  const size_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  const absl::string_view kBody = "This is an example response body.";

  // The body source must indicate that the end of the body is not the end of
  // the stream.
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, false);
  body1->AppendPayload(kBody);
  body1->EndData();
  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1));
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->session().want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(),
              EqualsFrames(
                  {spdy::SpdyFrameType::SETTINGS, spdy::SpdyFrameType::SETTINGS,
                   spdy::SpdyFrameType::HEADERS, spdy::SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->session().want_write());

  // The body source has been exhausted by the call to Send() above.
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::NO_ERROR));
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(adapter->session().want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
}

TEST(OgHttp2AdapterServerTest, ServerErrorWhileHandlingHeaders) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"},
                                           {"accept", "some bogus value!"}},
                                          /*fin=*/false)
                                 .WindowUpdate(1, 2000)
                                 .Data(1, "This is the request body.")
                                 .WindowUpdate(0, 2000)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "accept", "some bogus value!"))
      .WillOnce(testing::Return(Http2VisitorInterface::HEADER_RST_STREAM));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

  const size_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), result);

  EXPECT_TRUE(adapter->session().want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::NO_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
