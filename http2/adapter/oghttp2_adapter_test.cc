#include "http2/adapter/oghttp2_adapter.h"

#include <string>

#include "absl/strings/str_join.h"
#include "http2/adapter/http2_protocol.h"
#include "http2/adapter/http2_visitor_interface.h"
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

using ConnectionError = Http2VisitorInterface::ConnectionError;

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

TEST_F(OgHttp2AdapterTest, InitialSettings) {
  DataSavingVisitor client_visitor;
  OgHttp2Adapter::Options client_options{.perspective = Perspective::kClient};
  auto client_adapter = OgHttp2Adapter::Create(client_visitor, client_options);

  DataSavingVisitor server_visitor;
  OgHttp2Adapter::Options server_options{.perspective = Perspective::kServer};
  auto server_adapter = OgHttp2Adapter::Create(server_visitor, server_options);

  testing::InSequence s;

  // Client sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(client_visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(client_visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  {
    int result = client_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = client_visitor.data();
    EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
    data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
    EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
  }

  // Server sends the connection preface, including the initial SETTINGS.
  EXPECT_CALL(server_visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(server_visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  {
    int result = server_adapter->Send();
    EXPECT_EQ(0, result);
    absl::string_view data = server_visitor.data();
    EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
  }

  // Client processes the server's initial bytes, including initial SETTINGS.
  EXPECT_CALL(client_visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(client_visitor, OnSettingsStart());
  EXPECT_CALL(client_visitor, OnSettingsEnd());
  {
    const int64_t result = client_adapter->ProcessBytes(server_visitor.data());
    EXPECT_EQ(server_visitor.data().size(), static_cast<size_t>(result));
  }

  // Server processes the client's initial bytes, including initial SETTINGS.
  EXPECT_CALL(server_visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(server_visitor, OnSettingsStart());
  EXPECT_CALL(
      server_visitor,
      OnSetting(testing::AllOf(
          testing::Field(&Http2Setting::id, Http2KnownSettingsId::ENABLE_PUSH),
          testing::Field(&Http2Setting::value, 0))))
      .Times(2);
  EXPECT_CALL(server_visitor, OnSettingsEnd());
  {
    const int64_t result = server_adapter->ProcessBytes(client_visitor.data());
    EXPECT_EQ(client_visitor.data().size(), static_cast<size_t>(result));
  }
}

TEST_F(OgHttp2AdapterTest, AutomaticSettingsAndPingAcks) {
  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(http2_visitor_, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(http2_visitor_, OnSettingsStart());
  EXPECT_CALL(http2_visitor_, OnSettingsEnd());
  // PING
  EXPECT_CALL(http2_visitor_, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(http2_visitor_, OnPing(42, false));

  const int64_t read_result = adapter_->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter_->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  // PING ack
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(http2_visitor_, OnFrameSent(PING, 0, _, 0x1, 0));

  int send_result = adapter_->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(
      http2_visitor_.data(),
      EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                    spdy::SpdyFrameType::SETTINGS, spdy::SpdyFrameType::PING}));
}

TEST_F(OgHttp2AdapterTest, AutomaticPingAcksDisabled) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer,
                                  .auto_ping_ack = false};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames =
      TestFrameSequence().ClientPreface().Ping(42).Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // PING
  EXPECT_CALL(visitor, OnFrameHeader(0, _, PING, 0));
  EXPECT_CALL(visitor, OnPing(42, false));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_EQ(static_cast<size_t>(read_result), frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  // SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  // No PING ack expected because automatic PING acks are disabled.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientHandles100Headers) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 = adapter->SubmitRequest(headers1, nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}},
                   /*fin=*/false)
          .Ping(101)
          .Headers(1,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0));
  EXPECT_CALL(visitor, OnPing(101, false));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(PING, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(PING, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterClientTest, ClientRejects100HeadersWithFin) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});

  const int32_t stream_id1 = adapter->SubmitRequest(headers1, nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);
  QUICHE_LOG(INFO) << "Created stream: " << stream_id1;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .Headers(1, {{":status", "100"}}, /*fin=*/false)
          .Headers(1, {{":status", "100"}}, /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "100"));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));
  // NOTE: nghttp2 does not deliver the OnEndStream event.
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, _, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
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
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
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
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientHandlesMetadataWithError) {
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
  EXPECT_CALL(visitor, OnMetadataForStream(1, _))
      .WillOnce(testing::Return(false));
  // Remaining frames are not processed due to the error.
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  // Negative integer returned to indicate an error.
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  EXPECT_FALSE(adapter->want_read());
  EXPECT_TRUE(adapter->want_write());
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

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, stream_id1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientConnectionErrorWhileHandlingHeadersOnly) {
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
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":status", "200"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, "server", "my-fake-server"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"))
      .WillOnce(
          testing::Return(Http2VisitorInterface::HEADER_CONNECTION_ERROR));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
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
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientHandlesSmallerHpackHeaderTableSetting) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 = ToHeaders({
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.com"},
      {":path", "/this/is/request/one"},
      {"x-i-do-not-like", "green eggs and ham"},
      {"x-i-will-not-eat-them", "here or there, in a box, with a fox"},
      {"x-like-them-in-a-house", "no"},
      {"x-like-them-with-a-mouse", "no"},
  });

  const int32_t stream_id1 = adapter->SubmitRequest(headers1, nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  EXPECT_GT(adapter->GetHpackEncoderDynamicTableSize(), 100);

  const std::string stream_frames =
      TestFrameSequence().Settings({{HEADER_TABLE_SIZE, 100u}}).Serialize();
  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{HEADER_TABLE_SIZE, 100u}));
  // Duplicate setting callback due to the way extensions work.
  EXPECT_CALL(visitor, OnSetting(Http2Setting{HEADER_TABLE_SIZE, 100u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 100);
  EXPECT_LE(adapter->GetHpackEncoderDynamicTableSize(), 100);
}

TEST(OgHttp2AdapterClientTest, ClientHandlesLargerHpackHeaderTableSetting) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 4096);

  const std::string stream_frames =
      TestFrameSequence().Settings({{HEADER_TABLE_SIZE, 40960u}}).Serialize();
  // Server preface (SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting(Http2Setting{HEADER_TABLE_SIZE, 40960u}));
  // Duplicate setting callback due to the way extensions work.
  EXPECT_CALL(visitor, OnSetting(Http2Setting{HEADER_TABLE_SIZE, 40960u}));
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  // The increased capacity will not be applied until a SETTINGS ack is
  // serialized.
  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 4096);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  EXPECT_EQ(adapter->GetHpackEncoderDynamicTableCapacity(), 40960);
}

TEST(OgHttp2AdapterClientTest, ClientSendsHpackHeaderTableSetting) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 = ToHeaders({
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.com"},
      {":path", "/this/is/request/one"},
  });

  const int32_t stream_id1 = adapter->SubmitRequest(headers1, nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id1, _, 0x5, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string stream_frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()
          .Headers(
              1,
              {{":status", "200"},
               {"server", "my-fake-server"},
               {"date", "Tue, 6 Apr 2021 12:54:01 GMT"},
               {"x-i-do-not-like", "green eggs and ham"},
               {"x-i-will-not-eat-them", "here or there, in a box, with a fox"},
               {"x-like-them-in-a-house", "no"},
               {"x-like-them-with-a-mouse", "no"}},
              /*fin=*/true)
          .Serialize();
  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Server acks client's initial SETTINGS.
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 1));
  EXPECT_CALL(visitor, OnSettingsAck());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(7);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  // Submit settings, check decoder table size.
  adapter->SubmitSettings({{HEADER_TABLE_SIZE, 100u}});
  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  // Server preface SETTINGS ack
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  // SETTINGS with the new header table size value
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));

  // Because the client has not yet seen an ack from the server for the SETTINGS
  // with header table size, it has not applied the new value.
  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::vector<const Header> headers2 = ToHeaders({
      {":method", "GET"},
      {":scheme", "http"},
      {":authority", "example.com"},
      {":path", "/this/is/request/two"},
  });

  const int32_t stream_id2 = adapter->SubmitRequest(headers2, nullptr, nullptr);
  ASSERT_GT(stream_id2, stream_id1);

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id2, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id2, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  visitor.Clear();

  const std::string response_frames =
      TestFrameSequence()
          .Headers(stream_id2,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(stream_id2, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id2));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id2, _, _)).Times(3);
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id2));
  EXPECT_CALL(visitor, OnEndStream(stream_id2));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id2, Http2ErrorCode::HTTP2_NO_ERROR));

  const int64_t response_result = adapter->ProcessBytes(response_frames);
  EXPECT_EQ(response_frames.size(), static_cast<size_t>(response_result));

  // Still no ack for the outbound settings.
  EXPECT_GT(adapter->GetHpackDecoderSizeLimit(), 100);

  const std::string settings_ack =
      TestFrameSequence().SettingsAck().Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 1));
  EXPECT_CALL(visitor, OnSettingsAck());

  const int64_t ack_result = adapter->ProcessBytes(settings_ack);
  EXPECT_EQ(settings_ack.size(), static_cast<size_t>(ack_result));
  // Ack has finally arrived.
  EXPECT_EQ(adapter->GetHpackDecoderSizeLimit(), 100);
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

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, stream_id1, 4, 0x0, 1));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::PROTOCOL_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterClientTest, ClientFailsOnGoAway) {
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
          .GoAway(1, Http2ErrorCode::INTERNAL_ERROR, "indigestion")
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
              OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(0, _, GOAWAY, 0));
  // TODO(birenroy): Pass the GOAWAY opaque data through the oghttp2 stack.
  EXPECT_CALL(visitor, OnGoAway(1, Http2ErrorCode::INTERNAL_ERROR, ""))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientRejects101Response) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  const std::vector<const Header> headers1 =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"},
                 {"upgrade", "new-protocol"}});

  const int32_t stream_id1 = adapter->SubmitRequest(headers1, nullptr, nullptr);
  ASSERT_GT(stream_id1, 0);

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
                   {{":status", "101"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  1, Http2VisitorInterface::InvalidFrameError::kHttpMessaging));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<int64_t>(stream_frames.size()), stream_result);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(
      visitor,
      OnFrameSent(RST_STREAM, 1, 4, 0x0,
                  static_cast<uint32_t>(Http2ErrorCode::PROTOCOL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  EXPECT_TRUE(adapter->want_write());
  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterClientTest, ClientObeysMaxConcurrentStreams) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_FALSE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  // Even though the user has not queued any frames for the session, it should
  // still send the connection preface.
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = visitor.data();
  EXPECT_THAT(serialized,
              testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  serialized.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  // Initial SETTINGS.
  EXPECT_THAT(serialized, EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence()
          .ServerPreface({{.id = MAX_CONCURRENT_STREAMS, .value = 1}})
          .Serialize();
  testing::InSequence s;

  // Server preface (SETTINGS with MAX_CONCURRENT_STREAMS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 6, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSetting);
  // TODO(diannahu): Remove this duplicate call with a separate
  // ExtensionVisitorInterface implementation.
  EXPECT_CALL(visitor, OnSetting);
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Session will want to write a SETTINGS ack.
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string kBody = "This is an example request body.";
  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, true);
  body1->AppendPayload(kBody);
  body1->EndData();
  const int stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "POST"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}}),
                             std::move(body1), nullptr);
  EXPECT_GT(stream_id, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x4, 0));
  EXPECT_CALL(visitor, OnFrameSent(DATA, stream_id, _, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS,
                                            spdy::SpdyFrameType::DATA}));
  EXPECT_THAT(visitor.data(), testing::HasSubstr(kBody));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  const int next_stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "POST"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/two"}}),
                             nullptr, nullptr);

  // A new pending stream is created, but because of MAX_CONCURRENT_STREAMS, the
  // session should not want to write it at the moment.
  EXPECT_GT(next_stream_id, stream_id);
  EXPECT_FALSE(adapter->want_write());

  const std::string stream_frames =
      TestFrameSequence()
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(stream_id, "This is the response body.", /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, ":status", "200"));
  EXPECT_CALL(visitor,
              OnHeaderForStream(stream_id, "server", "my-fake-server"));
  EXPECT_CALL(visitor, OnHeaderForStream(stream_id, "date",
                                         "Tue, 6 Apr 2021 12:54:01 GMT"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(stream_id));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, 26, DATA, 0x1));
  EXPECT_CALL(visitor, OnBeginDataForStream(stream_id, 26));
  EXPECT_CALL(visitor,
              OnDataForStream(stream_id, "This is the response body."));
  EXPECT_CALL(visitor, OnEndStream(stream_id));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  // The first stream should close, which should make the session want to write
  // the next stream.
  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(stream_frames.size(), static_cast<size_t>(stream_result));
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, next_stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, next_stream_id, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);

  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterClientTest, FailureSendingConnectionPreface) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  visitor.set_has_write_error();
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kSendError));

  int result = adapter->Send();
  EXPECT_EQ(result, Http2VisitorInterface::kSendError);
}

TEST(OgHttp2AdapterClientTest, ClientForbidsPushPromise) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS}));

  visitor.Clear();

  const std::vector<const Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id = adapter->SubmitRequest(headers, nullptr, nullptr);
  ASSERT_GT(stream_id, 0);
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));
  write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::vector<const Header> push_headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/push"}});
  const std::string frames = TestFrameSequence()
                                 .ServerPreface()
                                 .SettingsAck()
                                 .PushPromise(stream_id, 2, push_headers)
                                 .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // SETTINGS ack (to acknowledge PUSH_ENABLED=0, though this is not explicitly
  // required for OgHttp2: should it be?)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck);

  // The PUSH_PROMISE is treated as an invalid frame.
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, PUSH_PROMISE, _));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidPushPromise));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_LT(read_result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // SETTINGS ack.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientForbidsPushStream) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  testing::InSequence s;

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));

  int write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS}));

  visitor.Clear();

  const std::vector<const Header> headers =
      ToHeaders({{":method", "GET"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}});
  const int32_t stream_id = adapter->SubmitRequest(headers, nullptr, nullptr);
  ASSERT_GT(stream_id, 0);
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));
  write_result = adapter->Send();
  EXPECT_EQ(0, write_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  const std::string frames =
      TestFrameSequence()
          .ServerPreface()
          .SettingsAck()
          .Headers(2,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/true)
          .Serialize();

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  // SETTINGS ack (to acknowledge PUSH_ENABLED=0, though this is not explicitly
  // required for OgHttp2: should it be?)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck);

  // The push HEADERS are invalid.
  EXPECT_CALL(visitor, OnFrameHeader(2, _, HEADERS, _));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidNewStreamId));

  const int64_t read_result = adapter->ProcessBytes(frames);
  EXPECT_LT(read_result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));

  int result = adapter->Send();
  EXPECT_EQ(0, result);
  // SETTINGS ack.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
}

TEST(OgHttp2AdapterClientTest, ClientReceivesDataOnClosedStream) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kClient};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  int result = adapter->Send();
  EXPECT_EQ(0, result);
  absl::string_view data = visitor.data();
  EXPECT_THAT(data, testing::StartsWith(spdy::kHttp2ConnectionHeaderPrefix));
  data.remove_prefix(strlen(spdy::kHttp2ConnectionHeaderPrefix));
  EXPECT_THAT(data, EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
  visitor.Clear();

  const std::string initial_frames =
      TestFrameSequence().ServerPreface().Serialize();
  testing::InSequence s;

  // Server preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(initial_frames.size(), static_cast<size_t>(initial_result));

  // Client SETTINGS ack
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Let the client open a stream with a request.
  int stream_id =
      adapter->SubmitRequest(ToHeaders({{":method", "GET"},
                                        {":scheme", "http"},
                                        {":authority", "example.com"},
                                        {":path", "/this/is/request/one"}}),
                             nullptr, nullptr);
  EXPECT_GT(stream_id, 0);

  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, stream_id, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, stream_id, _, 0x5, 0));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();

  // Let the client RST_STREAM the stream it opened.
  adapter->SubmitRst(stream_id, Http2ErrorCode::CANCEL);
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, stream_id, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, stream_id, _, 0x0,
                                   static_cast<int>(Http2ErrorCode::CANCEL)));
  EXPECT_CALL(visitor,
              OnCloseStream(stream_id, Http2ErrorCode::HTTP2_NO_ERROR));

  result = adapter->Send();
  EXPECT_EQ(0, result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::RST_STREAM}));
  visitor.Clear();

  // Let the server send a response on the stream. (It might not have received
  // the RST_STREAM yet.)
  const std::string response_frames =
      TestFrameSequence()
          .Headers(stream_id,
                   {{":status", "200"},
                    {"server", "my-fake-server"},
                    {"date", "Tue, 6 Apr 2021 12:54:01 GMT"}},
                   /*fin=*/false)
          .Data(stream_id, "This is the response body.", /*fin=*/true)
          .Serialize();

  // The visitor gets notified about the HEADERS frame and DATA frame for the
  // closed stream with no further processing on either frame.
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, HEADERS, 0x4));
  EXPECT_CALL(visitor, OnFrameHeader(stream_id, _, DATA, 0x1));

  const int64_t response_result = adapter->ProcessBytes(response_frames);
  EXPECT_EQ(response_frames.size(), static_cast<size_t>(response_result));

  EXPECT_FALSE(adapter->want_write());
}

TEST_F(OgHttp2AdapterTest, SubmitMetadata) {
  auto source = absl::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter_->SubmitMetadata(1, 16384u, std::move(source));
  EXPECT_TRUE(adapter_->want_write());

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
  EXPECT_FALSE(adapter_->want_write());
}

TEST_F(OgHttp2AdapterTest, SubmitMetadataMultipleFrames) {
  const auto kLargeValue = std::string(63 * 1024, 'a');
  auto source = absl::make_unique<TestMetadataSource>(
      ToHeaderBlock(ToHeaders({{"large-value", kLargeValue}})));
  adapter_->SubmitMetadata(1, 16384u, std::move(source));
  EXPECT_TRUE(adapter_->want_write());

  testing::InSequence seq;
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(kMetadataFrameType, 1, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(kMetadataFrameType, 1, _, 0x4));
  EXPECT_CALL(http2_visitor_, OnFrameSent(kMetadataFrameType, 1, _, 0x4, 0));

  int result = adapter_->Send();
  EXPECT_EQ(0, result);
  absl::string_view serialized = http2_visitor_.data();
  EXPECT_THAT(
      serialized,
      EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                    static_cast<spdy::SpdyFrameType>(kMetadataFrameType),
                    static_cast<spdy::SpdyFrameType>(kMetadataFrameType),
                    static_cast<spdy::SpdyFrameType>(kMetadataFrameType),
                    static_cast<spdy::SpdyFrameType>(kMetadataFrameType)}));
  EXPECT_FALSE(adapter_->want_write());
}

TEST_F(OgHttp2AdapterTest, SubmitConnectionMetadata) {
  auto source = absl::make_unique<TestMetadataSource>(ToHeaderBlock(ToHeaders(
      {{"query-cost", "is too darn high"}, {"secret-sauce", "hollandaise"}})));
  adapter_->SubmitMetadata(0, 16384u, std::move(source));
  EXPECT_TRUE(adapter_->want_write());

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
  EXPECT_FALSE(adapter_->want_write());
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
  EXPECT_TRUE(adapter_->want_read());
  EXPECT_FALSE(adapter_->want_write());

  adapter_->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  EXPECT_TRUE(adapter_->want_write());

  adapter_->SubmitPriorityForStream(3, 1, 255, true);
  adapter_->SubmitRst(3, Http2ErrorCode::CANCEL);
  adapter_->SubmitPing(42);
  adapter_->SubmitGoAway(13, Http2ErrorCode::HTTP2_NO_ERROR, "");
  adapter_->SubmitWindowUpdate(3, 127);
  EXPECT_TRUE(adapter_->want_write());

  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(PRIORITY, 3, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(PRIORITY, 3, _, 0x0, 0));
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(RST_STREAM, 3, _, 0x0, 0x8));
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
  EXPECT_FALSE(adapter_->want_write());
}

TEST_F(OgHttp2AdapterTest, TestPartialSerialize) {
  EXPECT_FALSE(adapter_->want_write());

  adapter_->SubmitSettings(
      {{HEADER_TABLE_SIZE, 128}, {MAX_FRAME_SIZE, 128 << 10}});
  adapter_->SubmitGoAway(13, Http2ErrorCode::HTTP2_NO_ERROR,
                         "And don't come back!");
  adapter_->SubmitPing(42);
  EXPECT_TRUE(adapter_->want_write());

  http2_visitor_.set_send_limit(20);
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  int result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter_->want_write());
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(GOAWAY, 0, _, 0x0, 0));
  result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_TRUE(adapter_->want_write());
  EXPECT_CALL(http2_visitor_, OnBeforeFrameSent(PING, 0, _, 0x0));
  EXPECT_CALL(http2_visitor_, OnFrameSent(PING, 0, _, 0x0, 0));
  result = adapter_->Send();
  EXPECT_EQ(0, result);
  EXPECT_FALSE(adapter_->want_write());
  EXPECT_THAT(http2_visitor_.data(),
              EqualsFrames({SpdyFrameType::SETTINGS, SpdyFrameType::GOAWAY,
                            SpdyFrameType::PING}));
}

TEST(OgHttp2AdapterServerTest, ClientSendsContinuation) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
}

TEST(OgHttp2AdapterServerTest, ClientSendsMetadataWithContinuation) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));
  EXPECT_EQ(TestFrameSequence::MetadataBlockForPayload(
                "Example connection metadata in multiple frames"),
            absl::StrJoin(visitor.GetMetadata(0), ""));
  EXPECT_EQ(TestFrameSequence::MetadataBlockForPayload(
                "Some stream metadata that's also sent in multiple frames"),
            absl::StrJoin(visitor.GetMetadata(1), ""));
}

TEST(OgHttp2AdapterServerTest, ServerSubmitsResponseWithDataSourceError) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  auto body1 = absl::make_unique<TestDataFrameSource>(visitor, false);
  body1->SimulateError();
  int submit_result = adapter->SubmitResponse(
      1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
      std::move(body1));
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
  // TODO(birenroy): Send RST_STREAM INTERNAL_ERROR to the client as well.
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::INTERNAL_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::HEADERS}));
  visitor.Clear();
  EXPECT_FALSE(adapter->want_write());

  // Since the stream has been closed, it is not possible to submit trailers for
  // the stream.
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_LT(trailer_result, 0);
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterServerTest, CompleteRequestWithServerResponse) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/false)
          .Data(1, "This is the response body.", /*fin=*/true)
          .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 1));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, _));
  EXPECT_CALL(visitor, OnEndStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}), nullptr);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterServerTest, IncompleteRequestWithServerResponse) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}), nullptr);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  // RST_STREAM NO_ERROR option is disabled.

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::HEADERS}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterServerTest,
     IncompleteRequestWithServerResponseRstStreamEnabled) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer,
                                  .rst_stream_no_error_when_incomplete = true};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());
  // Stream 1
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  int submit_result =
      adapter->SubmitResponse(1, ToHeaders({{":status", "200"}}), nullptr);
  EXPECT_EQ(submit_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(RST_STREAM, 1, 4, 0x0, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::HEADERS,
                                            spdy::SpdyFrameType::RST_STREAM}));
  EXPECT_FALSE(adapter->want_write());
}

TEST(OgHttp2AdapterServerTest, ServerSendsInvalidTrailers) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  EXPECT_FALSE(adapter->want_write());

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

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

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
  EXPECT_TRUE(adapter->want_write());

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
  EXPECT_FALSE(adapter->want_write());

  // The body source has been exhausted by the call to Send() above.
  int trailer_result =
      adapter->SubmitTrailer(1, ToHeaders({{":final-status", "a-ok"}}));
  ASSERT_EQ(trailer_result, 0);
  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
  EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
}

// Tests the case where the response body is in the progress of being sent while
// trailers are queued.
TEST(OgHttp2AdapterServerTest, ServerSubmitsTrailersWhileDataDeferred) {
  DataSavingVisitor visitor;
  for (const bool queue_trailers : {true, false}) {
    OgHttp2Adapter::Options options{
        .perspective = Perspective::kServer,
        .trailers_require_end_data = queue_trailers};
    auto adapter = OgHttp2Adapter::Create(visitor, options);

    const std::string frames = TestFrameSequence()
                                   .ClientPreface()
                                   .Headers(1,
                                            {{":method", "POST"},
                                             {":scheme", "https"},
                                             {":authority", "example.com"},
                                             {":path", "/this/is/request/one"}},
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
    EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
    EXPECT_CALL(visitor, OnEndHeadersForStream(1));
    EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
    EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
    EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
    EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
    EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
    EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
    EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

    const int64_t result = adapter->ProcessBytes(frames);
    EXPECT_EQ(frames.size(), static_cast<size_t>(result));

    EXPECT_TRUE(adapter->want_write());

    EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
    EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
    EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
    EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

    int send_result = adapter->Send();
    EXPECT_EQ(0, send_result);
    visitor.Clear();

    const absl::string_view kBody = "This is an example response body.";

    // The body source must indicate that the end of the body is not the end of
    // the stream.
    auto body1 = absl::make_unique<TestDataFrameSource>(visitor, false);
    body1->AppendPayload(kBody);
    auto* body1_ptr = body1.get();
    int submit_result = adapter->SubmitResponse(
        1, ToHeaders({{":status", "200"}, {"x-comment", "Sure, sounds good."}}),
        std::move(body1));
    EXPECT_EQ(submit_result, 0);
    EXPECT_TRUE(adapter->want_write());

    EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x4));
    EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x4, 0));
    EXPECT_CALL(visitor, OnFrameSent(DATA, 1, _, 0x0, 0));

    send_result = adapter->Send();
    EXPECT_EQ(0, send_result);
    visitor.Clear();
    EXPECT_FALSE(adapter->want_write());

    int trailer_result =
        adapter->SubmitTrailer(1, ToHeaders({{"final-status", "a-ok"}}));
    ASSERT_EQ(trailer_result, 0);
    if (queue_trailers) {
      // Even though there are new trailers to write, the data source has not
      // finished writing data and is blocked.
      EXPECT_FALSE(adapter->want_write());

      body1_ptr->EndData();
      adapter->ResumeStream(1);
      EXPECT_TRUE(adapter->want_write());

      EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
      EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));

      send_result = adapter->Send();
      EXPECT_EQ(0, send_result);
    } else {
      // Even though the data source has not finished sending data, the library
      // will write the trailers anyway.
      EXPECT_TRUE(adapter->want_write());

      EXPECT_CALL(visitor, OnBeforeFrameSent(HEADERS, 1, _, 0x5));
      EXPECT_CALL(visitor, OnFrameSent(HEADERS, 1, _, 0x5, 0));

      send_result = adapter->Send();
      EXPECT_EQ(0, send_result);
      EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::HEADERS}));
    }
  }
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
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader));
  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(1, 2000));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, _));
  EXPECT_CALL(visitor, OnDataForStream(1, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(0, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnWindowUpdate(0, 2000));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_EQ(frames.size(), static_cast<size_t>(result));

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM}));
}

TEST(OgHttp2AdapterServerTest, ServerConnectionErrorWhileHandlingHeaders) {
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
                                           {"Accept", "uppercase, oh boy!"}},
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
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(1, Http2VisitorInterface::InvalidFrameError::kHttpHeader))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kHeaderError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 1, 4, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 1, 4, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));
  EXPECT_CALL(visitor, OnCloseStream(1, Http2ErrorCode::HTTP2_NO_ERROR));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS ack
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::RST_STREAM,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerErrorAfterHandlingHeaders) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
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
  EXPECT_CALL(visitor, OnEndHeadersForStream(1))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

// Exercises the case when a visitor chooses to reject a frame based solely on
// the frame header, which is a fatal error for the connection.
TEST(OgHttp2AdapterServerTest, ServerRejectsFrameHeader) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Ping(64)
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
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

  EXPECT_CALL(visitor, OnFrameHeader(0, 8, PING, 0))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerRejectsBeginningOfData) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
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
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25))
      .WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerRejectsStreamData) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(1,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
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
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(1, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(1, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(1, 25));
  EXPECT_CALL(visitor, OnDataForStream(1, _)).WillOnce(testing::Return(false));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kParseError));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::INTERNAL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

// Exercises a naive mutually recursive test client and server. This test fails
// without recursion guards in OgHttp2Session.
TEST(OgHttp2AdapterInteractionTest, ClientServerInteractionTest) {
  MockHttp2Visitor client_visitor;
  auto client_adapter =
      OgHttp2Adapter::Create(client_visitor, {Perspective::kClient});
  MockHttp2Visitor server_visitor;
  auto server_adapter =
      OgHttp2Adapter::Create(server_visitor, {Perspective::kServer});

  // Feeds bytes sent from the client into the server's ProcessBytes.
  EXPECT_CALL(client_visitor, OnReadyToSend(_))
      .WillRepeatedly(
          testing::Invoke(server_adapter.get(), &OgHttp2Adapter::ProcessBytes));
  // Feeds bytes sent from the server into the client's ProcessBytes.
  EXPECT_CALL(server_visitor, OnReadyToSend(_))
      .WillRepeatedly(
          testing::Invoke(client_adapter.get(), &OgHttp2Adapter::ProcessBytes));
  // Sets up the server to respond automatically to a request from a client.
  EXPECT_CALL(server_visitor, OnEndHeadersForStream(_))
      .WillRepeatedly([&server_adapter](Http2StreamId stream_id) {
        server_adapter->SubmitResponse(
            stream_id, ToHeaders({{":status", "200"}}), nullptr);
        server_adapter->Send();
        return true;
      });
  // Sets up the client to create a new stream automatically when receiving a
  // response.
  EXPECT_CALL(client_visitor, OnEndHeadersForStream(_))
      .WillRepeatedly([&client_adapter,
                       &client_visitor](Http2StreamId stream_id) {
        if (stream_id < 10) {
          const Http2StreamId new_stream_id = stream_id + 2;
          auto body =
              absl::make_unique<TestDataFrameSource>(client_visitor, true);
          body->AppendPayload("This is an example request body.");
          body->EndData();
          const int created_stream_id = client_adapter->SubmitRequest(
              ToHeaders({{":method", "GET"},
                         {":scheme", "http"},
                         {":authority", "example.com"},
                         {":path",
                          absl::StrCat("/this/is/request/", new_stream_id)}}),
              std::move(body), nullptr);
          EXPECT_EQ(new_stream_id, created_stream_id);
          client_adapter->Send();
        }
        return true;
      });

  // Submit a request to ensure the first stream is created.
  int stream_id = client_adapter->SubmitRequest(
      ToHeaders({{":method", "POST"},
                 {":scheme", "http"},
                 {":authority", "example.com"},
                 {":path", "/this/is/request/one"}}),
      nullptr, nullptr);
  EXPECT_EQ(stream_id, 1);

  client_adapter->Send();
}

TEST(OgHttp2AdapterServerTest, ServerForbidsNewStreamBelowWatermark) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Headers(3,
                                          {{":method", "POST"},
                                           {":scheme", "https"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/one"}},
                                          /*fin=*/false)
                                 .Data(3, "This is the request body.")
                                 .Headers(1,
                                          {{":method", "GET"},
                                           {":scheme", "http"},
                                           {":authority", "example.com"},
                                           {":path", "/this/is/request/two"}},
                                          /*fin=*/true)
                                 .Serialize();
  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 4));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(3));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":method", "POST"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":scheme", "https"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":authority", "example.com"));
  EXPECT_CALL(visitor, OnHeaderForStream(3, ":path", "/this/is/request/one"));
  EXPECT_CALL(visitor, OnEndHeadersForStream(3));
  EXPECT_CALL(visitor, OnFrameHeader(3, 25, DATA, 0));
  EXPECT_CALL(visitor, OnBeginDataForStream(3, 25));
  EXPECT_CALL(visitor, OnDataForStream(3, "This is the request body."));
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 5));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kInvalidNewStreamId));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_EQ(3, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, _, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, _, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerForbidsWindowUpdateOnIdleStream) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames =
      TestFrameSequence().ClientPreface().WindowUpdate(1, 42).Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, 4, WINDOW_UPDATE, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerForbidsDataOnIdleStream) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames = TestFrameSequence()
                                 .ClientPreface()
                                 .Data(1, "Sorry, out of order")
                                 .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, DATA, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerForbidsRstStreamOnIdleStream) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);

  EXPECT_EQ(0, adapter->GetHighestReceivedStreamId());

  const std::string frames =
      TestFrameSequence()
          .ClientPreface()
          .RstStream(1, Http2ErrorCode::ENHANCE_YOUR_CALM)
          .Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  EXPECT_CALL(visitor, OnFrameHeader(1, _, RST_STREAM, 0));
  EXPECT_CALL(visitor, OnConnectionError(ConnectionError::kWrongFrameSequence));

  const int64_t result = adapter->ProcessBytes(frames);
  EXPECT_LT(result, 0);

  EXPECT_EQ(1, adapter->GetHighestReceivedStreamId());

  EXPECT_TRUE(adapter->want_write());

  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  int send_result = adapter->Send();
  // Some bytes should have been serialized.
  EXPECT_EQ(0, send_result);
  // SETTINGS, SETTINGS ack, and GOAWAY.
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest, ServerForbidsNewStreamAboveStreamLimit) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  adapter->SubmitSettings({{MAX_CONCURRENT_STREAMS, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server initial SETTINGS (with MAX_CONCURRENT_STREAMS) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Let the client send a SETTINGS ack and then attempt to open more than the
  // advertised number of streams. The overflow stream should be rejected.
  const std::string stream_frames =
      TestFrameSequence()
          .SettingsAck()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/true)
          .Headers(3,
                   {{":method", "GET"},
                    {":scheme", "http"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/two"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0x1));
  EXPECT_CALL(visitor, OnSettingsAck());
  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 0x5));
  EXPECT_CALL(
      visitor,
      OnInvalidFrame(3, Http2VisitorInterface::InvalidFrameError::kProtocol));
  // The oghttp2 stack also signals the connection error via OnConnectionError()
  // and a negative ProcessBytes() return value.
  EXPECT_CALL(visitor,
              OnConnectionError(Http2VisitorInterface::ConnectionError::
                                    kExceededMaxConcurrentStreams));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_LT(stream_result, 0);

  // The server should send a GOAWAY for this error, even though
  // OnInvalidFrame() returns true.
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(GOAWAY, 0, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(GOAWAY, 0, _, 0x0,
                          static_cast<int>(Http2ErrorCode::PROTOCOL_ERROR)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::GOAWAY}));
}

TEST(OgHttp2AdapterServerTest,
     ServerRstStreamsNewStreamAboveStreamLimitBeforeAck) {
  DataSavingVisitor visitor;
  OgHttp2Adapter::Options options{.perspective = Perspective::kServer};
  auto adapter = OgHttp2Adapter::Create(visitor, options);
  adapter->SubmitSettings({{MAX_CONCURRENT_STREAMS, 1}});

  const std::string initial_frames =
      TestFrameSequence().ClientPreface().Serialize();

  testing::InSequence s;

  // Client preface (empty SETTINGS)
  EXPECT_CALL(visitor, OnFrameHeader(0, 0, SETTINGS, 0));
  EXPECT_CALL(visitor, OnSettingsStart());
  EXPECT_CALL(visitor, OnSettingsEnd());

  const int64_t initial_result = adapter->ProcessBytes(initial_frames);
  EXPECT_EQ(static_cast<size_t>(initial_result), initial_frames.size());

  EXPECT_TRUE(adapter->want_write());

  // Server initial SETTINGS (with MAX_CONCURRENT_STREAMS) and SETTINGS ack.
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 6, 0x0));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 6, 0x0, 0));
  EXPECT_CALL(visitor, OnBeforeFrameSent(SETTINGS, 0, 0, 0x1));
  EXPECT_CALL(visitor, OnFrameSent(SETTINGS, 0, 0, 0x1, 0));

  int send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::SETTINGS,
                                            spdy::SpdyFrameType::SETTINGS}));
  visitor.Clear();

  // Let the client avoid sending a SETTINGS ack and attempt to open more than
  // the advertised number of streams. The server should still reject the
  // overflow stream, albeit with RST_STREAM REFUSED_STREAM instead of GOAWAY.
  const std::string stream_frames =
      TestFrameSequence()
          .Headers(1,
                   {{":method", "GET"},
                    {":scheme", "https"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/one"}},
                   /*fin=*/true)
          .Headers(3,
                   {{":method", "GET"},
                    {":scheme", "http"},
                    {":authority", "example.com"},
                    {":path", "/this/is/request/two"}},
                   /*fin=*/true)
          .Serialize();

  EXPECT_CALL(visitor, OnFrameHeader(1, _, HEADERS, 0x5));
  EXPECT_CALL(visitor, OnBeginHeadersForStream(1));
  EXPECT_CALL(visitor, OnHeaderForStream(1, _, _)).Times(4);
  EXPECT_CALL(visitor, OnEndHeadersForStream(1));
  EXPECT_CALL(visitor, OnEndStream(1));
  EXPECT_CALL(visitor, OnFrameHeader(3, _, HEADERS, 0x5));
  EXPECT_CALL(visitor,
              OnInvalidFrame(
                  3, Http2VisitorInterface::InvalidFrameError::kRefusedStream));

  const int64_t stream_result = adapter->ProcessBytes(stream_frames);
  EXPECT_EQ(static_cast<size_t>(stream_result), stream_frames.size());

  // The server sends a RST_STREAM for the offending stream.
  EXPECT_TRUE(adapter->want_write());
  EXPECT_CALL(visitor, OnBeforeFrameSent(RST_STREAM, 3, _, 0x0));
  EXPECT_CALL(visitor,
              OnFrameSent(RST_STREAM, 3, _, 0x0,
                          static_cast<int>(Http2ErrorCode::REFUSED_STREAM)));

  send_result = adapter->Send();
  EXPECT_EQ(0, send_result);
  EXPECT_THAT(visitor.data(), EqualsFrames({spdy::SpdyFrameType::RST_STREAM}));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
