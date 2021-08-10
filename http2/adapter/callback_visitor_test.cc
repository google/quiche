#include "http2/adapter/callback_visitor.h"

#include "http2/adapter/mock_nghttp2_callbacks.h"
#include "http2/adapter/nghttp2_test_utils.h"
#include "http2/adapter/test_utils.h"
#include "common/platform/api/quiche_test.h"

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

// Tests connection-level events.
TEST(ClientCallbackVisitorUnitTest, ConnectionFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // SETTINGS
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, SETTINGS, _)));
  visitor.OnFrameHeader(0, 0, SETTINGS, 0);

  visitor.OnSettingsStart();
  EXPECT_CALL(callbacks, OnFrameRecv(IsSettings(testing::IsEmpty())));
  visitor.OnSettingsEnd();

  // PING
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, PING, _)));
  visitor.OnFrameHeader(0, 8, PING, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPing(42)));
  visitor.OnPing(42, false);

  // WINDOW_UPDATE
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, WINDOW_UPDATE, _)));
  visitor.OnFrameHeader(0, 4, WINDOW_UPDATE, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsWindowUpdate(1000)));
  visitor.OnWindowUpdate(0, 1000);

  // PING ack
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(0, PING, NGHTTP2_FLAG_ACK)));
  visitor.OnFrameHeader(0, 8, PING, 1);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPingAck(247)));
  visitor.OnPing(247, true);

  // GOAWAY
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, GOAWAY, 0)));
  visitor.OnFrameHeader(0, 19, GOAWAY, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsGoAway(5, NGHTTP2_ENHANCE_YOUR_CALM,
                                              "calm down!!")));
  visitor.OnGoAway(5, Http2ErrorCode::ENHANCE_YOUR_CALM, "calm down!!");
}

TEST(ClientCallbackVisitorUnitTest, StreamFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, _)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks,
              OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, ":status", "200", _));
  visitor.OnHeaderForStream(1, ":status", "200");

  EXPECT_CALL(callbacks, OnHeader(_, "server", "my-fake-server", _));
  visitor.OnHeaderForStream(1, "server", "my-fake-server");

  EXPECT_CALL(callbacks,
              OnHeader(_, "date", "Tue, 6 Apr 2021 12:54:01 GMT", _));
  visitor.OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT");

  EXPECT_CALL(callbacks, OnHeader(_, "trailer", "x-server-status", _));
  visitor.OnHeaderForStream(1, "trailer", "x-server-status");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnEndHeadersForStream(1);

  // DATA for stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, DATA, 0)));
  visitor.OnFrameHeader(1, 26, DATA, 0);

  visitor.OnBeginDataForStream(1, 26);
  EXPECT_CALL(callbacks, OnDataChunkRecv(0, 1, "This is the response body."));
  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, 0)));
  visitor.OnDataForStream(1, "This is the response body.");

  // Trailers for stream 1, with a different nghttp2 "category".
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, _)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_HEADERS)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, "x-server-status", "OK", _));
  visitor.OnHeaderForStream(1, "x-server-status", "OK");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_HEADERS)));
  visitor.OnEndHeadersForStream(1);

  // RST_STREAM on stream 3
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(3, RST_STREAM, 0)));
  visitor.OnFrameHeader(3, 4, RST_STREAM, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(3, NGHTTP2_INTERNAL_ERROR)));
  visitor.OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_CALL(callbacks, OnStreamClose(3, NGHTTP2_INTERNAL_ERROR));
  visitor.OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR);

  // More stream close events
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(1, DATA, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnFrameHeader(1, 0, DATA, 1);

  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnBeginDataForStream(1, 0);
  visitor.OnEndStream(1);

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(1, Http2ErrorCode::NO_ERROR);

  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(5, RST_STREAM, _)));
  visitor.OnFrameHeader(5, 4, RST_STREAM, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(5, NGHTTP2_REFUSED_STREAM)));
  visitor.OnRstStream(5, Http2ErrorCode::REFUSED_STREAM);

  EXPECT_CALL(callbacks, OnStreamClose(5, NGHTTP2_REFUSED_STREAM));
  visitor.OnCloseStream(5, Http2ErrorCode::REFUSED_STREAM);
}

TEST(ClientCallbackVisitorUnitTest, HeadersWithContinuation) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kClient,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, 0x0)));
  visitor.OnFrameHeader(1, 23, HEADERS, 0x0);

  EXPECT_CALL(callbacks,
              OnBeginHeaders(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, ":status", "200", _));
  visitor.OnHeaderForStream(1, ":status", "200");

  EXPECT_CALL(callbacks, OnHeader(_, "server", "my-fake-server", _));
  visitor.OnHeaderForStream(1, "server", "my-fake-server");

  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(1, CONTINUATION, 0x4)));
  visitor.OnFrameHeader(1, 23, CONTINUATION, 0x4);

  EXPECT_CALL(callbacks,
              OnHeader(_, "date", "Tue, 6 Apr 2021 12:54:01 GMT", _));
  visitor.OnHeaderForStream(1, "date", "Tue, 6 Apr 2021 12:54:01 GMT");

  EXPECT_CALL(callbacks, OnHeader(_, "trailer", "x-server-status", _));
  visitor.OnHeaderForStream(1, "trailer", "x-server-status");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, _, NGHTTP2_HCAT_RESPONSE)));
  visitor.OnEndHeadersForStream(1);
}

TEST(ServerCallbackVisitorUnitTest, ConnectionFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // SETTINGS
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, SETTINGS, _)));
  visitor.OnFrameHeader(0, 0, SETTINGS, 0);

  visitor.OnSettingsStart();
  EXPECT_CALL(callbacks, OnFrameRecv(IsSettings(testing::IsEmpty())));
  visitor.OnSettingsEnd();

  // PING
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, PING, _)));
  visitor.OnFrameHeader(0, 8, PING, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPing(42)));
  visitor.OnPing(42, false);

  // WINDOW_UPDATE
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(0, WINDOW_UPDATE, _)));
  visitor.OnFrameHeader(0, 4, WINDOW_UPDATE, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsWindowUpdate(1000)));
  visitor.OnWindowUpdate(0, 1000);

  // PING ack
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(0, PING, NGHTTP2_FLAG_ACK)));
  visitor.OnFrameHeader(0, 8, PING, 1);

  EXPECT_CALL(callbacks, OnFrameRecv(IsPingAck(247)));
  visitor.OnPing(247, true);
}

TEST(ServerCallbackVisitorUnitTest, StreamFrames) {
  testing::StrictMock<MockNghttp2Callbacks> callbacks;
  CallbackVisitor visitor(Perspective::kServer,
                          *MockNghttp2Callbacks::GetCallbacks(), &callbacks);

  testing::InSequence seq;

  // HEADERS on stream 1
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(
                             1, HEADERS, NGHTTP2_FLAG_END_HEADERS)));
  visitor.OnFrameHeader(1, 23, HEADERS, 4);

  EXPECT_CALL(callbacks, OnBeginHeaders(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                                  NGHTTP2_HCAT_REQUEST)));
  visitor.OnBeginHeadersForStream(1);

  EXPECT_CALL(callbacks, OnHeader(_, ":method", "POST", _));
  visitor.OnHeaderForStream(1, ":method", "POST");

  EXPECT_CALL(callbacks, OnHeader(_, ":path", "/example/path", _));
  visitor.OnHeaderForStream(1, ":path", "/example/path");

  EXPECT_CALL(callbacks, OnHeader(_, ":scheme", "https", _));
  visitor.OnHeaderForStream(1, ":scheme", "https");

  EXPECT_CALL(callbacks, OnHeader(_, ":authority", "example.com", _));
  visitor.OnHeaderForStream(1, ":authority", "example.com");

  EXPECT_CALL(callbacks, OnHeader(_, "accept", "text/html", _));
  visitor.OnHeaderForStream(1, "accept", "text/html");

  EXPECT_CALL(callbacks, OnFrameRecv(IsHeaders(1, NGHTTP2_FLAG_END_HEADERS,
                                               NGHTTP2_HCAT_REQUEST)));
  visitor.OnEndHeadersForStream(1);

  // DATA on stream 1
  EXPECT_CALL(callbacks,
              OnBeginFrame(HasFrameHeader(1, DATA, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnFrameHeader(1, 25, DATA, NGHTTP2_FLAG_END_STREAM);

  visitor.OnBeginDataForStream(1, 25);
  EXPECT_CALL(callbacks, OnDataChunkRecv(NGHTTP2_FLAG_END_STREAM, 1,
                                         "This is the request body."));
  EXPECT_CALL(callbacks, OnFrameRecv(IsData(1, _, NGHTTP2_FLAG_END_STREAM)));
  visitor.OnDataForStream(1, "This is the request body.");
  visitor.OnEndStream(1);

  EXPECT_CALL(callbacks, OnStreamClose(1, NGHTTP2_NO_ERROR));
  visitor.OnCloseStream(1, Http2ErrorCode::NO_ERROR);

  // RST_STREAM on stream 3
  EXPECT_CALL(callbacks, OnBeginFrame(HasFrameHeader(3, RST_STREAM, 0)));
  visitor.OnFrameHeader(3, 4, RST_STREAM, 0);

  EXPECT_CALL(callbacks, OnFrameRecv(IsRstStream(3, NGHTTP2_INTERNAL_ERROR)));
  visitor.OnRstStream(3, Http2ErrorCode::INTERNAL_ERROR);

  EXPECT_CALL(callbacks, OnStreamClose(3, NGHTTP2_INTERNAL_ERROR));
  visitor.OnCloseStream(3, Http2ErrorCode::INTERNAL_ERROR);
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
