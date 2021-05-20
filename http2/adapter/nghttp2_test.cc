#include "third_party/nghttp2/src/lib/includes/nghttp2/nghttp2.h"
#include "http2/adapter/mock_nghttp2_callbacks.h"
#include "http2/adapter/test_frame_sequence.h"
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
};

nghttp2_option* GetOptions() {
  nghttp2_option* options;
  nghttp2_option_new(&options);
  // Set some common options for compatibility.
  nghttp2_option_set_no_closed_streams(options, 1);
  nghttp2_option_set_no_auto_window_update(options, 1);
  nghttp2_option_set_max_send_header_block_length(options, 0x2000000);
  nghttp2_option_set_max_outbound_ack(options, 10000);
  return options;
}

// Verifies nghttp2 behavior when acting as a client.
TEST(Nghttp2ClientTest, ClientReceivesUnexpectedHeaders) {
  testing::StrictMock<MockNghttp2Callbacks> mock_callbacks;
  auto nghttp2_callbacks = MockNghttp2Callbacks::GetCallbacks();
  nghttp2_option* options = GetOptions();
  nghttp2_session* ptr;
  nghttp2_session_client_new2(&ptr, nghttp2_callbacks.get(), &mock_callbacks,
                              options);

  auto client_session = MakeSessionPtr(ptr);

  const std::string initial_frames = TestFrameSequence()
                                         .ServerPreface()
                                         .Ping(42)
                                         .WindowUpdate(0, 1000)
                                         .Serialize();

  testing::InSequence seq;
  EXPECT_CALL(mock_callbacks, OnBeginFrame(HasFrameHeader(0, SETTINGS, 0)));
  EXPECT_CALL(mock_callbacks, OnFrameRecv(IsSettings(testing::IsEmpty())));
  EXPECT_CALL(mock_callbacks, OnBeginFrame(HasFrameHeader(0, PING, 0)));
  EXPECT_CALL(mock_callbacks, OnFrameRecv(IsPing(42)));
  EXPECT_CALL(mock_callbacks,
              OnBeginFrame(HasFrameHeader(0, WINDOW_UPDATE, 0)));
  EXPECT_CALL(mock_callbacks, OnFrameRecv(IsWindowUpdate(1000)));

  nghttp2_session_mem_recv(client_session.get(),
                           ToUint8Ptr(initial_frames.data()),
                           initial_frames.size());

  const std::string unexpected_stream_frames =
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

  EXPECT_CALL(mock_callbacks, OnBeginFrame(HasFrameHeader(1, HEADERS, _)));
  EXPECT_CALL(mock_callbacks, OnInvalidFrameRecv(IsHeaders(1, _, _), _));
  // No events from the DATA, RST_STREAM or GOAWAY.

  nghttp2_session_mem_recv(client_session.get(),
                           ToUint8Ptr(unexpected_stream_frames.data()),
                           unexpected_stream_frames.size());

  nghttp2_option_del(options);
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
