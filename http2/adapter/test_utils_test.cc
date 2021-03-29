#include "http2/adapter/test_utils.h"

#include "common/platform/api/quiche_test.h"
#include "spdy/core/spdy_framer.h"

namespace http2 {
namespace adapter {
namespace test {
namespace {

using spdy::SpdyFramer;

TEST(ContainsFrames, Empty) {
  EXPECT_THAT("", ContainsFrames(std::vector<spdy::SpdyFrameType>{}));
}

TEST(ContainsFrames, SingleFrameWithLength) {
  SpdyFramer framer{SpdyFramer::ENABLE_COMPRESSION};

  spdy::SpdyPingIR ping{511};
  EXPECT_THAT(framer.SerializeFrame(ping),
              ContainsFrames({{spdy::SpdyFrameType::PING, 8}}));

  spdy::SpdyWindowUpdateIR window_update{1, 101};
  EXPECT_THAT(framer.SerializeFrame(window_update),
              ContainsFrames({{spdy::SpdyFrameType::WINDOW_UPDATE, 4}}));

  spdy::SpdyDataIR data{3, "Some example data, ha ha!"};
  EXPECT_THAT(framer.SerializeFrame(data),
              ContainsFrames({{spdy::SpdyFrameType::DATA, 25}}));
}

TEST(ContainsFrames, SingleFrameWithoutLength) {
  SpdyFramer framer{SpdyFramer::ENABLE_COMPRESSION};

  spdy::SpdyRstStreamIR rst_stream{7, spdy::ERROR_CODE_REFUSED_STREAM};
  EXPECT_THAT(
      framer.SerializeFrame(rst_stream),
      ContainsFrames({{spdy::SpdyFrameType::RST_STREAM, absl::nullopt}}));

  spdy::SpdyGoAwayIR goaway{13, spdy::ERROR_CODE_ENHANCE_YOUR_CALM,
                            "Consider taking some deep breaths."};
  EXPECT_THAT(framer.SerializeFrame(goaway),
              ContainsFrames({{spdy::SpdyFrameType::GOAWAY, absl::nullopt}}));

  spdy::Http2HeaderBlock block;
  block[":method"] = "GET";
  block[":path"] = "/example";
  block[":authority"] = "example.com";
  spdy::SpdyHeadersIR headers{17, std::move(block)};
  EXPECT_THAT(framer.SerializeFrame(headers),
              ContainsFrames({{spdy::SpdyFrameType::HEADERS, absl::nullopt}}));
}

TEST(ContainsFrames, MultipleFrames) {
  SpdyFramer framer{SpdyFramer::ENABLE_COMPRESSION};

  spdy::SpdyPingIR ping{511};
  spdy::SpdyWindowUpdateIR window_update{1, 101};
  spdy::SpdyDataIR data{3, "Some example data, ha ha!"};
  spdy::SpdyRstStreamIR rst_stream{7, spdy::ERROR_CODE_REFUSED_STREAM};
  spdy::SpdyGoAwayIR goaway{13, spdy::ERROR_CODE_ENHANCE_YOUR_CALM,
                            "Consider taking some deep breaths."};
  spdy::Http2HeaderBlock block;
  block[":method"] = "GET";
  block[":path"] = "/example";
  block[":authority"] = "example.com";
  spdy::SpdyHeadersIR headers{17, std::move(block)};

  const std::string frame_sequence =
      absl::StrCat(absl::string_view(framer.SerializeFrame(ping)),
                   absl::string_view(framer.SerializeFrame(window_update)),
                   absl::string_view(framer.SerializeFrame(data)),
                   absl::string_view(framer.SerializeFrame(rst_stream)),
                   absl::string_view(framer.SerializeFrame(goaway)),
                   absl::string_view(framer.SerializeFrame(headers)));
  EXPECT_THAT(
      frame_sequence,
      ContainsFrames({{spdy::SpdyFrameType::PING, absl::nullopt},
                      {spdy::SpdyFrameType::WINDOW_UPDATE, absl::nullopt},
                      {spdy::SpdyFrameType::DATA, 25},
                      {spdy::SpdyFrameType::RST_STREAM, absl::nullopt},
                      {spdy::SpdyFrameType::GOAWAY, 42},
                      {spdy::SpdyFrameType::HEADERS, 19}}));
  EXPECT_THAT(
      frame_sequence,
      ContainsFrames(
          {spdy::SpdyFrameType::PING, spdy::SpdyFrameType::WINDOW_UPDATE,
           spdy::SpdyFrameType::DATA, spdy::SpdyFrameType::RST_STREAM,
           spdy::SpdyFrameType::GOAWAY, spdy::SpdyFrameType::HEADERS}));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
