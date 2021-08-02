#ifndef QUICHE_HTTP2_ADAPTER_TEST_UTILS_H_
#define QUICHE_HTTP2_ADAPTER_TEST_UTILS_H_

#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "http2/adapter/data_source.h"
#include "http2/adapter/http2_protocol.h"
#include "http2/adapter/mock_http2_visitor.h"
#include "common/platform/api/quiche_export.h"
#include "common/platform/api/quiche_test.h"
#include "spdy/core/spdy_header_block.h"
#include "spdy/core/spdy_protocol.h"

namespace http2 {
namespace adapter {
namespace test {

class QUICHE_NO_EXPORT DataSavingVisitor
    : public testing::StrictMock<MockHttp2Visitor> {
 public:
  ssize_t OnReadyToSend(absl::string_view data) override {
    if (is_write_blocked_) {
      return kSendBlocked;
    }
    const size_t to_accept = std::min(send_limit_, data.size());
    if (to_accept == 0) {
      return kSendBlocked;
    }
    absl::StrAppend(&data_, data.substr(0, to_accept));
    return to_accept;
  }

  const std::string& data() { return data_; }
  void Clear() { data_.clear(); }

  void set_send_limit(size_t limit) { send_limit_ = limit; }

  bool is_write_blocked() const { return is_write_blocked_; }
  void set_is_write_blocked(bool value) { is_write_blocked_ = value; }

 private:
  std::string data_;
  size_t send_limit_ = std::numeric_limits<size_t>::max();
  bool is_write_blocked_ = false;
};

// A test DataFrameSource that can be initialized with a single string payload,
// or a chunked payload.
class QUICHE_NO_EXPORT TestDataFrameSource : public DataFrameSource {
 public:
  TestDataFrameSource(Http2VisitorInterface& visitor,
                      absl::string_view data_payload,
                      bool has_fin = true);

  TestDataFrameSource(Http2VisitorInterface& visitor,
                      absl::Span<absl::string_view> payload_fragments,
                      bool has_fin = true);

  std::pair<ssize_t, bool> SelectPayloadLength(size_t max_length) override;
  bool Send(absl::string_view frame_header, size_t payload_length) override;
  bool send_fin() const override { return has_fin_; }

  void set_is_data_available(bool value) { is_data_available_ = value; }

 private:
  Http2VisitorInterface& visitor_;
  std::vector<std::string> payload_fragments_;
  absl::string_view current_fragment_;
  const bool has_fin_;
  bool is_data_available_ = true;
};

class QUICHE_NO_EXPORT TestMetadataSource : public MetadataSource {
 public:
  explicit TestMetadataSource(const spdy::SpdyHeaderBlock& entries);

  std::pair<ssize_t, bool> Pack(uint8_t* dest, size_t dest_len) override;

 private:
  const std::string encoded_entries_;
  absl::string_view remaining_;
};

// These matchers check whether a string consists entirely of HTTP/2 frames of
// the specified ordered sequence. This is useful in tests where we want to show
// that one or more particular frame types are serialized for sending to the
// peer. The match will fail if there are input bytes not consumed by the
// matcher.

// Requires that frames match both types and lengths.
testing::Matcher<absl::string_view> EqualsFrames(
    std::vector<std::pair<spdy::SpdyFrameType, absl::optional<size_t>>>
        types_and_lengths);

// Requires that frames match the specified types.
testing::Matcher<absl::string_view> EqualsFrames(
    std::vector<spdy::SpdyFrameType> types);

}  // namespace test
}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_TEST_UTILS_H_
