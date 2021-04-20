#ifndef QUICHE_HTTP2_ADAPTER_TEST_UTILS_H_
#define QUICHE_HTTP2_ADAPTER_TEST_UTILS_H_

#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "common/platform/api/quiche_test.h"
#include "spdy/core/spdy_protocol.h"

namespace http2 {
namespace adapter {
namespace test {

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
