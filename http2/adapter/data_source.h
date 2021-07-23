#ifndef QUICHE_HTTP2_ADAPTER_DATA_SOURCE_H_
#define QUICHE_HTTP2_ADAPTER_DATA_SOURCE_H_

#include <string>
#include <utility>

#include "absl/strings/string_view.h"

namespace http2 {
namespace adapter {

// Represents a source of DATA frames for transmission to the peer.
class DataFrameSource {
 public:
  virtual ~DataFrameSource() {}

  static constexpr ssize_t kBlocked = 0;
  static constexpr ssize_t kError = -1;

  // Returns the number of bytes to send in the next DATA frame, and whether
  // this frame indicates the end of the data. Returns {kBlocked, false} if
  // blocked, {kError, false} on error.
  virtual std::pair<ssize_t, bool> SelectPayloadLength(size_t max_length) = 0;

  // This method is called with a frame header and a payload length to send. The
  // source should send or buffer the entire frame and return true, or return
  // false without sending or buffering anything.
  virtual bool Send(absl::string_view frame_header, size_t payload_length) = 0;

  // If true, the end of this data source indicates the end of the stream.
  // Otherwise, this data will be followed by trailers.
  virtual bool send_fin() const = 0;
};

}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_DATA_SOURCE_H_
