#include "http2/adapter/oghttp2_session.h"

namespace http2 {
namespace adapter {

ssize_t OgHttp2Session::ProcessBytes(absl::string_view bytes) {
  QUICHE_BUG(oghttp2_process_bytes) << "Not implemented";
  return 0;
}

int OgHttp2Session::Consume(Http2StreamId stream_id, size_t num_bytes) {
  auto it = stream_map_.find(stream_id);
  if (it == stream_map_.end()) {
    // TODO(b/181586191): LOG_ERROR rather than QUICHE_BUG.
    QUICHE_BUG(stream_consume_notfound)
        << "Stream " << stream_id << " not found";
  } else {
    it->second.window_manager.MarkDataFlushed(num_bytes);
  }
  return 0;  // Remove?
}

void OgHttp2Session::EnqueueFrame(std::unique_ptr<spdy::SpdyFrameIR> frame) {
  frames_.push_back(std::move(frame));
}

std::string OgHttp2Session::GetBytesToWrite(absl::optional<size_t> max_bytes) {
  const size_t serialized_max =
      max_bytes ? max_bytes.value() : std::numeric_limits<size_t>::max();
  std::string serialized = std::move(serialized_prefix_);
  while (serialized.size() < serialized_max && !frames_.empty()) {
    spdy::SpdySerializedFrame frame = framer_.SerializeFrame(*frames_.front());
    absl::StrAppend(&serialized, absl::string_view(frame));
    frames_.pop_front();
  }
  if (serialized.size() > serialized_max) {
    serialized_prefix_ = serialized.substr(serialized_max);
    serialized.resize(serialized_max);
  }
  return serialized;
}

}  // namespace adapter
}  // namespace http2
