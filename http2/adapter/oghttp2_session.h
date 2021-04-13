#ifndef QUICHE_HTTP2_ADAPTER_OGHTTP2_SESSION_H_
#define QUICHE_HTTP2_ADAPTER_OGHTTP2_SESSION_H_

#include <list>

#include "http2/adapter/http2_session.h"
#include "http2/adapter/http2_visitor_interface.h"
#include "http2/adapter/window_manager.h"
#include "common/platform/api/quiche_bug_tracker.h"
#include "spdy/core/spdy_framer.h"

namespace http2 {
namespace adapter {

// This class manages state associated with a single multiplexed HTTP/2 session.
class OgHttp2Session : public Http2Session {
 public:
  struct Options {
    Perspective context;
  };

  OgHttp2Session(Http2VisitorInterface& /*visitor*/, Options /*options*/) {}
  ~OgHttp2Session() override {}

  // Enqueues a frame for transmission to the peer.
  void EnqueueFrame(std::unique_ptr<spdy::SpdyFrameIR> frame);

  // If |want_write()| returns true, this method will return a non-empty string
  // containing serialized HTTP/2 frames to write to the peer.
  std::string GetBytesToWrite(absl::optional<size_t> max_bytes);

  // From Http2Session.
  ssize_t ProcessBytes(absl::string_view bytes) override;
  int Consume(Http2StreamId stream_id, size_t num_bytes) override;
  bool want_read() const override { return false; }
  bool want_write() const override {
    return !frames_.empty() || !serialized_prefix_.empty();
  }
  int GetRemoteWindowSize() const override {
    QUICHE_BUG(peer_window_not_updated) << "Not implemented";
    return peer_window_;
  }

 private:
  struct StreamState {
    WindowManager window_manager;
    bool half_closed_local = false;
    bool half_closed_remote = false;
  };

  spdy::SpdyFramer framer_{spdy::SpdyFramer::ENABLE_COMPRESSION};
  absl::flat_hash_map<Http2StreamId, StreamState> stream_map_;
  std::list<std::unique_ptr<spdy::SpdyFrameIR>> frames_;
  std::string serialized_prefix_;
  int peer_window_ = 65535;
};

}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_OGHTTP2_SESSION_H_
