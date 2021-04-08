#ifndef QUICHE_HTTP2_ADAPTER_NGHTTP2_SESSION_H_
#define QUICHE_HTTP2_ADAPTER_NGHTTP2_SESSION_H_

#include "http2/adapter/http2_session.h"
#include "third_party/nghttp2/src/lib/includes/nghttp2/nghttp2.h"

namespace http2 {
namespace adapter {

// A C++ wrapper around common nghttp2_session operations.
class NgHttp2Session : public Http2Session {
 public:
  NgHttp2Session(Perspective perspective,
                 nghttp2_session_callbacks* callbacks,
                 nghttp2_option* options,
                 void* userdata);
  ~NgHttp2Session() override;

  ssize_t ProcessBytes(absl::string_view bytes) override;

  int Consume(Http2StreamId stream_id, size_t num_bytes) override;

  bool want_read() const override;
  bool want_write() const override;
  int GetRemoteWindowSize() const override;

  nghttp2_session* raw_ptr() const { return session_.get(); }

 private:
  using SessionDeleter = void (&)(nghttp2_session*);
  using OptionsDeleter = void (&)(nghttp2_option*);

  std::unique_ptr<nghttp2_session, SessionDeleter> session_;
  std::unique_ptr<nghttp2_option, OptionsDeleter> options_;
  Perspective perspective_;
};

}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_NGHTTP2_SESSION_H_
