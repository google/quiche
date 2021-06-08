#ifndef QUICHE_HTTP2_ADAPTER_NGHTTP2_ADAPTER_H_
#define QUICHE_HTTP2_ADAPTER_NGHTTP2_ADAPTER_H_

#include "http2/adapter/http2_adapter.h"
#include "http2/adapter/http2_protocol.h"
#include "http2/adapter/nghttp2_session.h"
#include "http2/adapter/nghttp2_util.h"

namespace http2 {
namespace adapter {

class NgHttp2Adapter : public Http2Adapter {
 public:
  ~NgHttp2Adapter() override;

  // Creates an adapter that functions as a client.
  static std::unique_ptr<NgHttp2Adapter> CreateClientAdapter(
      Http2VisitorInterface& visitor);

  // Creates an adapter that functions as a server.
  static std::unique_ptr<NgHttp2Adapter> CreateServerAdapter(
      Http2VisitorInterface& visitor);

  bool IsServerSession() const override;

  ssize_t ProcessBytes(absl::string_view bytes) override;
  void SubmitSettings(absl::Span<const Http2Setting> settings) override;
  void SubmitPriorityForStream(Http2StreamId stream_id,
                               Http2StreamId parent_stream_id,
                               int weight,
                               bool exclusive) override;

  // Submits a PING on the connection. Note that nghttp2 automatically submits
  // PING acks upon receiving non-ack PINGs from the peer, so callers only use
  // this method to originate PINGs. See nghttp2_option_set_no_auto_ping_ack().
  void SubmitPing(Http2PingId ping_id) override;

  void SubmitShutdownNotice() override;
  void SubmitGoAway(Http2StreamId last_accepted_stream_id,
                    Http2ErrorCode error_code,
                    absl::string_view opaque_data) override;

  void SubmitWindowUpdate(Http2StreamId stream_id,
                          int window_increment) override;

  void SubmitRst(Http2StreamId stream_id, Http2ErrorCode error_code) override;

  void SubmitMetadata(Http2StreamId stream_id, bool end_metadata) override;

  void Send() override;

  int GetPeerConnectionWindow() const override;

  Http2StreamId GetHighestReceivedStreamId() const override;

  void MarkDataConsumedForStream(Http2StreamId stream_id,
                                 size_t num_bytes) override;

  int32_t SubmitRequest(absl::Span<const Header> headers,
                        DataFrameSource* data_source,
                        void* user_data) override;

  int32_t SubmitResponse(Http2StreamId stream_id,
                         absl::Span<const Header> headers,
                         DataFrameSource* data_source) override;

  int SubmitTrailer(Http2StreamId stream_id,
                    absl::Span<const Header> trailers) override;

  void SetStreamUserData(Http2StreamId stream_id, void* user_data) override;
  void* GetStreamUserData(Http2StreamId stream_id) override;

  // TODO(b/181586191): Temporary accessor until equivalent functionality is
  // available in this adapter class.
  NgHttp2Session& session() { return *session_; }

 private:
  NgHttp2Adapter(Http2VisitorInterface& visitor, Perspective perspective);

  // Performs any necessary initialization of the underlying HTTP/2 session,
  // such as preparing initial SETTINGS.
  void Initialize();

  std::unique_ptr<NgHttp2Session> session_;
  Http2VisitorInterface& visitor_;
  Perspective perspective_;
};

}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_NGHTTP2_ADAPTER_H_
