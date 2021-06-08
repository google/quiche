#include "http2/adapter/nghttp2_adapter.h"

#include "absl/algorithm/container.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "http2/adapter/nghttp2_callbacks.h"
#include "http2/adapter/nghttp2_data_provider.h"
#include "third_party/nghttp2/src/lib/includes/nghttp2/nghttp2.h"
#include "common/platform/api/quiche_logging.h"
#include "common/quiche_endian.h"

namespace http2 {
namespace adapter {

/* static */
std::unique_ptr<NgHttp2Adapter> NgHttp2Adapter::CreateClientAdapter(
    Http2VisitorInterface& visitor) {
  auto adapter = new NgHttp2Adapter(visitor, Perspective::kClient);
  adapter->Initialize();
  return absl::WrapUnique(adapter);
}

/* static */
std::unique_ptr<NgHttp2Adapter> NgHttp2Adapter::CreateServerAdapter(
    Http2VisitorInterface& visitor) {
  auto adapter = new NgHttp2Adapter(visitor, Perspective::kServer);
  adapter->Initialize();
  return absl::WrapUnique(adapter);
}

bool NgHttp2Adapter::IsServerSession() const {
  int result = nghttp2_session_check_server_session(session_->raw_ptr());
  QUICHE_DCHECK_EQ(perspective_ == Perspective::kServer, result > 0);
  return result > 0;
}

ssize_t NgHttp2Adapter::ProcessBytes(absl::string_view bytes) {
  const ssize_t processed_bytes = session_->ProcessBytes(bytes);
  if (processed_bytes < 0) {
    visitor_.OnConnectionError();
  }
  return processed_bytes;
}

void NgHttp2Adapter::SubmitSettings(absl::Span<const Http2Setting> settings) {
  // Submit SETTINGS, converting each Http2Setting to an nghttp2_settings_entry.
  std::vector<nghttp2_settings_entry> nghttp2_settings;
  absl::c_transform(settings, std::back_inserter(nghttp2_settings),
                    [](const Http2Setting& setting) {
                      return nghttp2_settings_entry{setting.id, setting.value};
                    });
  nghttp2_submit_settings(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                          nghttp2_settings.data(), nghttp2_settings.size());
}

void NgHttp2Adapter::SubmitPriorityForStream(Http2StreamId stream_id,
                                             Http2StreamId parent_stream_id,
                                             int weight,
                                             bool exclusive) {
  nghttp2_priority_spec priority_spec;
  nghttp2_priority_spec_init(&priority_spec, parent_stream_id, weight,
                             static_cast<int>(exclusive));
  nghttp2_submit_priority(session_->raw_ptr(), NGHTTP2_FLAG_NONE, stream_id,
                          &priority_spec);
}

void NgHttp2Adapter::SubmitPing(Http2PingId ping_id) {
  uint8_t opaque_data[8] = {};
  Http2PingId ping_id_to_serialize = quiche::QuicheEndian::HostToNet64(ping_id);
  std::memcpy(opaque_data, &ping_id_to_serialize, sizeof(Http2PingId));
  nghttp2_submit_ping(session_->raw_ptr(), NGHTTP2_FLAG_NONE, opaque_data);
}

void NgHttp2Adapter::SubmitShutdownNotice() {
  nghttp2_submit_shutdown_notice(session_->raw_ptr());
}

void NgHttp2Adapter::SubmitGoAway(Http2StreamId last_accepted_stream_id,
                                  Http2ErrorCode error_code,
                                  absl::string_view opaque_data) {
  nghttp2_submit_goaway(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                        last_accepted_stream_id,
                        static_cast<uint32_t>(error_code),
                        ToUint8Ptr(opaque_data.data()), opaque_data.size());
}

void NgHttp2Adapter::SubmitWindowUpdate(Http2StreamId stream_id,
                                        int window_increment) {
  nghttp2_submit_window_update(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                               stream_id, window_increment);
}

void NgHttp2Adapter::SubmitMetadata(Http2StreamId stream_id,
                                    bool end_metadata) {
  QUICHE_LOG(DFATAL) << "Not implemented";
}

void NgHttp2Adapter::Send() {
  const int result = nghttp2_session_send(session_->raw_ptr());
  if (result != 0) {
    visitor_.OnConnectionError();
  }
}

int NgHttp2Adapter::GetPeerConnectionWindow() const {
  return session_->GetRemoteWindowSize();
}

Http2StreamId NgHttp2Adapter::GetHighestReceivedStreamId() const {
  return nghttp2_session_get_last_proc_stream_id(session_->raw_ptr());
}

void NgHttp2Adapter::MarkDataConsumedForStream(Http2StreamId stream_id,
                                               size_t num_bytes) {
  int rc = session_->Consume(stream_id, num_bytes);
  if (rc != 0) {
    QUICHE_LOG(ERROR) << "Error " << rc << " marking " << num_bytes
                      << " bytes consumed for stream " << stream_id;
  }
}

void NgHttp2Adapter::SubmitRst(Http2StreamId stream_id,
                               Http2ErrorCode error_code) {
  int status =
      nghttp2_submit_rst_stream(session_->raw_ptr(), NGHTTP2_FLAG_NONE,
                                stream_id, static_cast<uint32_t>(error_code));
  if (status < 0) {
    QUICHE_LOG(WARNING) << "Reset stream failed: " << stream_id
                        << " with status code " << status;
  }
}

int32_t NgHttp2Adapter::SubmitRequest(absl::Span<const Header> headers,
                                      DataFrameSource* data_source,
                                      void* user_data) {
  auto nvs = GetNghttp2Nvs(headers);
  std::unique_ptr<nghttp2_data_provider> provider =
      MakeDataProvider(data_source);
  return nghttp2_submit_request(session_->raw_ptr(), nullptr, nvs.data(),
                                nvs.size(), provider.get(), user_data);
}

int32_t NgHttp2Adapter::SubmitResponse(Http2StreamId stream_id,
                                       absl::Span<const Header> headers,
                                       DataFrameSource* data_source) {
  auto nvs = GetNghttp2Nvs(headers);
  std::unique_ptr<nghttp2_data_provider> provider =
      MakeDataProvider(data_source);
  return nghttp2_submit_response(session_->raw_ptr(), stream_id, nvs.data(),
                                 nvs.size(), provider.get());
}

int NgHttp2Adapter::SubmitTrailer(Http2StreamId stream_id,
                                  absl::Span<const Header> trailers) {
  auto nvs = GetNghttp2Nvs(trailers);
  return nghttp2_submit_trailer(session_->raw_ptr(), stream_id, nvs.data(),
                                nvs.size());
}

NgHttp2Adapter::NgHttp2Adapter(Http2VisitorInterface& visitor,
                               Perspective perspective)
    : Http2Adapter(visitor), visitor_(visitor), perspective_(perspective) {}

NgHttp2Adapter::~NgHttp2Adapter() {}

void NgHttp2Adapter::Initialize() {
  nghttp2_option* options;
  nghttp2_option_new(&options);
  // Set some common options for compatibility.
  nghttp2_option_set_no_closed_streams(options, 1);
  nghttp2_option_set_no_auto_window_update(options, 1);
  nghttp2_option_set_max_send_header_block_length(options, 0x2000000);
  nghttp2_option_set_max_outbound_ack(options, 10000);

  session_ =
      absl::make_unique<NgHttp2Session>(perspective_, callbacks::Create(),
                                        options, static_cast<void*>(&visitor_));
}

}  // namespace adapter
}  // namespace http2
