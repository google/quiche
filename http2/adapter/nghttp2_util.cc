#include "http2/adapter/nghttp2_util.h"

#include <cstdint>

#include "absl/strings/string_view.h"
#include "http2/adapter/http2_protocol.h"
#include "third_party/nghttp2/src/lib/includes/nghttp2/nghttp2.h"
#include "common/platform/api/quiche_logging.h"

namespace http2 {
namespace adapter {

namespace {

void DeleteCallbacks(nghttp2_session_callbacks* callbacks) {
  if (callbacks) {
    nghttp2_session_callbacks_del(callbacks);
  }
}

void DeleteSession(nghttp2_session* session) {
  if (session) {
    nghttp2_session_del(session);
  }
}

}  // namespace

nghttp2_session_callbacks_unique_ptr MakeCallbacksPtr(
    nghttp2_session_callbacks* callbacks) {
  return nghttp2_session_callbacks_unique_ptr(callbacks, DeleteCallbacks);
}

nghttp2_session_unique_ptr MakeSessionPtr(nghttp2_session* session) {
  return nghttp2_session_unique_ptr(session, DeleteSession);
}

uint8_t* ToUint8Ptr(char* str) { return reinterpret_cast<uint8_t*>(str); }
uint8_t* ToUint8Ptr(const char* str) {
  return const_cast<uint8_t*>(reinterpret_cast<const uint8_t*>(str));
}

absl::string_view ToStringView(nghttp2_rcbuf* rc_buffer) {
  nghttp2_vec buffer = nghttp2_rcbuf_get_buf(rc_buffer);
  return absl::string_view(reinterpret_cast<const char*>(buffer.base),
                           buffer.len);
}

absl::string_view ToStringView(uint8_t* pointer, size_t length) {
  return absl::string_view(reinterpret_cast<const char*>(pointer), length);
}

absl::string_view ToStringView(const uint8_t* pointer, size_t length) {
  return absl::string_view(reinterpret_cast<const char*>(pointer), length);
}

std::vector<nghttp2_nv> GetNghttp2Nvs(absl::Span<const Header> headers) {
  const int num_headers = headers.size();
  auto nghttp2_nvs = std::vector<nghttp2_nv>(num_headers);
  for (int i = 0; i < num_headers; ++i) {
    nghttp2_nv header;
    uint8_t flags = NGHTTP2_NV_FLAG_NONE;

    const auto [name, no_copy_name] = GetStringView(headers[i].first);
    header.name = ToUint8Ptr(name.data());
    header.namelen = name.size();
    if (no_copy_name) {
      flags |= NGHTTP2_NV_FLAG_NO_COPY_NAME;
    }
    const auto [value, no_copy_value] = GetStringView(headers[i].second);
    header.value = ToUint8Ptr(value.data());
    header.valuelen = value.size();
    if (no_copy_value) {
      flags |= NGHTTP2_NV_FLAG_NO_COPY_VALUE;
    }
    header.flags = flags;
    nghttp2_nvs.push_back(std::move(header));
  }

  return nghttp2_nvs;
}

std::vector<nghttp2_nv> GetResponseNghttp2Nvs(
    const spdy::Http2HeaderBlock& headers,
    absl::string_view response_code) {
  // Allocate enough for all headers and also the :status pseudoheader.
  const int num_headers = headers.size();
  auto nghttp2_nvs = std::vector<nghttp2_nv>(num_headers + 1);

  // Add the :status pseudoheader first.
  nghttp2_nv status;
  status.name = ToUint8Ptr(kHttp2StatusPseudoHeader);
  status.namelen = strlen(kHttp2StatusPseudoHeader);
  status.value = ToUint8Ptr(response_code.data());
  status.valuelen = response_code.size();
  status.flags = NGHTTP2_FLAG_NONE;
  nghttp2_nvs.push_back(std::move(status));

  // Add the remaining headers.
  for (const auto header_pair : headers) {
    nghttp2_nv header;
    header.name = ToUint8Ptr(header_pair.first.data());
    header.namelen = header_pair.first.size();
    header.value = ToUint8Ptr(header_pair.second.data());
    header.valuelen = header_pair.second.size();
    header.flags = NGHTTP2_FLAG_NONE;
    nghttp2_nvs.push_back(std::move(header));
  }

  return nghttp2_nvs;
}

Http2ErrorCode ToHttp2ErrorCode(uint32_t wire_error_code) {
  if (wire_error_code > static_cast<int>(Http2ErrorCode::MAX_ERROR_CODE)) {
    return Http2ErrorCode::INTERNAL_ERROR;
  }
  return static_cast<Http2ErrorCode>(wire_error_code);
}

class Nghttp2DataFrameSource : public DataFrameSource {
 public:
  Nghttp2DataFrameSource(nghttp2_data_provider provider,
                         nghttp2_send_data_callback send_data,
                         void* user_data)
      : provider_(std::move(provider)),
        send_data_(std::move(send_data)),
        user_data_(user_data) {}

  std::pair<ssize_t, bool> SelectPayloadLength(size_t max_length) override {
    const int32_t stream_id = 0;
    uint32_t data_flags = 0;
    QUICHE_LOG(INFO) << "Invoking read callback";
    ssize_t result = provider_.read_callback(
        nullptr /* session */, stream_id, nullptr /* buf */, max_length,
        &data_flags, &provider_.source, nullptr /* user_data */);
    if (result == NGHTTP2_ERR_DEFERRED) {
      return {kBlocked, false};
    } else if (result < 0) {
      return {kError, false};
    } else if ((data_flags & NGHTTP2_DATA_FLAG_NO_COPY) == 0) {
      QUICHE_LOG(ERROR) << "Source did not use the zero-copy API!";
      return {kError, false};
    } else {
      if (data_flags & NGHTTP2_DATA_FLAG_NO_END_STREAM) {
        send_fin_ = false;
      }
      const bool eof = data_flags & NGHTTP2_DATA_FLAG_EOF;
      return {result, eof};
    }
  }

  bool Send(absl::string_view frame_header, size_t payload_length) override {
    const int result =
        send_data_(nullptr /* session */, nullptr /* frame */,
                   ToUint8Ptr(frame_header.data()), payload_length,
                   &provider_.source, user_data_);
    QUICHE_LOG_IF(ERROR, result < 0 && result != NGHTTP2_ERR_WOULDBLOCK)
        << "Unexpected error code from send: " << result;
    return result == 0;
  }

  bool send_fin() const override { return send_fin_; }

 private:
  nghttp2_data_provider provider_;
  nghttp2_send_data_callback send_data_;
  void* user_data_;
  bool send_fin_ = true;
};

std::unique_ptr<DataFrameSource> MakeZeroCopyDataFrameSource(
    nghttp2_data_provider provider,
    void* user_data,
    nghttp2_send_data_callback send_data) {
  return absl::make_unique<Nghttp2DataFrameSource>(
      std::move(provider), std::move(send_data), user_data);
}

}  // namespace adapter
}  // namespace http2
