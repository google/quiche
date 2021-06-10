#include "http2/adapter/oghttp2_session.h"

#include "absl/strings/escaping.h"
#include "http2/adapter/oghttp2_util.h"

namespace http2 {
namespace adapter {

void OgHttp2Session::PassthroughHeadersHandler::OnHeaderBlockStart() {
  visitor_.OnBeginHeadersForStream(stream_id_);
}

void OgHttp2Session::PassthroughHeadersHandler::OnHeader(
    absl::string_view key,
    absl::string_view value) {
  visitor_.OnHeaderForStream(stream_id_, key, value);
}

void OgHttp2Session::PassthroughHeadersHandler::OnHeaderBlockEnd(
    size_t /* uncompressed_header_bytes */,
    size_t /* compressed_header_bytes */) {
  visitor_.OnEndHeadersForStream(stream_id_);
}

OgHttp2Session::OgHttp2Session(Http2VisitorInterface& visitor, Options options)
    : visitor_(visitor), headers_handler_(visitor), options_(options) {
  decoder_.set_visitor(this);
  if (options_.perspective == Perspective::kServer) {
    remaining_preface_ = {spdy::kHttp2ConnectionHeaderPrefix,
                          spdy::kHttp2ConnectionHeaderPrefixSize};
  }
}

OgHttp2Session::~OgHttp2Session() {}

void OgHttp2Session::SetStreamUserData(Http2StreamId stream_id,
                                       void* user_data) {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    it->second.user_data = user_data;
  }
}

void* OgHttp2Session::GetStreamUserData(Http2StreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it != stream_map_.end()) {
    return it->second.user_data;
  }
  return nullptr;
}

bool OgHttp2Session::ResumeStream(Http2StreamId stream_id) {
  if (auto it = stream_map_.find(stream_id);
      it->second.outbound_body == nullptr ||
      !write_scheduler_.StreamRegistered(stream_id)) {
    return false;
  }
  write_scheduler_.MarkStreamReady(stream_id, /*add_to_front=*/false);
  return true;
}

ssize_t OgHttp2Session::ProcessBytes(absl::string_view bytes) {
  ssize_t preface_consumed = 0;
  if (!remaining_preface_.empty()) {
    QUICHE_VLOG(2) << "Preface bytes remaining: " << remaining_preface_.size();
    // decoder_ does not understand the client connection preface.
    size_t min_size = std::min(remaining_preface_.size(), bytes.size());
    if (!absl::StartsWith(remaining_preface_, bytes.substr(0, min_size))) {
      // Preface doesn't match!
      QUICHE_DLOG(INFO) << "Preface doesn't match! Expected: ["
                        << absl::CEscape(remaining_preface_) << "], actual: ["
                        << absl::CEscape(bytes) << "]";
      visitor_.OnConnectionError();
      return -1;
    }
    remaining_preface_.remove_prefix(min_size);
    bytes.remove_prefix(min_size);
    if (!remaining_preface_.empty()) {
      QUICHE_VLOG(2) << "Preface bytes remaining: "
                     << remaining_preface_.size();
      return min_size;
    }
    preface_consumed = min_size;
  }
  ssize_t result = decoder_.ProcessInput(bytes.data(), bytes.size());
  return result < 0 ? result : result + preface_consumed;
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

void OgHttp2Session::StartGracefulShutdown() {
  if (options_.perspective == Perspective::kServer) {
    if (!queued_goaway_) {
      EnqueueFrame(absl::make_unique<spdy::SpdyGoAwayIR>(
          std::numeric_limits<int32_t>::max(), spdy::ERROR_CODE_NO_ERROR,
          "graceful_shutdown"));
    }
  } else {
    QUICHE_LOG(ERROR) << "Graceful shutdown not needed for clients.";
  }
}

void OgHttp2Session::EnqueueFrame(std::unique_ptr<spdy::SpdyFrameIR> frame) {
  if (frame->frame_type() == spdy::SpdyFrameType::GOAWAY) {
    queued_goaway_ = true;
  }
  frames_.push_back(std::move(frame));
}

void OgHttp2Session::Send() {
  MaybeSetupPreface();
  ssize_t result = std::numeric_limits<ssize_t>::max();
  // Flush any serialized prefix.
  while (result > 0 && !serialized_prefix_.empty()) {
    result = visitor_.OnReadyToSend(serialized_prefix_);
    if (result > 0) {
      serialized_prefix_.erase(0, result);
    }
  }
  if (!serialized_prefix_.empty()) {
    return;
  }
  bool continue_writing = SendQueuedFrames();
  // Wake streams for writes.
  while (continue_writing && write_scheduler_.HasReadyStreams() &&
         peer_window_ > 0) {
    const Http2StreamId stream_id = write_scheduler_.PopNextReadyStream();
    // TODO(birenroy): Add a return value to indicate write blockage, so streams
    // aren't woken unnecessarily.
    continue_writing = WriteForStream(stream_id);
  }
  if (continue_writing) {
    SendQueuedFrames();
  }
}

bool OgHttp2Session::SendQueuedFrames() {
  // Serialize and send frames in the queue.
  while (!frames_.empty()) {
    spdy::SpdySerializedFrame frame = framer_.SerializeFrame(*frames_.front());
    const ssize_t result = visitor_.OnReadyToSend(absl::string_view(frame));
    if (result < 0) {
      visitor_.OnConnectionError();
      return false;
    } else if (result == 0) {
      // Write blocked.
      return false;
    } else {
      frames_.pop_front();
      if (result < frame.size()) {
        // The frame was partially written, so the rest must be buffered.
        serialized_prefix_.assign(frame.data() + result, frame.size() - result);
        return false;
      }
    }
  }
  return true;
}

bool OgHttp2Session::WriteForStream(Http2StreamId stream_id) {
  auto it = stream_map_.find(stream_id);
  if (it == stream_map_.end()) {
    QUICHE_LOG(ERROR) << "Can't find stream " << stream_id
                      << " which is ready to write!";
    return true;
  }
  StreamState& state = it->second;
  if (state.outbound_body == nullptr) {
    // No data to send, but there might be trailers.
    if (state.trailers != nullptr) {
      auto block_ptr = std::move(state.trailers);
      if (state.half_closed_local) {
        QUICHE_LOG(ERROR) << "Sent fin; can't send trailers.";
      } else {
        SendTrailers(stream_id, std::move(*block_ptr));
        MaybeCloseWithRstStream(stream_id, state);
      }
    }
    return true;
  }
  bool source_can_produce = true;
  bool connection_can_write = true;
  int32_t available_window =
      std::min(std::min(peer_window_, state.send_window), max_frame_payload_);
  while (available_window > 0 && state.outbound_body != nullptr) {
    auto [length, end_data] =
        state.outbound_body->SelectPayloadLength(available_window);
    if (length == DataFrameSource::kBlocked) {
      source_can_produce = false;
      break;
    } else if (length == DataFrameSource::kError) {
      source_can_produce = false;
      visitor_.OnCloseStream(stream_id, Http2ErrorCode::INTERNAL_ERROR);
      break;
    }
    const bool fin = end_data ? state.outbound_body->send_fin() : false;
    spdy::SpdyDataIR data(stream_id);
    data.set_fin(fin);
    data.SetDataShallow(length);
    spdy::SpdySerializedFrame header =
        spdy::SpdyFramer::SerializeDataFrameHeaderWithPaddingLengthField(data);
    const bool success =
        state.outbound_body->Send(absl::string_view(header), length);
    if (!success) {
      connection_can_write = false;
      break;
    }
    peer_window_ -= length;
    state.send_window -= length;
    available_window =
        std::min(std::min(peer_window_, state.send_window), max_frame_payload_);
    if (end_data) {
      bool sent_trailers = false;
      if (state.trailers != nullptr) {
        auto block_ptr = std::move(state.trailers);
        if (fin) {
          QUICHE_LOG(ERROR) << "Sent fin; can't send trailers.";
        } else {
          SendTrailers(stream_id, std::move(*block_ptr));
          sent_trailers = true;
        }
      }
      state.outbound_body = nullptr;
      if (fin || sent_trailers) {
        MaybeCloseWithRstStream(stream_id, state);
      }
    }
  }
  // If the stream still has data to send, it should be marked as ready in the
  // write scheduler.
  if (source_can_produce && state.send_window > 0 &&
      state.outbound_body != nullptr) {
    write_scheduler_.MarkStreamReady(stream_id, false);
  }
  // Streams can continue writing as long as the connection is not write-blocked
  // and there is additional flow control quota available.
  return connection_can_write && available_window > 0;
}

int32_t OgHttp2Session::SubmitRequest(absl::Span<const Header> headers,
                                      DataFrameSource* data_source,
                                      void* user_data) {
  // TODO(birenroy): return an error for the incorrect perspective
  const Http2StreamId stream_id = next_stream_id_;
  next_stream_id_ += 2;
  // Convert headers to header block, create headers frame.
  auto frame =
      absl::make_unique<spdy::SpdyHeadersIR>(stream_id, ToHeaderBlock(headers));
  // Add data source and user data to stream state
  WindowManager::WindowUpdateListener listener =
      [this, stream_id](size_t window_update_delta) {
        SendWindowUpdate(stream_id, window_update_delta);
      };
  auto [iter, inserted] = stream_map_.try_emplace(
      stream_id,
      StreamState(stream_receive_window_limit_, std::move(listener)));
  if (!inserted) {
    QUICHE_LOG(DFATAL) << "Stream " << stream_id << " already exists!";
    return -501;  // NGHTTP2_ERR_INVALID_ARGUMENT
  }
  iter->second.outbound_body = data_source;
  iter->second.user_data = user_data;
  if (data_source == nullptr) {
    frame->set_fin(true);
    iter->second.half_closed_local = true;
  }
  // Add the stream to the write scheduler.
  const WriteScheduler::StreamPrecedenceType precedence(3);
  write_scheduler_.RegisterStream(stream_id, precedence);
  write_scheduler_.MarkStreamReady(stream_id, false);
  // Enqueue headers frame
  EnqueueFrame(std::move(frame));
  return stream_id;
}

int32_t OgHttp2Session::SubmitResponse(Http2StreamId stream_id,
                                       absl::Span<const Header> headers,
                                       DataFrameSource* data_source) {
  // TODO(birenroy): return an error for the incorrect perspective
  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end()) {
    QUICHE_LOG(ERROR) << "Unable to find stream " << stream_id;
    return -501;  // NGHTTP2_ERR_INVALID_ARGUMENT
  }
  // Convert headers to header block, create headers frame
  auto frame =
      absl::make_unique<spdy::SpdyHeadersIR>(stream_id, ToHeaderBlock(headers));
  if (data_source == nullptr) {
    frame->set_fin(true);
    if (iter->second.half_closed_remote) {
      visitor_.OnCloseStream(stream_id, Http2ErrorCode::NO_ERROR);
    }
  } else {
    // Add data source to stream state
    iter->second.outbound_body = data_source;
    write_scheduler_.MarkStreamReady(stream_id, false);
  }
  EnqueueFrame(std::move(frame));
  return 0;
}

int OgHttp2Session::SubmitTrailer(Http2StreamId stream_id,
                                  absl::Span<const Header> trailers) {
  // TODO(birenroy): Reject trailers when acting as a client?
  auto iter = stream_map_.find(stream_id);
  if (iter == stream_map_.end()) {
    QUICHE_LOG(ERROR) << "Unable to find stream " << stream_id;
    return -501;  // NGHTTP2_ERR_INVALID_ARGUMENT
  }
  StreamState& state = iter->second;
  if (state.half_closed_local) {
    QUICHE_LOG(ERROR) << "Stream " << stream_id << " is half closed (local)";
    return -514;  // NGHTTP2_ERR_INVALID_STREAM_STATE
  }
  if (state.trailers != nullptr) {
    QUICHE_LOG(ERROR) << "Stream " << stream_id
                      << " already has trailers queued";
    return -514;  // NGHTTP2_ERR_INVALID_STREAM_STATE
  }
  if (state.outbound_body == nullptr) {
    // Enqueue trailers immediately.
    SendTrailers(stream_id, ToHeaderBlock(trailers));
    MaybeCloseWithRstStream(stream_id, state);
  } else {
    QUICHE_LOG_IF(ERROR, state.outbound_body->send_fin())
        << "DataFrameSource will send fin, preventing trailers!";
    // Save trailers so they can be written once data is done.
    state.trailers =
        absl::make_unique<spdy::SpdyHeaderBlock>(ToHeaderBlock(trailers));
    write_scheduler_.MarkStreamReady(stream_id, false);
  }
  return 0;
}

void OgHttp2Session::OnError(http2::Http2DecoderAdapter::SpdyFramerError error,
                             std::string detailed_error) {
  QUICHE_VLOG(1) << "Error: "
                 << http2::Http2DecoderAdapter::SpdyFramerErrorToString(error)
                 << " details: " << detailed_error;
  visitor_.OnConnectionError();
}

void OgHttp2Session::OnCommonHeader(spdy::SpdyStreamId stream_id,
                                    size_t length,
                                    uint8_t type,
                                    uint8_t flags) {
  highest_received_stream_id_ = std::max(static_cast<Http2StreamId>(stream_id),
                                         highest_received_stream_id_);
  visitor_.OnFrameHeader(stream_id, length, type, flags);
}

void OgHttp2Session::OnDataFrameHeader(spdy::SpdyStreamId stream_id,
                                       size_t length,
                                       bool fin) {
  visitor_.OnBeginDataForStream(stream_id, length);
}

void OgHttp2Session::OnStreamFrameData(spdy::SpdyStreamId stream_id,
                                       const char* data,
                                       size_t len) {
  visitor_.OnDataForStream(stream_id, absl::string_view(data, len));
}

void OgHttp2Session::OnStreamEnd(spdy::SpdyStreamId stream_id) {
  auto iter = stream_map_.find(stream_id);
  if (iter != stream_map_.end()) {
    iter->second.half_closed_remote = true;
  }
  visitor_.OnEndStream(stream_id);
}

void OgHttp2Session::OnStreamPadLength(spdy::SpdyStreamId /*stream_id*/,
                                       size_t /*value*/) {
  // TODO(181586191): handle padding
}

void OgHttp2Session::OnStreamPadding(spdy::SpdyStreamId stream_id, size_t len) {
  // TODO(181586191): handle padding
}

spdy::SpdyHeadersHandlerInterface* OgHttp2Session::OnHeaderFrameStart(
    spdy::SpdyStreamId stream_id) {
  headers_handler_.set_stream_id(stream_id);
  return &headers_handler_;
}

void OgHttp2Session::OnHeaderFrameEnd(spdy::SpdyStreamId stream_id) {
  headers_handler_.set_stream_id(0);
}

void OgHttp2Session::OnRstStream(spdy::SpdyStreamId stream_id,
                                 spdy::SpdyErrorCode error_code) {
  auto iter = stream_map_.find(stream_id);
  if (iter != stream_map_.end()) {
    iter->second.half_closed_remote = true;
    iter->second.outbound_body = nullptr;
    write_scheduler_.UnregisterStream(stream_id);
  }
  visitor_.OnRstStream(stream_id, TranslateErrorCode(error_code));
  // TODO(birenroy): Consider bundling "close stream" behavior into a dedicated
  // method that also cleans up the stream map.
  visitor_.OnCloseStream(stream_id, TranslateErrorCode(error_code));
}

void OgHttp2Session::OnSettings() {
  visitor_.OnSettingsStart();
}

void OgHttp2Session::OnSetting(spdy::SpdySettingsId id, uint32_t value) {
  visitor_.OnSetting({id, value});
}

void OgHttp2Session::OnSettingsEnd() {
  visitor_.OnSettingsEnd();
  auto settings = absl::make_unique<spdy::SpdySettingsIR>();
  settings->set_is_ack(true);
  EnqueueFrame(std::move(settings));
}

void OgHttp2Session::OnSettingsAck() {
  visitor_.OnSettingsAck();
}

void OgHttp2Session::OnPing(spdy::SpdyPingId unique_id, bool is_ack) {
  visitor_.OnPing(unique_id, is_ack);
}

void OgHttp2Session::OnGoAway(spdy::SpdyStreamId last_accepted_stream_id,
                              spdy::SpdyErrorCode error_code) {
  received_goaway_ = true;
  visitor_.OnGoAway(last_accepted_stream_id, TranslateErrorCode(error_code),
                    "");
}

bool OgHttp2Session::OnGoAwayFrameData(const char* goaway_data, size_t len) {
  // Opaque data is currently ignored.
  return true;
}

void OgHttp2Session::OnHeaders(spdy::SpdyStreamId stream_id,
                               bool has_priority,
                               int weight,
                               spdy::SpdyStreamId parent_stream_id,
                               bool exclusive,
                               bool fin,
                               bool end) {
  if (options_.perspective == Perspective::kServer) {
    WindowManager::WindowUpdateListener listener =
        [this, stream_id](size_t window_update_delta) {
          SendWindowUpdate(stream_id, window_update_delta);
        };
    // TODO(birenroy): Factor out a CreateStream() method from here and
    // SubmitRequest().
    stream_map_.try_emplace(stream_id, StreamState(stream_receive_window_limit_,
                                                   std::move(listener)));
    // Add the stream to the write scheduler.
    const WriteScheduler::StreamPrecedenceType precedence(3);
    write_scheduler_.RegisterStream(stream_id, precedence);
  }
}

void OgHttp2Session::OnWindowUpdate(spdy::SpdyStreamId stream_id,
                                    int delta_window_size) {
  if (stream_id == 0) {
    peer_window_ += delta_window_size;
  } else {
    auto it = stream_map_.find(stream_id);
    if (it == stream_map_.end()) {
      QUICHE_VLOG(1) << "Stream " << stream_id << " not found!";
    } else {
      if (it->second.send_window == 0) {
        // The stream was blocked on flow control.
        write_scheduler_.MarkStreamReady(stream_id, false);
      }
      it->second.send_window += delta_window_size;
    }
  }
  visitor_.OnWindowUpdate(stream_id, delta_window_size);
}

void OgHttp2Session::OnPushPromise(spdy::SpdyStreamId stream_id,
                                   spdy::SpdyStreamId promised_stream_id,
                                   bool end) {}

void OgHttp2Session::OnContinuation(spdy::SpdyStreamId stream_id, bool end) {}

void OgHttp2Session::OnAltSvc(spdy::SpdyStreamId /*stream_id*/,
                              absl::string_view /*origin*/,
                              const spdy::SpdyAltSvcWireFormat::
                                  AlternativeServiceVector& /*altsvc_vector*/) {
}

void OgHttp2Session::OnPriority(spdy::SpdyStreamId stream_id,
                                spdy::SpdyStreamId parent_stream_id,
                                int weight,
                                bool exclusive) {}

void OgHttp2Session::OnPriorityUpdate(spdy::SpdyStreamId prioritized_stream_id,
                                      absl::string_view priority_field_value) {}

bool OgHttp2Session::OnUnknownFrame(spdy::SpdyStreamId stream_id,
                                    uint8_t frame_type) {
  return true;
}

void OgHttp2Session::MaybeSetupPreface() {
  if (!queued_preface_) {
    if (options_.perspective == Perspective::kClient) {
      serialized_prefix_.assign(spdy::kHttp2ConnectionHeaderPrefix,
                                spdy::kHttp2ConnectionHeaderPrefixSize);
    }
    // First frame must be a non-ack SETTINGS.
    if (frames_.empty() ||
        frames_.front()->frame_type() != spdy::SpdyFrameType::SETTINGS ||
        reinterpret_cast<spdy::SpdySettingsIR*>(frames_.front().get())
            ->is_ack()) {
      frames_.push_front(absl::make_unique<spdy::SpdySettingsIR>());
    }
    queued_preface_ = true;
  }
}

void OgHttp2Session::SendWindowUpdate(Http2StreamId stream_id,
                                      size_t update_delta) {
  EnqueueFrame(
      absl::make_unique<spdy::SpdyWindowUpdateIR>(stream_id, update_delta));
}

void OgHttp2Session::SendTrailers(Http2StreamId stream_id,
                                  spdy::SpdyHeaderBlock trailers) {
  auto frame =
      absl::make_unique<spdy::SpdyHeadersIR>(stream_id, std::move(trailers));
  frame->set_fin(true);
  EnqueueFrame(std::move(frame));
}

void OgHttp2Session::MaybeCloseWithRstStream(Http2StreamId stream_id,
                                             StreamState& state) {
  state.half_closed_local = true;
  if (options_.perspective == Perspective::kServer) {
    if (!state.half_closed_remote) {
      // Since the peer has not yet ended the stream, this endpoint should
      // send a RST_STREAM NO_ERROR. See RFC 7540 Section 8.1.
      EnqueueFrame(absl::make_unique<spdy::SpdyRstStreamIR>(
          stream_id, spdy::SpdyErrorCode::ERROR_CODE_NO_ERROR));
    }
    visitor_.OnCloseStream(stream_id, Http2ErrorCode::NO_ERROR);
  }
}

}  // namespace adapter
}  // namespace http2
