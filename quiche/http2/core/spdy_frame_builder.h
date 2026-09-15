// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_HTTP2_CORE_SPDY_FRAME_BUILDER_H_
#define QUICHE_HTTP2_CORE_SPDY_FRAME_BUILDER_H_

#include <cstddef>
#include <cstdint>
#include <memory>

#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_protocol.h"
#include "quiche/http2/core/zero_copy_output_buffer.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/quiche_endian.h"

namespace spdy {

namespace test {
class SpdyFrameBuilderPeer;
}  // namespace test

// This class provides facilities for basic binary value packing
// into Spdy frames.
//
// The SpdyFrameBuilder supports appending primitive values (int, string, etc)
// to a frame instance.  The SpdyFrameBuilder grows its internal memory buffer
// dynamically to hold the sequence of primitive values.   The internal memory
// buffer is exposed as the "data" of the SpdyFrameBuilder.
class QUICHE_EXPORT SpdyFrameBuilder {
 public:
  // Initializes a SpdyFrameBuilder with a buffer of given size
  explicit SpdyFrameBuilder(size_t size);
  // Doesn't take ownership of output.
  SpdyFrameBuilder(size_t size, ZeroCopyOutputBuffer* output);

  ~SpdyFrameBuilder();

  // Returns the total size of the SpdyFrameBuilder's data, which may include
  // multiple frames.
  size_t length() const { return offset_ + length_; }

  // Seeks forward by the given number of bytes. Useful in conjunction with
  // GetWriteableBuffer() above.
  bool Seek(size_t length);

  // Populates this frame with a HTTP2 frame prefix using length information
  // from |capacity_|. The given type must be a control frame type.
  bool BeginNewFrame(SpdyFrameType type, uint8_t flags, SpdyStreamId stream_id);

  // Populates this frame with a HTTP2 frame prefix with type and length
  // information.  |type| must be a defined frame type.
  bool BeginNewFrame(SpdyFrameType type, uint8_t flags, SpdyStreamId stream_id,
                     size_t length);

  // Populates this frame with a HTTP2 frame prefix with type and length
  // information.  |raw_frame_type| may be a defined or undefined frame type.
  bool BeginNewUncheckedFrame(uint8_t raw_frame_type, uint8_t flags,
                              SpdyStreamId stream_id, size_t length);

  // Takes the buffer from the SpdyFrameBuilder.
  SpdySerializedFrame take() {
    QUICHE_BUG_IF(spdy_bug_39_1, output_ != nullptr)
        << "ZeroCopyOutputBuffer is used to build "
        << "frames. take() shouldn't be called";
    QUICHE_BUG_IF(spdy_bug_39_2, kMaxFrameSizeLimit < length_)
        << "Frame length " << length_
        << " is longer than the maximum possible allowed length.";
    SpdySerializedFrame rv(std::move(buffer_), length());
    capacity_ = 0;
    length_ = 0;
    offset_ = 0;
    return rv;
  }

  // Methods for adding to the payload.  These values are appended to the end
  // of the SpdyFrameBuilder payload. Note - binary integers are converted from
  // host to network form.
  bool WriteUInt8(uint8_t value) { return WriteBytes(&value, sizeof(value)); }
  bool WriteUInt16(uint16_t value) {
    value = quiche::QuicheEndian::HostToNet16(value);
    return WriteBytes(&value, sizeof(value));
  }
  bool WriteUInt24(uint32_t value) {
    value = quiche::QuicheEndian::HostToNet32(value);
    return WriteBytes(reinterpret_cast<char*>(&value) + 1, sizeof(value) - 1);
  }
  bool WriteUInt32(uint32_t value) {
    value = quiche::QuicheEndian::HostToNet32(value);
    return WriteBytes(&value, sizeof(value));
  }
  bool WriteUInt64(uint64_t value) {
    uint32_t upper =
        quiche::QuicheEndian::HostToNet32(static_cast<uint32_t>(value >> 32));
    uint32_t lower =
        quiche::QuicheEndian::HostToNet32(static_cast<uint32_t>(value));
    return (WriteBytes(&upper, sizeof(upper)) &&
            WriteBytes(&lower, sizeof(lower)));
  }
  bool WriteStringPiece32(const absl::string_view value);
  bool WriteBytes(const void* data, uint32_t data_len);

 private:
  friend class test::SpdyFrameBuilderPeer;

  // Populates this frame with a HTTP2 frame prefix with type and length
  // information.
  bool BeginNewFrameInternal(uint8_t raw_frame_type, uint8_t flags,
                             SpdyStreamId stream_id, size_t length);

  // Returns a writeable buffer of given size in bytes, to be appended to the
  // currently written frame. Does bounds checking on length but does not
  // increment the underlying iterator. To do so, consumers should subsequently
  // call Seek().
  // In general, consumers should use Write*() calls instead of this.
  // Returns NULL on failure.
  char* GetWritableBuffer(size_t length);
  char* GetWritableOutput(size_t desired_length, size_t* actual_length);

  // Checks to make sure that there is an appropriate amount of space for a
  // write of given size, in bytes.
  bool CanWrite(size_t length) const;

  // A buffer to be created whenever a new frame needs to be written. Used only
  // if |output_| is nullptr.
  std::unique_ptr<char[]> buffer_;
  // A pre-allocated buffer. If not-null, serialized frame data is written to
  // this buffer.
  ZeroCopyOutputBuffer* output_ = nullptr;  // Does not own.

  size_t capacity_;  // Allocation size of payload, set by constructor.
  size_t length_;    // Length of the latest frame in the buffer.
  size_t offset_;    // Position at which the latest frame begins.
};

// Packs the exclusive dependency bit (bit 31) and the 31-bit parent stream ID
// into a single 32-bit unsigned integer in network wire format for PRIORITY and
// HEADERS frames.
inline uint32_t PackStreamDependencyValues(bool exclusive,
                                           SpdyStreamId parent_stream_id) {
  uint32_t parent = parent_stream_id & 0x7fffffff;
  uint32_t e_bit = exclusive ? 0x80000000 : 0;
  return parent | e_bit;
}

inline bool SerializeDataFrame(const DataFrame& frame,
                               SpdyFrameBuilder& builder) {
  uint8_t flags = frame.flags;
  if (frame.fin()) {
    flags |= DATA_FLAG_FIN;
  }
  if (frame.padded()) {
    flags |= DATA_FLAG_PADDED;
  }
  size_t payload_len = frame.data.size() +
                       (frame.padded() ? (1 + frame.padding_payload_len) : 0);
  if (!builder.BeginNewFrame(SpdyFrameType::DATA, flags, frame.stream_id,
                             payload_len)) {
    return false;
  }
  if (frame.padded()) {
    if (!builder.WriteUInt8(frame.padding_payload_len)) {
      return false;
    }
  }
  if (!builder.WriteBytes(frame.data.data(), frame.data.size())) {
    return false;
  }
  if (frame.padded() && frame.padding_payload_len > 0) {
    std::string padding(frame.padding_payload_len, 0);
    if (!builder.WriteBytes(padding.data(), padding.length())) {
      return false;
    }
  }
  return true;
}

inline bool SerializeHeadersFrame(const HeadersFrame& frame,
                                  SpdyFrameBuilder& builder) {
  uint8_t flags = frame.flags;
  if (frame.fin()) {
    flags |= CONTROL_FLAG_FIN;
  }
  if (frame.end_headers()) {
    flags |= HEADERS_FLAG_END_HEADERS;
  }
  if (frame.padded()) {
    flags |= HEADERS_FLAG_PADDED;
  }
  if (frame.has_priority) {
    flags |= HEADERS_FLAG_PRIORITY;
  }
  size_t payload_len = frame.hpack_block.size() +
                       (frame.padded() ? (1 + frame.padding_payload_len) : 0) +
                       (frame.has_priority ? 5 : 0);
  if (!builder.BeginNewFrame(SpdyFrameType::HEADERS, flags, frame.stream_id,
                             payload_len)) {
    return false;
  }
  if (frame.padded()) {
    if (!builder.WriteUInt8(frame.padding_payload_len)) {
      return false;
    }
  }
  if (frame.has_priority) {
    int weight = ClampHttp2Weight(frame.priority.weight);
    if (!builder.WriteUInt32(PackStreamDependencyValues(
            frame.priority.exclusive, frame.priority.parent_stream_id))) {
      return false;
    }
    if (!builder.WriteUInt8(static_cast<uint8_t>(weight - 1))) {
      return false;
    }
  }
  if (!builder.WriteBytes(frame.hpack_block.data(), frame.hpack_block.size())) {
    return false;
  }
  if (frame.padded() && frame.padding_payload_len > 0) {
    std::string padding(frame.padding_payload_len, 0);
    if (!builder.WriteBytes(padding.data(), padding.length())) {
      return false;
    }
  }
  return true;
}

inline bool SerializePriorityFrame(const PriorityFrame& frame,
                                   SpdyFrameBuilder& builder) {
  if (!builder.BeginNewFrame(SpdyFrameType::PRIORITY, 0, frame.stream_id, 5)) {
    return false;
  }
  int weight = ClampHttp2Weight(frame.priority.weight);
  if (!builder.WriteUInt32(PackStreamDependencyValues(
          frame.priority.exclusive, frame.priority.parent_stream_id))) {
    return false;
  }
  return builder.WriteUInt8(static_cast<uint8_t>(weight - 1));
}

inline bool SerializeRstStreamFrame(const RstStreamFrame& frame,
                                    SpdyFrameBuilder& builder) {
  if (!builder.BeginNewFrame(SpdyFrameType::RST_STREAM, 0, frame.stream_id,
                             4)) {
    return false;
  }
  return builder.WriteUInt32(static_cast<uint32_t>(frame.error_code));
}

inline bool SerializeSettingsFrame(const SettingsFrame& frame,
                                   SpdyFrameBuilder& builder) {
  uint8_t flags = frame.is_ack ? SETTINGS_FLAG_ACK : 0;
  size_t payload_len =
      frame.is_ack ? 0 : (frame.values.size() * kSettingsOneSettingSize);
  if (!builder.BeginNewFrame(SpdyFrameType::SETTINGS, flags, 0, payload_len)) {
    return false;
  }
  if (!frame.is_ack) {
    for (const auto& param : frame.values) {
      if (!builder.WriteUInt16(param.id) || !builder.WriteUInt32(param.value)) {
        return false;
      }
    }
  }
  return true;
}

inline bool SerializePushPromiseFrame(const PushPromiseFrame& frame,
                                      SpdyFrameBuilder& builder) {
  uint8_t flags = frame.flags;
  if (frame.end_headers()) {
    flags |= PUSH_PROMISE_FLAG_END_PUSH_PROMISE;
  }
  if (frame.padded()) {
    flags |= PUSH_PROMISE_FLAG_PADDED;
  }
  size_t payload_len = 4 + frame.hpack_block.size() +
                       (frame.padded() ? (1 + frame.padding_payload_len) : 0);
  if (!builder.BeginNewFrame(SpdyFrameType::PUSH_PROMISE, flags,
                             frame.stream_id, payload_len)) {
    return false;
  }
  if (frame.padded()) {
    if (!builder.WriteUInt8(frame.padding_payload_len)) {
      return false;
    }
  }
  if (!builder.WriteUInt32(frame.promised_stream_id & 0x7fffffff)) {
    return false;
  }
  if (!builder.WriteBytes(frame.hpack_block.data(), frame.hpack_block.size())) {
    return false;
  }
  if (frame.padded() && frame.padding_payload_len > 0) {
    std::string padding(frame.padding_payload_len, 0);
    if (!builder.WriteBytes(padding.data(), padding.length())) {
      return false;
    }
  }
  return true;
}

inline bool SerializePingFrame(const PingFrame& frame,
                               SpdyFrameBuilder& builder) {
  uint8_t flags = frame.is_ack ? PING_FLAG_ACK : 0;
  if (!builder.BeginNewFrame(SpdyFrameType::PING, flags, 0, 8)) {
    return false;
  }
  return builder.WriteUInt64(frame.opaque_data);
}

inline bool SerializeGoAwayFrame(const GoAwayFrame& frame,
                                 SpdyFrameBuilder& builder) {
  size_t payload_len = 8 + frame.debug_data.size();
  if (!builder.BeginNewFrame(SpdyFrameType::GOAWAY, 0, 0, payload_len)) {
    return false;
  }
  if (!builder.WriteUInt32(frame.last_good_stream_id & 0x7fffffff)) {
    return false;
  }
  if (!builder.WriteUInt32(static_cast<uint32_t>(frame.error_code))) {
    return false;
  }
  if (!frame.debug_data.empty()) {
    if (!builder.WriteBytes(frame.debug_data.data(), frame.debug_data.size())) {
      return false;
    }
  }
  return true;
}

inline bool SerializeWindowUpdateFrame(const WindowUpdateFrame& frame,
                                       SpdyFrameBuilder& builder) {
  if (!builder.BeginNewFrame(SpdyFrameType::WINDOW_UPDATE, 0, frame.stream_id,
                             4)) {
    return false;
  }
  return builder.WriteUInt32(frame.delta & 0x7fffffff);
}

inline bool SerializeContinuationFrame(const ContinuationFrame& frame,
                                       SpdyFrameBuilder& builder) {
  uint8_t flags = frame.flags;
  if (frame.end_headers()) {
    flags |= HEADERS_FLAG_END_HEADERS;
  }
  if (!builder.BeginNewFrame(SpdyFrameType::CONTINUATION, flags,
                             frame.stream_id, frame.hpack_block.size())) {
    return false;
  }
  return builder.WriteBytes(frame.hpack_block.data(), frame.hpack_block.size());
}

inline bool SerializeAltSvcFrame(const AltSvcFrame& frame,
                                 SpdyFrameBuilder& builder) {
  size_t payload_len = 2 + frame.origin.size() + frame.value.size();
  if (!builder.BeginNewFrame(SpdyFrameType::ALTSVC, 0, frame.stream_id,
                             payload_len)) {
    return false;
  }
  if (!builder.WriteUInt16(frame.origin.size())) {
    return false;
  }
  if (!builder.WriteBytes(frame.origin.data(), frame.origin.size())) {
    return false;
  }
  return builder.WriteBytes(frame.value.data(), frame.value.size());
}

inline bool SerializePriorityUpdateFrame(const PriorityUpdateFrame& frame,
                                         SpdyFrameBuilder& builder) {
  size_t payload_len = 4 + frame.priority_field_value.size();
  if (!builder.BeginNewFrame(SpdyFrameType::PRIORITY_UPDATE, 0, 0,
                             payload_len)) {
    return false;
  }
  if (!builder.WriteUInt32(frame.prioritized_stream_id & 0x7fffffff)) {
    return false;
  }
  return builder.WriteBytes(frame.priority_field_value.data(),
                            frame.priority_field_value.size());
}

inline bool SerializeAcceptChFrame(const AcceptChFrame& frame,
                                   SpdyFrameBuilder& builder) {
  size_t payload_len = 0;
  for (size_t i = 0; i < frame.num_entries && i < frame.entries.size(); ++i) {
    payload_len +=
        4 + frame.entries[i].origin.size() + frame.entries[i].value.size();
  }
  if (!builder.BeginNewFrame(SpdyFrameType::ACCEPT_CH, 0, 0, payload_len)) {
    return false;
  }
  for (size_t i = 0; i < frame.num_entries && i < frame.entries.size(); ++i) {
    if (!builder.WriteUInt16(frame.entries[i].origin.size()) ||
        !builder.WriteBytes(frame.entries[i].origin.data(),
                            frame.entries[i].origin.size()) ||
        !builder.WriteUInt16(frame.entries[i].value.size()) ||
        !builder.WriteBytes(frame.entries[i].value.data(),
                            frame.entries[i].value.size())) {
      return false;
    }
  }
  return true;
}

inline bool SerializeUnknownFrame(const UnknownFrame& frame,
                                  SpdyFrameBuilder& builder) {
  // Handles other unknown frame types, where the payload is opaque.
  if (!builder.BeginNewUncheckedFrame(frame.type, frame.flags, frame.stream_id,
                                      frame.payload.size())) {
    return false;
  }
  return builder.WriteBytes(frame.payload.data(), frame.payload.size());
}

// Serializes a strongly-typed HTTP/2 frame representation directly into the
// provided `SpdyFrameBuilder`.
//
// This generic template writes HTTP/2 wire-format frames (RFC 9113) without
// allocating intermediate heap objects. Returns true on success, or false if
// the buffer cannot accommodate the frame or serialization fails.
template <Http2FrameConcept T>
bool SerializeFrame(const T& frame, SpdyFrameBuilder& builder) {
  if constexpr (std::is_same_v<T, DataFrame>) {
    return SerializeDataFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, HeadersFrame>) {
    return SerializeHeadersFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, PriorityFrame>) {
    return SerializePriorityFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, RstStreamFrame>) {
    return SerializeRstStreamFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, SettingsFrame>) {
    return SerializeSettingsFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, PushPromiseFrame>) {
    return SerializePushPromiseFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, PingFrame>) {
    return SerializePingFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, GoAwayFrame>) {
    return SerializeGoAwayFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, WindowUpdateFrame>) {
    return SerializeWindowUpdateFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, ContinuationFrame>) {
    return SerializeContinuationFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, AltSvcFrame>) {
    return SerializeAltSvcFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, PriorityUpdateFrame>) {
    return SerializePriorityUpdateFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, AcceptChFrame>) {
    return SerializeAcceptChFrame(frame, builder);
  } else if constexpr (std::is_same_v<T, UnknownFrame>) {
    return SerializeUnknownFrame(frame, builder);
  }
  return false;
}

// Serializes a unified `SpdyFrame` variant (containing any standard-layout
// HTTP/2 frame type) into the provided `SpdyFrameBuilder` using `std::visit`.
// Returns true on success, or false if serialization fails.
inline bool SerializeSpdyFrame(const SpdyFrame& frame,
                               SpdyFrameBuilder& builder) {
  return std::visit(
      [&builder](const auto& f) { return SerializeFrame(f, builder); }, frame);
}

}  // namespace spdy

#endif  // QUICHE_HTTP2_CORE_SPDY_FRAME_BUILDER_H_
