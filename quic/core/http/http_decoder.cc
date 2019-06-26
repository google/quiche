// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/http/http_decoder.h"

#include "net/third_party/quiche/src/quic/core/quic_data_reader.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_bug_tracker.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_fallthrough.h"

namespace quic {

namespace {

// Create a mask that sets the last |num_bits| to 1 and the rest to 0.
inline uint8_t GetMaskFromNumBits(uint8_t num_bits) {
  return (1u << num_bits) - 1;
}

// Extract |num_bits| from |flags| offset by |offset|.
uint8_t ExtractBits(uint8_t flags, uint8_t num_bits, uint8_t offset) {
  return (flags >> offset) & GetMaskFromNumBits(num_bits);
}

// Length of the weight field of a priority frame.
static const size_t kPriorityWeightLength = 1;
// Length of a priority frame's first byte.
static const size_t kPriorityFirstByteLength = 1;

}  // namespace

HttpDecoder::HttpDecoder()
    : visitor_(nullptr),
      state_(STATE_READING_FRAME_TYPE),
      current_frame_type_(0),
      current_length_field_length_(0),
      remaining_length_field_length_(0),
      current_frame_length_(0),
      remaining_frame_length_(0),
      current_type_field_length_(0),
      remaining_type_field_length_(0),
      error_(QUIC_NO_ERROR),
      error_detail_("") {}

HttpDecoder::~HttpDecoder() {}

QuicByteCount HttpDecoder::ProcessInput(const char* data, QuicByteCount len) {
  DCHECK_EQ(QUIC_NO_ERROR, error_);
  DCHECK_NE(STATE_ERROR, state_);

  QuicDataReader reader(data, len);
  bool continue_processing = true;
  while (continue_processing &&
         (reader.BytesRemaining() != 0 || state_ == STATE_FINISH_PARSING)) {
    // |continue_processing| must have been set to false upon error.
    DCHECK_EQ(QUIC_NO_ERROR, error_);
    DCHECK_NE(STATE_ERROR, state_);

    switch (state_) {
      case STATE_READING_FRAME_TYPE:
        ReadFrameType(&reader);
        break;
      case STATE_READING_FRAME_LENGTH:
        continue_processing = ReadFrameLength(&reader);
        break;
      case STATE_READING_FRAME_PAYLOAD:
        continue_processing = ReadFramePayload(&reader);
        break;
      case STATE_FINISH_PARSING:
        continue_processing = FinishParsing();
        break;
      case STATE_ERROR:
        break;
      default:
        QUIC_BUG << "Invalid state: " << state_;
    }
  }

  return len - reader.BytesRemaining();
}

void HttpDecoder::ReadFrameType(QuicDataReader* reader) {
  DCHECK_NE(0u, reader->BytesRemaining());
  if (current_type_field_length_ == 0) {
    // A new frame is coming.
    current_type_field_length_ = reader->PeekVarInt62Length();
    DCHECK_NE(0u, current_type_field_length_);
    if (current_type_field_length_ > reader->BytesRemaining()) {
      // Buffer a new type field.
      remaining_type_field_length_ = current_type_field_length_;
      BufferFrameType(reader);
      return;
    }
    // The reader has all type data needed, so no need to buffer.
    bool success = reader->ReadVarInt62(&current_frame_type_);
    DCHECK(success);
  } else {
    // Buffer the existing type field.
    BufferFrameType(reader);
    // The frame is still not buffered completely.
    if (remaining_type_field_length_ != 0) {
      return;
    }
    QuicDataReader type_reader(type_buffer_.data(), current_type_field_length_);
    bool success = type_reader.ReadVarInt62(&current_frame_type_);
    DCHECK(success);
  }

  state_ = STATE_READING_FRAME_LENGTH;
}

bool HttpDecoder::ReadFrameLength(QuicDataReader* reader) {
  DCHECK_NE(0u, reader->BytesRemaining());
  if (current_length_field_length_ == 0) {
    // A new frame is coming.
    current_length_field_length_ = reader->PeekVarInt62Length();
    DCHECK_NE(0u, current_length_field_length_);
    if (current_length_field_length_ > reader->BytesRemaining()) {
      // Buffer a new length field.
      remaining_length_field_length_ = current_length_field_length_;
      BufferFrameLength(reader);
      return true;
    }
    // The reader has all length data needed, so no need to buffer.
    bool success = reader->ReadVarInt62(&current_frame_length_);
    DCHECK(success);
  } else {
    // Buffer the existing length field.
    BufferFrameLength(reader);
    // The frame is still not buffered completely.
    if (remaining_length_field_length_ != 0) {
      return true;
    }
    QuicDataReader length_reader(length_buffer_.data(),
                                 current_length_field_length_);
    bool success = length_reader.ReadVarInt62(&current_frame_length_);
    DCHECK(success);
  }

  if (current_frame_length_ > MaxFrameLength(current_frame_type_)) {
    // TODO(bnc): Signal HTTP_EXCESSIVE_LOAD or similar to peer.
    RaiseError(QUIC_INTERNAL_ERROR, "Frame is too large");
    visitor_->OnError(this);
    return false;
  }

  // Calling the following visitor methods does not require parsing of any
  // frame payload.
  bool continue_processing = true;
  auto frame_meta = Http3FrameLengths(
      current_length_field_length_ + current_type_field_length_,
      current_frame_length_);
  if (current_frame_type_ == 0x0) {
    continue_processing = visitor_->OnDataFrameStart(frame_meta);
  } else if (current_frame_type_ == 0x1) {
    continue_processing = visitor_->OnHeadersFrameStart(frame_meta);
  } else if (current_frame_type_ == 0x4) {
    continue_processing = visitor_->OnSettingsFrameStart(frame_meta);
  } else if (current_frame_type_ == 0x2) {
    continue_processing = visitor_->OnPriorityFrameStart(frame_meta);
  }

  remaining_frame_length_ = current_frame_length_;
  state_ = (remaining_frame_length_ == 0) ? STATE_FINISH_PARSING
                                          : STATE_READING_FRAME_PAYLOAD;
  return continue_processing;
}

bool HttpDecoder::ReadFramePayload(QuicDataReader* reader) {
  DCHECK_NE(0u, reader->BytesRemaining());
  DCHECK_NE(0u, remaining_frame_length_);

  bool continue_processing = true;

  switch (current_frame_type_) {
    case 0x0: {  // DATA
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader->BytesRemaining());
      QuicStringPiece payload;
      bool success = reader->ReadStringPiece(&payload, bytes_to_read);
      DCHECK(success);
      DCHECK(!payload.empty());
      continue_processing = visitor_->OnDataFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case 0x1: {  // HEADERS
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader->BytesRemaining());
      QuicStringPiece payload;
      bool success = reader->ReadStringPiece(&payload, bytes_to_read);
      DCHECK(success);
      DCHECK(!payload.empty());
      continue_processing = visitor_->OnHeadersFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case 0x2: {  // PRIORITY
      // TODO(rch): avoid buffering if the entire frame is present, and
      // instead parse directly out of |reader|.
      BufferFramePayload(reader);
      break;
    }
    case 0x3: {  // CANCEL_PUSH
      BufferFramePayload(reader);
      break;
    }
    case 0x4: {  // SETTINGS
      BufferFramePayload(reader);
      break;
    }
    case 0x5: {  // PUSH_PROMISE
      if (current_frame_length_ == remaining_frame_length_) {
        QuicByteCount bytes_remaining = reader->BytesRemaining();
        PushId push_id;
        // TODO(rch): Handle partial delivery of this field.
        if (!reader->ReadVarInt62(&push_id)) {
          RaiseError(QUIC_INTERNAL_ERROR, "Unable to read push_id");
          return false;
        }
        remaining_frame_length_ -= bytes_remaining - reader->BytesRemaining();
        if (!visitor_->OnPushPromiseFrameStart(push_id)) {
          continue_processing = false;
          break;
        }
      }
      DCHECK_LT(remaining_frame_length_, current_frame_length_);
      QuicByteCount bytes_to_read = std::min<QuicByteCount>(
          remaining_frame_length_, reader->BytesRemaining());
      if (bytes_to_read == 0) {
        break;
      }
      QuicStringPiece payload;
      bool success = reader->ReadStringPiece(&payload, bytes_to_read);
      DCHECK(success);
      DCHECK(!payload.empty());
      continue_processing = visitor_->OnPushPromiseFramePayload(payload);
      remaining_frame_length_ -= payload.length();
      break;
    }
    case 0x7: {  // GOAWAY
      BufferFramePayload(reader);
      break;
    }

    case 0xD: {  // MAX_PUSH_ID
      // TODO(rch): Handle partial delivery.
      BufferFramePayload(reader);
      break;
    }

    case 0xE: {  // DUPLICATE_PUSH
      BufferFramePayload(reader);
      break;
    }
    // Reserved frame types.
    // TODO(rch): Since these are actually the same behavior as the
    // default, we probably don't need to special case them here?
    case 0xB:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F * 2:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F * 3:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F * 4:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F * 5:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F * 6:
      QUIC_FALLTHROUGH_INTENDED;
    case 0xB + 0x1F * 7:
      QUIC_FALLTHROUGH_INTENDED;
    default:
      DiscardFramePayload(reader);
      return true;
  }

  if (remaining_frame_length_ == 0) {
    state_ = STATE_FINISH_PARSING;
  }

  return continue_processing;
}

bool HttpDecoder::FinishParsing() {
  DCHECK_EQ(0u, remaining_frame_length_);

  bool continue_processing = true;

  switch (current_frame_type_) {
    case 0x0: {  // DATA
      continue_processing = visitor_->OnDataFrameEnd();
      break;
    }
    case 0x1: {  // HEADERS
      continue_processing = visitor_->OnHeadersFrameEnd();
      break;
    }
    case 0x2: {  // PRIORITY
      // TODO(rch): avoid buffering if the entire frame is present, and
      // instead parse directly out of |reader|.
      PriorityFrame frame;
      QuicDataReader reader(buffer_.data(), current_frame_length_);
      if (!ParsePriorityFrame(&reader, &frame)) {
        return false;
      }
      continue_processing = visitor_->OnPriorityFrame(frame);
      break;
    }
    case 0x3: {  // CANCEL_PUSH
      // TODO(rch): Handle partial delivery.
      CancelPushFrame frame;
      QuicDataReader reader(buffer_.data(), current_frame_length_);
      if (!reader.ReadVarInt62(&frame.push_id)) {
        RaiseError(QUIC_INTERNAL_ERROR, "Unable to read push_id");
        return false;
      }
      continue_processing = visitor_->OnCancelPushFrame(frame);
      break;
    }
    case 0x4: {  // SETTINGS
      SettingsFrame frame;
      QuicDataReader reader(buffer_.data(), current_frame_length_);
      if (!ParseSettingsFrame(&reader, &frame)) {
        return false;
      }
      continue_processing = visitor_->OnSettingsFrame(frame);
      break;
    }
    case 0x5: {  // PUSH_PROMISE
      continue_processing = visitor_->OnPushPromiseFrameEnd();
      break;
    }
    case 0x7: {  // GOAWAY
      // TODO(bnc): Handle partial delivery.
      QuicDataReader reader(buffer_.data(), current_frame_length_);
      GoAwayFrame frame;
      static_assert(!std::is_same<decltype(frame.stream_id), uint64_t>::value,
                    "Please remove local |stream_id| variable and pass "
                    "&frame.stream_id directly to ReadVarInt62() when changing "
                    "QuicStreamId from uint32_t to uint64_t.");
      uint64_t stream_id;
      if (!reader.ReadVarInt62(&stream_id)) {
        RaiseError(QUIC_INTERNAL_ERROR, "Unable to read GOAWAY stream_id");
        return false;
      }
      frame.stream_id = static_cast<QuicStreamId>(stream_id);
      continue_processing = visitor_->OnGoAwayFrame(frame);
      break;
    }

    case 0xD: {  // MAX_PUSH_ID
      // TODO(bnc): Handle partial delivery.
      QuicDataReader reader(buffer_.data(), current_frame_length_);
      MaxPushIdFrame frame;
      if (!reader.ReadVarInt62(&frame.push_id)) {
        RaiseError(QUIC_INTERNAL_ERROR, "Unable to read push_id");
        return false;
      }
      continue_processing = visitor_->OnMaxPushIdFrame(frame);
      break;
    }

    case 0xE: {  // DUPLICATE_PUSH
      // TODO(bnc): Handle partial delivery.
      QuicDataReader reader(buffer_.data(), current_frame_length_);
      DuplicatePushFrame frame;
      if (!reader.ReadVarInt62(&frame.push_id)) {
        RaiseError(QUIC_INTERNAL_ERROR, "Unable to read push_id");
        return false;
      }
      continue_processing = visitor_->OnDuplicatePushFrame(frame);
      break;
    }
  }

  current_length_field_length_ = 0;
  current_type_field_length_ = 0;
  state_ = STATE_READING_FRAME_TYPE;
  return continue_processing;
}

void HttpDecoder::DiscardFramePayload(QuicDataReader* reader) {
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_frame_length_, reader->BytesRemaining());
  QuicStringPiece payload;
  bool success = reader->ReadStringPiece(&payload, bytes_to_read);
  DCHECK(success);
  remaining_frame_length_ -= payload.length();
  if (remaining_frame_length_ == 0) {
    state_ = STATE_READING_FRAME_TYPE;
    current_length_field_length_ = 0;
    current_type_field_length_ = 0;
  }
}

void HttpDecoder::BufferFramePayload(QuicDataReader* reader) {
  if (current_frame_length_ == remaining_frame_length_) {
    buffer_.erase(buffer_.size());
    buffer_.reserve(current_frame_length_);
  }
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_frame_length_, reader->BytesRemaining());
  bool success = reader->ReadBytes(
      &(buffer_[0]) + current_frame_length_ - remaining_frame_length_,
      bytes_to_read);
  DCHECK(success);
  remaining_frame_length_ -= bytes_to_read;
}

void HttpDecoder::BufferFrameLength(QuicDataReader* reader) {
  if (current_length_field_length_ == remaining_length_field_length_) {
    length_buffer_.fill(0);
  }
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_length_field_length_, reader->BytesRemaining());
  bool success =
      reader->ReadBytes(length_buffer_.data() + current_length_field_length_ -
                            remaining_length_field_length_,
                        bytes_to_read);
  DCHECK(success);
  remaining_length_field_length_ -= bytes_to_read;
}

void HttpDecoder::BufferFrameType(QuicDataReader* reader) {
  if (current_type_field_length_ == remaining_type_field_length_) {
    type_buffer_.fill(0);
  }
  QuicByteCount bytes_to_read = std::min<QuicByteCount>(
      remaining_type_field_length_, reader->BytesRemaining());
  bool success =
      reader->ReadBytes(type_buffer_.data() + current_type_field_length_ -
                            remaining_type_field_length_,
                        bytes_to_read);
  DCHECK(success);
  remaining_type_field_length_ -= bytes_to_read;
}

void HttpDecoder::RaiseError(QuicErrorCode error, std::string error_detail) {
  state_ = STATE_ERROR;
  error_ = error;
  error_detail_ = std::move(error_detail);
}

bool HttpDecoder::ParsePriorityFrame(QuicDataReader* reader,
                                     PriorityFrame* frame) {
  uint8_t flags;
  bool success = reader->ReadUInt8(&flags);
  DCHECK(success);

  frame->prioritized_type =
      static_cast<PriorityElementType>(ExtractBits(flags, 2, 6));
  frame->dependency_type =
      static_cast<PriorityElementType>(ExtractBits(flags, 2, 4));
  frame->exclusive = flags % 2 == 1;
  // TODO(bnc): Handle partial delivery.
  if (frame->prioritized_type != ROOT_OF_TREE &&
      !reader->ReadVarInt62(&frame->prioritized_element_id)) {
    RaiseError(QUIC_INTERNAL_ERROR, "Unable to read prioritized_element_id");
    return false;
  }
  if (frame->dependency_type != ROOT_OF_TREE &&
      !reader->ReadVarInt62(&frame->element_dependency_id)) {
    RaiseError(QUIC_INTERNAL_ERROR, "Unable to read element_dependency_id");
    return false;
  }
  if (!reader->ReadUInt8(&frame->weight)) {
    RaiseError(QUIC_INTERNAL_ERROR, "Unable to read priority frame weight");
    return false;
  }
  return true;
}

bool HttpDecoder::ParseSettingsFrame(QuicDataReader* reader,
                                     SettingsFrame* frame) {
  while (!reader->IsDoneReading()) {
    // TODO(bnc): Handle partial delivery of both fields.
    uint64_t id;
    if (!reader->ReadVarInt62(&id)) {
      RaiseError(QUIC_INTERNAL_ERROR,
                 "Unable to read settings frame identifier");
      return false;
    }
    uint64_t content;
    if (!reader->ReadVarInt62(&content)) {
      RaiseError(QUIC_INTERNAL_ERROR, "Unable to read settings frame content");
      return false;
    }
    frame->values[id] = content;
  }
  return true;
}

QuicByteCount HttpDecoder::MaxFrameLength(uint8_t frame_type) {
  switch (frame_type) {
    case 0x2:  // PRIORITY
      return kPriorityFirstByteLength + VARIABLE_LENGTH_INTEGER_LENGTH_8 * 2 +
             kPriorityWeightLength;
    case 0x3:  // CANCEL_PUSH
      return sizeof(PushId);
    case 0x4:  // SETTINGS
      // This limit is arbitrary.
      return 1024 * 1024;
    case 0x7:  // GOAWAY
      return sizeof(QuicStreamId);
    case 0xD:  // MAX_PUSH_ID
      return sizeof(PushId);
    case 0xE:  // DUPLICATE_PUSH
      return sizeof(PushId);
    default:
      // Other frames require no data buffering, so it's safe to have no limit.
      return std::numeric_limits<QuicByteCount>::max();
  }
}

}  // namespace quic
