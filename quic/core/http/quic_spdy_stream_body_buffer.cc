// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/http/quic_spdy_stream_body_buffer.h"

#include <utility>

#include "net/third_party/quiche/src/quic/core/quic_stream_sequencer.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_logging.h"

namespace quic {

QuicSpdyStreamBodyBuffer::QuicSpdyStreamConsumeManager::
    QuicSpdyStreamConsumeManager(ConsumeFunction consume_function)
    : consume_function_(std::move(consume_function)) {}

void QuicSpdyStreamBodyBuffer::QuicSpdyStreamConsumeManager::OnConsumableBytes(
    QuicByteCount length) {
  DCHECK_NE(0u, length);

  if (fragments_.empty()) {
    consume_function_(length);
    return;
  }

  DCHECK(!fragments_.front().consumable);
  fragments_.push_back({length, /* consumable = */ true});
}

void QuicSpdyStreamBodyBuffer::QuicSpdyStreamConsumeManager::OnDataPayload(
    QuicByteCount length) {
  DCHECK_NE(0u, length);

  fragments_.push_back({length, /* consumable = */ false});
}

void QuicSpdyStreamBodyBuffer::QuicSpdyStreamConsumeManager::ConsumeData(
    QuicByteCount length) {
  if (length == 0) {
    return;
  }

  DCHECK(!fragments_.empty());
  DCHECK(!fragments_.front().consumable);

  QuicByteCount remaining_length = length;
  QuicByteCount bytes_to_consume = 0;

  do {
    const Fragment& fragment = fragments_.front();

    if (fragment.consumable) {
      bytes_to_consume += fragment.length;
      fragments_.pop_front();
      continue;
    }

    if (remaining_length == 0) {
      break;
    }

    if (fragment.length <= remaining_length) {
      bytes_to_consume += fragment.length;
      remaining_length -= fragment.length;
      fragments_.pop_front();
      // Continue iterating even if |remaining_length| to make sure consumable
      // bytes on the front of the queue are consumed.
      continue;
    }

    bytes_to_consume += remaining_length;
    QuicByteCount new_fragement_length = fragment.length - remaining_length;
    remaining_length = 0;
    fragments_.pop_front();
    fragments_.push_front({new_fragement_length, /* consumable = */ false});
    break;
  } while (!fragments_.empty());

  DCHECK_EQ(0u, remaining_length);
  if (!fragments_.empty()) {
    DCHECK(!fragments_.front().consumable);
  }

  consume_function_(bytes_to_consume);
}

QuicSpdyStreamBodyBuffer::QuicSpdyStreamBodyBuffer(
    QuicStreamSequencer* sequencer)
    : QuicSpdyStreamBodyBuffer(std::bind(&QuicStreamSequencer::MarkConsumed,
                                         sequencer,
                                         std::placeholders::_1)) {}

QuicSpdyStreamBodyBuffer::QuicSpdyStreamBodyBuffer(
    ConsumeFunction consume_function)
    : bytes_remaining_(0),
      total_body_bytes_readable_(0),
      total_body_bytes_received_(0),
      consume_manager_(std::move(consume_function)) {}

QuicSpdyStreamBodyBuffer::~QuicSpdyStreamBodyBuffer() {}

void QuicSpdyStreamBodyBuffer::OnConsumableBytes(QuicByteCount length) {
  DCHECK_NE(0u, length);

  consume_manager_.OnConsumableBytes(length);
}

void QuicSpdyStreamBodyBuffer::OnDataPayload(QuicStringPiece payload) {
  DCHECK(!payload.empty());

  consume_manager_.OnDataPayload(payload.length());

  bodies_.push_back(payload);
  total_body_bytes_received_ += payload.length();
  total_body_bytes_readable_ += payload.length();
}

void QuicSpdyStreamBodyBuffer::MarkBodyConsumed(size_t num_bytes) {
  // Check if the stream has enough decoded data.
  if (num_bytes > total_body_bytes_readable_) {
    QUIC_BUG << "Invalid argument to MarkBodyConsumed."
             << " expect to consume: " << num_bytes
             << ", but not enough bytes available. "
             << "Total bytes readable are: " << total_body_bytes_readable_;
    return;
  }
  // Discard references in the stream before the sequencer marks them consumed.
  size_t remaining = num_bytes;
  while (remaining > 0) {
    if (bodies_.empty()) {
      QUIC_BUG << "Failed to consume because body buffer is empty.";
      return;
    }
    auto body = bodies_.front();
    bodies_.pop_front();
    if (body.length() <= remaining) {
      remaining -= body.length();
    } else {
      body = body.substr(remaining, body.length() - remaining);
      bodies_.push_front(body);
      remaining = 0;
    }
  }

  // Consume DATA frame payloads and optionally other data (like DATA frame
  // headers).
  consume_manager_.ConsumeData(num_bytes);

  // Update accountings.
  bytes_remaining_ -= num_bytes;
  total_body_bytes_readable_ -= num_bytes;
}

int QuicSpdyStreamBodyBuffer::PeekBody(iovec* iov, size_t iov_len) const {
  DCHECK(iov != nullptr);
  DCHECK_GT(iov_len, 0u);

  if (bodies_.empty()) {
    iov[0].iov_base = nullptr;
    iov[0].iov_len = 0;
    return 0;
  }
  // Fill iovs with references from the stream.
  size_t iov_filled = 0;
  while (iov_filled < bodies_.size() && iov_filled < iov_len) {
    QuicStringPiece body = bodies_[iov_filled];
    iov[iov_filled].iov_base = const_cast<char*>(body.data());
    iov[iov_filled].iov_len = body.size();
    iov_filled++;
  }
  return iov_filled;
}

size_t QuicSpdyStreamBodyBuffer::ReadBody(const struct iovec* iov,
                                          size_t iov_len) {
  size_t total_data_read = 0;
  QuicByteCount total_remaining = total_body_bytes_readable_;
  size_t index = 0;
  size_t src_offset = 0;
  for (size_t i = 0; i < iov_len && total_remaining > 0; ++i) {
    char* dest = reinterpret_cast<char*>(iov[i].iov_base);
    size_t dest_remaining = iov[i].iov_len;
    while (dest_remaining > 0 && total_remaining > 0) {
      auto body = bodies_[index];
      size_t bytes_to_copy =
          std::min<size_t>(body.length() - src_offset, dest_remaining);
      memcpy(dest, body.substr(src_offset, bytes_to_copy).data(),
             bytes_to_copy);
      dest += bytes_to_copy;
      dest_remaining -= bytes_to_copy;
      total_data_read += bytes_to_copy;
      total_remaining -= bytes_to_copy;
      if (bytes_to_copy < body.length() - src_offset) {
        src_offset += bytes_to_copy;
      } else {
        index++;
        src_offset = 0;
      }
    }
  }

  MarkBodyConsumed(total_data_read);
  return total_data_read;
}

}  // namespace quic
