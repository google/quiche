// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_bidi_stream.h"

#include <array>
#include <cstdint>
#include <optional>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/common/platform/api/quiche_bug_tracker.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/web_transport/stream_helpers.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

void MoqtBidiStreamBase::OnCanRead() {
  if (stream_parser_ == nullptr) {
    QUICHE_BUG(MoqtBidiStreamBase_OnCanRead_no_stream)
        << "OnCanRead() called when no stream is bound";
    return;
  }
  while (!stream_parser_->fin_read()) {
    absl::StatusOr<MoqtRawControlMessage> message =
        stream_parser_->ReadNextMessage();
    if (absl::IsUnavailable(message.status())) {
      return;
    }
    if (!message.ok()) {
      OnFatalError(message.status());
      return;
    }
    absl::Status status = OnRawControlMessage(*message);
    if (!status.ok()) {
      OnFatalError(status);
      return;
    }
  }
}

void MoqtBidiStreamBase::OnCanWrite() {
  if (stream_parser_ == nullptr) {
    QUICHE_BUG(MoqtBidiStreamBase_OnCanWrite_no_stream)
        << "OnCanWrite() called when no stream is bound";
    return;
  }
  webtransport::Stream* stream = stream_parser_->stream();
  if (pending_messages_.empty() && fin_queued_) {
    absl::Status status = webtransport::SendFinOnStream(*stream);
    if (!status.ok()) {
      OnFatalError(status);
    }
    return;
  }
  while (!pending_messages_.empty() && stream->CanWrite()) {
    absl::Status status =
        SendMessage(std::move(pending_messages_.front()),
                    fin_queued_ && pending_messages_.size() == 1);
    pending_messages_.pop_front();
    if (!status.ok()) {
      OnFatalError(status);
      return;
    }
  }
}

absl::Status MoqtBidiStreamBase::SendOrBufferMessage(
    quiche::QuicheBuffer message, bool fin) {
  if (fin_queued_) {
    return absl::InternalError(
        "Trying to send data when a FIN has been already queued");
  }
  if (stream() == nullptr || !stream()->CanWrite()) {
    fin_queued_ = fin;
    return AddToQueue(std::move(message));
  }
  return SendMessage(std::move(message), fin);
}

absl::Status MoqtBidiStreamBase::SendRequestOk(
    uint64_t request_id, const MessageParameters& parameters, bool fin) {
  return SendOrBufferMessage(
      framer_->SerializeRequestOk(MoqtRequestOk{request_id, parameters}), fin);
}

absl::Status MoqtBidiStreamBase::SendRequestError(
    uint64_t request_id, RequestErrorCode error_code,
    std::optional<quic::QuicTimeDelta> retry_interval,
    absl::string_view reason_phrase, bool fin) {
  MoqtRequestError request_error;
  request_error.request_id = request_id;
  request_error.error_code = error_code;
  request_error.retry_interval = retry_interval;
  request_error.reason_phrase = reason_phrase;
  return SendOrBufferMessage(framer_->SerializeRequestError(request_error),
                             fin);
}

absl::Status MoqtBidiStreamBase::SendRequestError(uint64_t request_id,
                                                  MoqtRequestErrorInfo info,
                                                  bool fin) {
  return SendRequestError(request_id, info.error_code, info.retry_interval,
                          info.reason_phrase, fin);
}

void MoqtBidiStreamBase::OnFatalError(absl::Status status) {
  QUICHE_DCHECK(!status.ok());
  if (session_error_callback_ == nullptr) {
    return;
  }
  std::optional<MoqtError> error_code = GetMoqtErrorForStatus(status);
  if (!error_code.has_value()) {
    error_code = absl::IsInvalidArgument(status) ? MoqtError::kProtocolViolation
                                                 : MoqtError::kInternalError;
  }
  std::move(session_error_callback_)(*error_code, status.message());
}

absl::Status MoqtBidiStreamBase::AddToQueue(quiche::QuicheBuffer message) {
  if (pending_messages_.size() == kMaxPendingMessages) {
    return absl::ResourceExhaustedError(
        "Not enough flow credit on the control stream");
  }
  pending_messages_.push_back(std::move(message));
  return absl::OkStatus();
}

absl::Status MoqtBidiStreamBase::SendMessage(quiche::QuicheBuffer message,
                                             bool fin) {
  webtransport::StreamWriteOptions options;
  options.set_send_fin(fin);
  std::array write_vector = {quiche::QuicheMemSlice(std::move(message))};
  return stream()->Writev(absl::MakeSpan(write_vector), options);
}

}  // namespace moqt
