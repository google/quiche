// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_namespace_stream.h"

#include <memory>
#include <optional>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/session_namespace_tree.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

MoqtNamespaceSubscriberStream::~MoqtNamespaceSubscriberStream() {
  NamespaceTask* task = task_.GetIfAvailable();
  if (task != nullptr) {
    task->DeclareEof();
  }
}

void MoqtNamespaceSubscriberStream::set_stream(
    webtransport::Stream* absl_nonnull stream) {
  // TODO(martinduke): Set the priority for this stream.
  MoqtBidiStreamBase::set_stream(stream);
}

void MoqtNamespaceSubscriberStream::OnRequestOkMessage(
    const MoqtRequestOk& message) {
  if (message.request_id != request_id_) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "Unexpected request ID in response");
    return;
  }
  if (response_callback_ == nullptr) {
    OnParsingError(MoqtError::kProtocolViolation, "Two responses");
    return;
  }
  std::move(response_callback_)(std::nullopt);
  response_callback_ = nullptr;
}

void MoqtNamespaceSubscriberStream::OnRequestErrorMessage(
    const MoqtRequestError& message) {
  if (message.request_id != request_id_) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "Unexpected request ID in error");
    return;
  }
  if (response_callback_ == nullptr) {
    OnParsingError(MoqtError::kProtocolViolation, "Two responses");
    return;
  }
  std::move(response_callback_)(MoqtRequestErrorInfo{
      message.error_code, message.retry_interval, message.reason_phrase});
  response_callback_ = nullptr;
}

void MoqtNamespaceSubscriberStream::OnNamespaceMessage(
    const MoqtNamespace& message) {
  if (response_callback_ != nullptr) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "First message must be REQUEST_OK or REQUEST_ERROR");
    return;
  }
  NamespaceTask* task = task_.GetIfAvailable();
  if (task == nullptr) {
    // The application has already unsubscribed, and the stream has been reset.
    // This is irrelevant.
    return;
  }
  if (task->prefix().number_of_elements() +
          message.track_namespace_suffix.number_of_elements() >
      kMaxNamespaceElements) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "Too many namespace elements");
    return;
  }
  if (task->prefix().total_length() +
          message.track_namespace_suffix.total_length() >
      kMaxFullTrackNameSize) {
    OnParsingError(MoqtError::kProtocolViolation, "Namespace too large");
    return;
  }
  auto [it, inserted] =
      published_suffixes_.insert(message.track_namespace_suffix);
  if (!inserted) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "Two NAMESPACE messages for the same track namespace");
    return;
  }
  task->AddPendingSuffix(message.track_namespace_suffix, TransactionType::kAdd);
}

void MoqtNamespaceSubscriberStream::OnNamespaceDoneMessage(
    const MoqtNamespaceDone& message) {
  if (response_callback_ != nullptr) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "First message must be REQUEST_OK or REQUEST_ERROR");
    return;
  }
  NamespaceTask* task = task_.GetIfAvailable();
  if (task == nullptr) {
    return;
  }
  if (published_suffixes_.erase(message.track_namespace_suffix) == 0) {
    OnParsingError(MoqtError::kProtocolViolation,
                   "NAMESPACE_DONE with no active namespace");
    return;
  }
  task->AddPendingSuffix(message.track_namespace_suffix,
                         TransactionType::kDelete);
}

std::unique_ptr<MoqtNamespaceTask> MoqtNamespaceSubscriberStream::CreateTask(
    const TrackNamespace& prefix,
    ObjectsAvailableCallback absl_nonnull callback) {
  auto task =
      std::make_unique<NamespaceTask>(this, prefix, std::move(callback));
  QUICHE_DCHECK(task != nullptr);
  task_ = task->GetWeakPtr();
  QUICHE_DCHECK(task_.IsValid());
  return std::move(task);
}

MoqtNamespaceSubscriberStream::NamespaceTask::~NamespaceTask() {
  if (state_ != nullptr) {
    state_->Reset(kResetCodeCanceled);
  }
}

GetNextResult MoqtNamespaceSubscriberStream::NamespaceTask::GetNextSuffix(
    TrackNamespace& suffix, TransactionType& type) {
  if (pending_suffixes_.empty()) {
    if (error_.has_value()) {
      return kError;
    }
    if (eof_) {
      return kEof;
    }
    return kPending;
  }
  suffix = pending_suffixes_.front().suffix;
  type = pending_suffixes_.front().type;
  pending_suffixes_.pop_front();
  return kSuccess;
}

void MoqtNamespaceSubscriberStream::NamespaceTask::AddPendingSuffix(
    TrackNamespace suffix, TransactionType type) {
  if (pending_suffixes_.size() == kMaxPendingSuffixes) {
    error_ = kResetCodeTooFarBehind;
    if (state_ != nullptr) {
      state_->Reset(kResetCodeTooFarBehind);
    }
    return;
  }
  pending_suffixes_.push_back(PendingSuffix{std::move(suffix), type});
  if (callback_ != nullptr) {
    callback_();
  }
}

void MoqtNamespaceSubscriberStream::NamespaceTask::DeclareEof() {
  if (eof_) {
    return;
  }
  eof_ = true;
  state_ = nullptr;
  if (callback_ != nullptr) {
    callback_();
  }
}

MoqtNamespacePublisherStream::MoqtNamespacePublisherStream(
    MoqtFramer* framer, webtransport::Stream* stream,
    SessionErrorCallback session_error_callback, SessionNamespaceTree& tree,
    MoqtIncomingSubscribeNamespaceCallbackNew& application)
    // No stream_deleted_callback because there's no state yet.
    : MoqtBidiStreamBase(
          framer, []() {}, std::move(session_error_callback)),
      tree_(tree),
      application_(application) {
  // TODO(martinduke): Set the priority for this stream.
  MoqtBidiStreamBase::set_stream(stream, MoqtMessageType::kSubscribeNamespace);
}

MoqtNamespacePublisherStream::~MoqtNamespacePublisherStream() {
  if (task_ != nullptr) {
    // Could be null if the stream died early.
    tree_.UnsubscribeNamespace(task_->prefix());
  }
}

void MoqtNamespacePublisherStream::OnSubscribeNamespaceMessage(
    const MoqtSubscribeNamespace& message) {
  request_id_ = message.request_id;
  if (!tree_.SubscribeNamespace(message.track_namespace_prefix)) {
    SendRequestError(request_id_, RequestErrorCode::kPrefixOverlap,
                     std::nullopt, "");
    return;
  }
  QUICHE_DCHECK(task_ == nullptr);
  task_ = application_(
      message.track_namespace_prefix, message.parameters,
      // Response callback
      [this](std::optional<MoqtRequestErrorInfo> error) {
        if (error.has_value()) {
          SendRequestError(request_id_, *error, /*fin=*/true);
        } else {
          SendRequestOk(request_id_, MessageParameters());
        }
      },
      // Objects available callback
      [this]() { ProcessNamespaces(); });
}

void MoqtNamespacePublisherStream::ProcessNamespaces() {
  if (task_ == nullptr) {
    return;
  }
  TrackNamespace suffix;
  TransactionType type;
  while (!QueueIsFull()) {
    GetNextResult result = task_->GetNextSuffix(suffix, type);
    switch (result) {
      case kPending:
        return;
      case kEof:
        if (!SendFinOnStream(*stream()).ok()) {
          OnParsingError(MoqtError::kInternalError, "Failed to send FIN");
        };
        return;
      case kError:
        Reset(kResetCodeCanceled);
        return;
      case kSuccess: {
        switch (type) {
          case TransactionType::kAdd: {
            auto [it, inserted] = published_suffixes_.insert(suffix);
            if (!inserted) {
              // This should never happen. Do not send something that would
              // cause a protocol violation.
              return;
            }
            SendOrBufferMessage(
                framer_->SerializeNamespace(MoqtNamespace{suffix}));
            break;
          }
          case TransactionType::kDelete: {
            if (published_suffixes_.erase(suffix) == 0) {
              // This should never happen. Do not send something that would
              // cause a protocol violation.
              return;
            }
            SendOrBufferMessage(
                framer_->SerializeNamespaceDone(MoqtNamespaceDone{suffix}));
            break;
          }
        }
      }
    }
  }
}

}  // namespace moqt
