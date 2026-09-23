// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_FETCH_STREAM_H_
#define QUICHE_QUIC_MOQT_MOQT_FETCH_STREAM_H_

#include <cstdint>
#include <memory>
#include <optional>

#include "absl/base/nullability.h"
#include "absl/status/status.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_live_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_object_subscriber.h"
#include "quiche/quic/moqt/moqt_parser.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

using RemoveFetchCallback =
    quiche::SingleUseCallback<void(uint64_t request_id)>;

class MoqtFetchRequestStream : public MoqtBidiStreamBase,
                               public ObjectSubscriber {
 public:
  // Constructor for a standalone fetch.
  MoqtFetchRequestStream(MoqtFramer* framer,
                         const MoqtControlMessageParser& message_parser,
                         uint64_t request_id, const FullTrackName& name,
                         Location start, Location end,
                         const MessageParameters& parameters,
                         UpstreamFetchTask* absl_nonnull task,
                         SessionErrorCallback session_error_callback,
                         FetchResponseCallback response_callback,
                         RemoveFetchCallback delete_callback);
  // Constructor for a joining fetch.
  MoqtFetchRequestStream(MoqtFramer* framer,
                         const MoqtControlMessageParser& message_parser,
                         uint64_t request_id, const FullTrackName& name,
                         uint64_t joining_request_id, uint64_t joining_start,
                         bool relative, MessageParameters parameters,
                         UpstreamFetchTask* absl_nonnull task,
                         SessionErrorCallback session_error_callback,
                         FetchResponseCallback response_callback,
                         RemoveFetchCallback delete_callback);
  ~MoqtFetchRequestStream() {
    // If stream_status_ has yet to be reported, this is not a clean close.
    if (stream_status().ok()) {
      set_status(absl::CancelledError("stream destroyed"));
    }
    Detach();
  }

  // ObjectSubscriber overrides.
  bool InWindow(Location location) const override {
    return (location >= start_ && location <= end_);
  }
  bool is_fetch() const override { return true; }
  void OnStreamOpened(webtransport::StreamVisitor* stream) override;
  void OnStreamClosed(absl::Status status,
                      std::optional<DataStreamIndex> index) override;

  // MoqtBidiStreamBase overrides.
  void OnStreamBound() override;
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override;
  absl::Status OnControlMessage(const MoqtFetchOk& message);
  absl::Status OnControlMessage(const MoqtRequestOk& message);
  absl::Status OnControlMessage(const MoqtRequestError& message);
  void Detach() override;

 private:
  Location start_, end_;
  std::optional<uint64_t> joining_request_id_;
  std::optional<uint64_t> relative_groups_;

  UpstreamFetchTask* task_;
  FetchResponseCallback response_callback_;
  RemoveFetchCallback remove_callback_;
};

class MoqtFetchResponseStream : public MoqtBidiStreamBase {
 public:
  // The stream ID is the *bidi* stream ID. The stream ID is to find the
  // FETCH when the uni stream is open.
  using OpenStreamCallback = quiche::SingleUseCallback<void(
      webtransport::StreamId, MoqtTrackPriority)>;
  // Retrieve the associated subscription for a joining FETCH.
  using GetSubscriptionCallback =
      quiche::SingleUseCallback<LivePublisher*(uint64_t request_id)>;
  MoqtFetchResponseStream(MoqtFramer* absl_nonnull framer,
                          const MoqtControlMessageParser& message_parser,
                          MoqtPublisher* absl_nonnull application,
                          SessionErrorCallback session_error_callback,
                          ValidateRequestIdCallback validate_request_id,
                          OpenStreamCallback open_stream_callback,
                          GetSubscriptionCallback get_subscription_callback);
  ~MoqtFetchResponseStream() {
    if (stream_status().ok()) {
      set_status(absl::CancelledError("stream destroyed"));
    }
    Detach();
  }

  // MoqtBidiStreamBase overrides.
  void OnStreamBound() override { stream_parser()->set_allow_fin(true); }
  absl::Status OnRawControlMessage(
      const MoqtRawControlMessage& message) override;
  absl::Status OnControlMessage(const MoqtFetch& message);
  absl::Status OnControlMessage(const MoqtRequestUpdate& message);
  void Detach() override;

  std::optional<uint64_t> request_id() const { return request_id_; }
  void OnDataStreamOpen(webtransport::Stream* absl_nonnull stream,
                        MoqtTraceRecorder* trace_recorder);

 private:
  OutgoingFetchStream* absl_nullable data_stream_ = nullptr;
  std::optional<uint64_t> request_id_;
  MessageParameters parameters_;
  MoqtPriority default_publisher_priority_ = kDefaultPublisherPriority;
  std::unique_ptr<MoqtFetchTask> fetch_;
  MoqtPublisher* absl_nonnull application_;
  ValidateRequestIdCallback validate_request_id_;
  OpenStreamCallback open_stream_callback_;
  GetSubscriptionCallback get_subscription_callback_;
  quiche::QuicheWeakPtrFactory<MoqtFetchResponseStream> weak_ptr_factory_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_FETCH_STREAM_H_
