// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_NAMESPACE_STREAM_H_
#define QUICHE_QUIC_MOQT_MOQT_NAMESPACE_STREAM_H_

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/container/flat_hash_set.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_fetch_task.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_session_callbacks.h"
#include "quiche/quic/moqt/session_namespace_tree.h"
#include "quiche/common/quiche_circular_deque.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

// This class will be owned by the webtransport stream.
class MoqtNamespaceSubscriberStream : public MoqtBidiStreamBase {
 public:
  // Assumes the caller will send or queue the SUBSCRIBE_NAMESPACE.
  MoqtNamespaceSubscriberStream(
      MoqtFramer* framer, uint64_t request_id,
      BidiStreamDeletedCallback stream_deleted_callback,
      SessionErrorCallback session_error_callback,
      MoqtResponseCallback response_callback)
      : MoqtBidiStreamBase(framer, std::move(stream_deleted_callback),
                           std::move(session_error_callback)),
        request_id_(request_id),
        response_callback_(std::move(response_callback)) {}
  ~MoqtNamespaceSubscriberStream() override;

  // MoqtBidiStreamBase overrides.
  void set_stream(webtransport::Stream* absl_nonnull stream) override;
  void OnRequestOkMessage(const MoqtRequestOk& message) override;
  void OnRequestErrorMessage(const MoqtRequestError& message) override;
  void OnNamespaceMessage(const MoqtNamespace& message) override;
  void OnNamespaceDoneMessage(const MoqtNamespaceDone& message) override;

  // Send the prefix now so it is only stored in one place (the task).
  std::unique_ptr<MoqtNamespaceTask> CreateTask(const TrackNamespace& prefix,
                                                ObjectsAvailableCallback
                                                absl_nonnull callback);

 private:
  // The class that will be passed to the application to consume namespace
  // information. Owned by the application.
  class NamespaceTask : public MoqtNamespaceTask {
   public:
    NamespaceTask(MoqtNamespaceSubscriberStream* absl_nonnull state,
                  const TrackNamespace& prefix,
                  ObjectsAvailableCallback absl_nonnull callback)
        : MoqtNamespaceTask(),
          prefix_(prefix),
          state_(state),
          callback_(std::move(callback)),
          weak_ptr_factory_(this) {}
    ~NamespaceTask() override;
    // MoqtNamespaceTask methods. A return value of kEof implies
    // NAMESPACE_DONE for all outstanding namespaces.
    GetNextResult GetNextSuffix(TrackNamespace& suffix,
                                TransactionType& type) override;
    std::optional<webtransport::StreamErrorCode> GetStatus() override {
      return error_;
    }
    const TrackNamespace& prefix() override { return prefix_; }

    // Queues a suffix corresponding to a NAMESPACE (if |type| is kAdd) or a
    // NAMESPACE_DONE (if |type| is kDelete).
    void AddPendingSuffix(TrackNamespace suffix, TransactionType type);
    // The stream is closed, so no more NAMESPACE messages are forthcoming.
    // This is an implicit NAMESPACE_DONE for all published namespaces.
    void DeclareEof();
    quiche::QuicheWeakPtr<NamespaceTask> GetWeakPtr() {
      return weak_ptr_factory_.Create();
    }

   private:
    struct PendingSuffix {
      TrackNamespace suffix;
      TransactionType type;
    };

    static constexpr size_t kMaxPendingSuffixes = 100;
    const TrackNamespace prefix_;
    // Must be nonnull initially, will be nullptr if the stream is closed.
    MoqtNamespaceSubscriberStream* state_;
    quiche::QuicheCircularDeque<PendingSuffix> pending_suffixes_;
    ObjectsAvailableCallback callback_;
    std::optional<webtransport::StreamErrorCode> error_;
    bool eof_ = false;
    // Must be last.
    quiche::QuicheWeakPtrFactory<NamespaceTask> weak_ptr_factory_;
  };

  const uint64_t request_id_;
  MoqtResponseCallback response_callback_;
  absl::flat_hash_set<TrackNamespace> published_suffixes_;
  quiche::QuicheWeakPtr<NamespaceTask> task_;
};

class MoqtNamespacePublisherStream : public MoqtBidiStreamBase {
 public:
  // Constructor for the publisher side.
  MoqtNamespacePublisherStream(
      MoqtFramer* framer, webtransport::Stream* stream,
      SessionErrorCallback session_error_callback, SessionNamespaceTree& tree,
      MoqtIncomingSubscribeNamespaceCallbackNew& application);
  ~MoqtNamespacePublisherStream() override;

  // MoqtBidiStreamBase overrides.
  void OnSubscribeNamespaceMessage(
      const MoqtSubscribeNamespace& message) override;
  // TODO(martinduke): Implement this.
  void OnSubscribeUpdateMessage(const MoqtSubscribeUpdate& message) override {
    QUICHE_DLOG(INFO) << "Got SUBSCRIBE_UPDATE on Namespace stream";
  }

 private:
  void ProcessNamespaces();

  uint64_t request_id_;
  SessionNamespaceTree& tree_;
  MoqtIncomingSubscribeNamespaceCallbackNew& application_;
  std::unique_ptr<MoqtNamespaceTask> task_;
  absl::flat_hash_set<TrackNamespace> published_suffixes_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_NAMESPACE_STREAM_H_
