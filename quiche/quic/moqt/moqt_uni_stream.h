// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_UNI_STREAM_H_
#define QUICHE_QUIC_MOQT_MOQT_UNI_STREAM_H_

#include <cstdint>
#include <memory>
#include <optional>

#include "absl/base/nullability.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {
class MoqtSessionPeer;
}

// This interface provides information about the subscription.
class SubscriptionPublisherInterface {
 public:
  virtual ~SubscriptionPublisherInterface() = default;
  virtual bool InWindow(Location) = 0;
  virtual bool alternate_delivery_timeout() = 0;
  virtual const quic::QuicClock* clock() = 0;
  virtual quic::QuicTimeDelta delivery_timeout() = 0;
  virtual quic::QuicAlarmFactory* alarm_factory() = 0;
  // Called when the first byte of an object is written to the stream.
  virtual void OnObjectSent(Location) = 0;
  virtual void OnStreamTimeout(DataStreamIndex) = 0;
  virtual void OnSubgroupAbandoned(uint64_t group, uint64_t subgroup,
                                   webtransport::StreamErrorCode) = 0;
  virtual void OnDataStreamDestroyed(DataStreamIndex) = 0;
};

// This is for subscriptions only. FETCH uses its own construct.
class QUICHE_EXPORT OutgoingSubgroupStream
    : public webtransport::StreamVisitor {
 public:
  // |visitor| is owned by the subscription, so the WeakPtr also serves as a
  // liveness token.
  OutgoingSubgroupStream(
      MoqtFramer framer, webtransport::Stream* absl_nonnull stream,
      DataStreamIndex index, uint64_t first_object,
      quiche::QuicheWeakPtr<SubscriptionPublisherInterface> visitor,
      std::shared_ptr<MoqtTrackPublisher> absl_nonnull track_publisher,
      webtransport::StreamPriority priority, uint64_t track_alias,
      MoqtTraceRecorder* absl_nonnull trace_recorder);
  ~OutgoingSubgroupStream();

  // webtransport::StreamVisitor implementation.
  void OnCanRead() override {}
  void OnCanWrite() override;
  void OnResetStreamReceived(webtransport::StreamErrorCode) override {}
  void OnStopSendingReceived(webtransport::StreamErrorCode error_code) override;
  void OnWriteSideInDataRecvdState() override {}

  class DeliveryTimeoutDelegate
      : public quic::QuicAlarm::DelegateWithoutContext {
   public:
    explicit DeliveryTimeoutDelegate(OutgoingSubgroupStream* stream)
        : stream_(stream) {}
    void OnAlarm() override;

   private:
    OutgoingSubgroupStream* stream_;
  };

  // Sends a pure FIN on the stream, if the last object sent matches
  // |last_object|. Otherwise, does nothing.
  void Fin(Location last_object);
  // Reset can be called directly on the stream, with no need to involve the
  // visitor.

  // Recomputes the send order and updates it for the associated stream.
  void UpdatePriority(MoqtPriority subscriber_priority) {
    priority_.send_order = UpdateSendOrderForSubscriberPriority(
        priority_.send_order, subscriber_priority);
    stream_.SetPriority(priority_);
  }

  // Creates and sets an alarm for the given deadline. Does nothing if the
  // alarm is already created.
  void CreateAndSetAlarm(quic::QuicTime deadline);

 private:
  friend class DeliveryTimeoutDelegate;
  friend class test::MoqtSessionPeer;

  // Sends objects on the stream, starting with `next_object_`, until the
  // stream becomes write-blocked or closed. Can reset the stream, destroying
  // the class, on a write error.
  void SendObjects();

  // Writes an object to the stream. Returns false if the write failed. The
  // caller should reset the stream if that happens.
  bool WriteObjectToStream(PublishedObject& object);

  webtransport::Stream& stream_;  // Always valid because it owns this object.
  DataStreamIndex index_;
  quiche::QuicheWeakPtr<SubscriptionPublisherInterface> visitor_;
  MoqtFramer framer_;
  MoqtDataStreamType type_;
  uint64_t track_alias_;
  std::shared_ptr<MoqtTrackPublisher> publisher_;
  // Minimum object ID that should go out next. The session doesn't know the
  // exact ID of the next object in the stream because the next object could
  // be in a different subgroup or simply be skipped.
  uint64_t next_object_;
  // Number of payload bytes from next_object_ that has already been written
  // to the stream.
  uint64_t already_delivered_ = 0;
  // Used in subgroup streams to compute the object ID diff and pass metadata
  // for partial objects. If nullopt, the stream header has not been written
  // yet.
  std::optional<PublishedObjectMetadata> last_object_;
  webtransport::StreamPriority priority_;
  // If this data stream is for SUBSCRIBE, reset it if an object has been
  // excessively delayed per Section 7.1.1.2.
  std::unique_ptr<quic::QuicAlarm> delivery_timeout_alarm_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_UNI_STREAM_H_
