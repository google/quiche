// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_SUBSCRIPTION_H_
#define QUICHE_QUIC_MOQT_MOQT_SUBSCRIPTION_H_

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>

#include "absl/base/nullability.h"
#include "absl/container/btree_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_bidi_stream.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_stream_map.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/quic/moqt/moqt_uni_stream.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

namespace test {
class SubscriptionPublisherPeer;
}  // namespace test

// This is the part of the send order useful for ranking streams within the
// subscription. It sets the subscriber_priority to kDefaultSubscriberPriority
// to avoid constantly updating all pending streams.
using StreamRank = webtransport::SendOrder;

struct NewDataStreamParameters {
  DataStreamIndex index;
  uint64_t first_object;
  // nullopt if the default priority is used.
  std::optional<MoqtPriority> publisher_priority;

  NewDataStreamParameters(uint64_t group, uint64_t subgroup,
                          uint64_t first_object,
                          std::optional<MoqtPriority> publisher_priority)
      : index(group, subgroup),
        first_object(first_object),
        publisher_priority(publisher_priority) {}
};

// MoqtPublishingMonitorInterface allows a publisher monitor the delivery
// progress for a single individual subscriber.
class MoqtPublishingMonitorInterface {
 public:
  virtual ~MoqtPublishingMonitorInterface() = default;

  virtual void OnObjectAckSupportKnown(
      std::optional<quic::QuicTimeDelta> time_window) = 0;
  virtual void OnNewObjectEnqueued(Location location) = 0;
  virtual void OnObjectAckReceived(Location location,
                                   quic::QuicTimeDelta delta_from_deadline) = 0;
};

// Allows SubscriptionPublisher to get data from the session.
class QUICHE_EXPORT SessionToPublisherInterface {
 public:
  virtual ~SessionToPublisherInterface() = default;
  virtual bool alternate_delivery_timeout() const = 0;
  // If |old_priority| is nullopt, the subscription does not have any pending
  // streams. If it has a value, |old_priority| is the old value to be replaced
  // by |new_priority|.
  virtual void UpdateTrackPriority(
      uint64_t request_id, std::optional<MoqtTrackPriority> old_priority,
      MoqtTrackPriority new_priority) = 0;
  virtual quic::QuicAlarmFactory* alarm_factory() = 0;
  // Destroy any state associated with the subscription. It is OK destroy
  // SubscriptionPublisher in this method.
  virtual void PublishIsDone(uint64_t request_id) = 0;
  // Returns nullptr if MoqtSession is closing.
  virtual webtransport::Session* session() = 0;
};

// State for delivery of objects via a subscription, whether initiated by a
// SUBSCRIBE or PUBLISH.
class SubscriptionPublisher : public MoqtObjectListener,
                              public SubscriptionPublisherInterface {
 public:
  SubscriptionPublisher(MoqtFramer framer,
                        std::shared_ptr<MoqtTrackPublisher> track_publisher,
                        MoqtBidiStreamBase* absl_nonnull bidi_stream,
                        uint64_t request_id, uint64_t track_alias,
                        const MessageParameters& parameters,
                        SessionToPublisherInterface* absl_nonnull visitor,
                        MoqtPublishingMonitorInterface* monitoring_interface,
                        const quic::QuicClock* absl_nonnull clock,
                        MoqtTraceRecorder& trace_recorder);
  ~SubscriptionPublisher();

  SubscriptionPublisher(const SubscriptionPublisher&) = delete;
  SubscriptionPublisher(SubscriptionPublisher&&) = delete;
  SubscriptionPublisher& operator=(const SubscriptionPublisher&) = delete;
  SubscriptionPublisher& operator=(SubscriptionPublisher&&) = delete;

  uint64_t request_id() const { return request_id_; }
  MoqtTrackPublisher& publisher() { return *track_publisher_; }
  uint64_t track_alias() const { return track_alias_; }
  MessageParameters& parameters() { return parameters_; }

  // MoqtObjectListener implementation.
  void OnSubscribeAccepted() override;
  void OnSubscribeRejected(MoqtRequestErrorInfo info) override;
  // This is only called for objects that have just arrived.
  void OnNewObjectAvailable(Location location, std::optional<uint64_t> subgroup,
                            MoqtPriority publisher_priority) override;
  void OnTrackPublisherGone() override;
  void OnNewFinAvailable(Location location, uint64_t subgroup) override;
  // also a part of SubscriptionPublisherInterface.
  void OnSubgroupAbandoned(uint64_t group, uint64_t subgroup,
                           webtransport::StreamErrorCode error_code) override;
  void OnGroupAbandoned(uint64_t group_id) override;
  void ProcessObjectAck(const MoqtObjectAck& message);

  // SubscriptionPublisherInterface implementation.
  bool InWindow(Location location) override {
    return parameters_.forward() &&
           (!parameters_.subscription_filter.has_value() ||
            (parameters_.subscription_filter->WindowKnown() &&
             parameters_.subscription_filter->InWindow(location)));
  };
  bool alternate_delivery_timeout() override {
    return visitor_->alternate_delivery_timeout();
  }
  const quic::QuicClock* clock() override { return clock_; }
  quic::QuicTimeDelta delivery_timeout() override {
    return std::min(
        parameters_.delivery_timeout.value_or(kDefaultDeliveryTimeout),
        publisher_delivery_timeout_.value_or(kDefaultDeliveryTimeout));
  }
  quic::QuicAlarmFactory* alarm_factory() override {
    return visitor_->alarm_factory();
  }
  void OnObjectSent(Location sequence) override;
  void OnStreamTimeout(DataStreamIndex index) override {
    reset_subgroups_.insert(index);
    if (visitor_->alternate_delivery_timeout()) {
      first_active_group_ = std::max(first_active_group_, index.group + 1);
    }
  }
  // OnSubgroupAbandoned() is declared above with MoqtObjectListener.
  void OnDataStreamDestroyed(DataStreamIndex) override;

  // Called by MoqtSession when this subscription can open a new stream.
  void OnCanCreateNewUniStream();

  // Called when the parameters_ needs an update.
  void Update(const MessageParameters& parameters);

  bool can_have_joining_fetch() const { return parameters_.forward(); }

  bool established() const { return established_; }

 private:
  friend class test::SubscriptionPublisherPeer;

  MoqtPriority default_publisher_priority() const {
    return default_publisher_priority_.value_or(kDefaultPublisherPriority);
  }

  // Checks if a given Location or Group should be forwarded to the
  // subscriber.
  bool InWindow(uint64_t group) {
    return parameters_.forward() &&
           (!parameters_.subscription_filter.has_value() ||
            (parameters_.subscription_filter->WindowKnown() &&
             parameters_.subscription_filter->InWindow(group)));
  }

  void SendDatagram(Location sequence);

  // Returns the rank of the stream with respect to other streams in the
  // subscription. Higher numbers are higher priority.
  StreamRank StreamRankFor(const NewDataStreamParameters& parameters) const {
    return SendOrderForStream(
        kDefaultSubscriberPriority,
        parameters.publisher_priority.value_or(default_publisher_priority()),
        parameters.index.group, parameters.index.subgroup,
        *parameters_.group_order);
  }

  // Returns the stream priority for use at the moment of stream creation.
  webtransport::StreamPriority StreamPriorityFor(
      const NewDataStreamParameters& parameters) const {
    return webtransport::StreamPriority{
        kMoqtSendGroupId,
        SendOrderForStream(subscriber_priority(),
                           parameters.publisher_priority.value_or(
                               default_publisher_priority()),
                           parameters.index.group, parameters.index.subgroup,
                           *parameters_.group_order)};
  }

  webtransport::Stream* absl_nullable OpenDataStream(
      const NewDataStreamParameters& parameters);

  void PublishIsDone(uint64_t request_id, PublishDoneCode code,
                     absl::string_view reason);

  MoqtPriority subscriber_priority() const {
    return parameters_.subscriber_priority.value_or(kDefaultSubscriberPriority);
  }

  webtransport::Stream* GetStreamById(webtransport::StreamId stream_id) {
    return visitor_->session() == nullptr
               ? nullptr
               : visitor_->session()->GetStreamById(stream_id);
  }

  std::shared_ptr<MoqtTrackPublisher> track_publisher_;
  MoqtBidiStreamBase* absl_nonnull bidi_stream_;
  SessionToPublisherInterface* absl_nonnull visitor_;
  uint64_t request_id_;
  // Subscription is in the ESTABLISHED state.
  bool established_ = false;
  const uint64_t track_alias_;
  MoqtFramer framer_;
  MoqtTraceRecorder& trace_recorder_;
  // These are (mostly) the parameters from the SUBSCRIBE message. However,
  // group_order and largest_object may be updated by SUBSCRIBE_OK because
  // have no effect in a future REQUEST_UPDATE message.
  MessageParameters parameters_;
  std::optional<quic::QuicTimeDelta> publisher_delivery_timeout_;
  std::optional<MoqtPriority> default_publisher_priority_;
  uint64_t streams_opened_ = 0;

  // The subscription will ignore any groups with a lower ID, so it doesn't
  // need to track reset subgroups.
  uint64_t first_active_group_ = 0;
  // If a stream has been reset due to delivery timeout, do not open a new
  // stream if more object arrive for it.
  absl::flat_hash_set<DataStreamIndex> reset_subgroups_;

  MoqtPublishingMonitorInterface* monitoring_interface_;
  // Largest sequence number ever sent via this subscription.
  std::optional<Location> largest_sent_;
  SendStreamMap stream_map_;
  // Store the StreamRank of queued outgoing data streams. High StreamRank is
  // highest priority, so use rbegin() to get the highest priority pending
  // stream.
  absl::btree_multimap<StreamRank, NewDataStreamParameters> pending_streams_;
  const quic::QuicClock* absl_nonnull clock_;
  // Must be last.
  quiche::QuicheWeakPtrFactory<SubscriptionPublisherInterface>
      weak_ptr_factory_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_SUBSCRIPTION_H_
