// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_uni_stream.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>
#include <vector>

#include "absl/base/nullability.h"
#include "absl/memory/memory.h"
#include "absl/status/status.h"
#include "absl/types/span.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_object.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_trace_recorder.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_mem_slice.h"
#include "quiche/common/quiche_weak_ptr.h"
#include "quiche/web_transport/stream_helpers.h"
#include "quiche/web_transport/web_transport.h"

namespace moqt {

OutgoingSubgroupStream::OutgoingSubgroupStream(
    MoqtFramer framer, webtransport::Stream* absl_nonnull stream,
    DataStreamIndex index, uint64_t first_object,
    quiche::QuicheWeakPtr<SubscriptionPublisherInterface> visitor,
    std::shared_ptr<MoqtTrackPublisher> absl_nonnull track_publisher,
    webtransport::StreamPriority priority, uint64_t track_alias,
    MoqtTraceRecorder* absl_nonnull trace_recorder)
    : stream_(*stream),
      index_(index),
      visitor_(std::move(visitor)),
      framer_(framer),
      track_alias_(track_alias),
      publisher_(track_publisher),
      next_object_(first_object),
      priority_(priority) {
  stream_.SetPriority(priority_);
  trace_recorder->RecordSubgroupStreamCreated(stream->GetStreamId(),
                                              track_alias_, index);
}

OutgoingSubgroupStream::~OutgoingSubgroupStream() {
  // Though it might seem intuitive that the session object has to outlive the
  // connection object (and this is indeed how something like QuicSession and
  // QuicStream works), this is not the true for WebTransport visitors: the
  // session getting destroyed will inevitably lead to all related streams being
  // destroyed, but the actual order of destruction is not guaranteed.  Thus, we
  // need to check if the session still exists while accessing it in a stream
  // destructor.
  if (delivery_timeout_alarm_ != nullptr) {
    delivery_timeout_alarm_->PermanentCancel();
  }
  SubscriptionPublisherInterface* visitor = visitor_.GetIfAvailable();
  if (visitor != nullptr) {
    visitor->OnDataStreamDestroyed(index_);
  }
}

void OutgoingSubgroupStream::OnCanWrite() { SendObjects(); }

void OutgoingSubgroupStream::OnStopSendingReceived(
    webtransport::StreamErrorCode error_code) {
  SubscriptionPublisherInterface* visitor = visitor_.GetIfAvailable();
  if (visitor != nullptr) {
    visitor->OnSubgroupAbandoned(index_.group, index_.subgroup, error_code);
  }
}

void OutgoingSubgroupStream::DeliveryTimeoutDelegate::OnAlarm() {
  SubscriptionPublisherInterface* visitor = stream_->visitor_.GetIfAvailable();
  if (visitor != nullptr) {
    visitor->OnStreamTimeout(stream_->index_);
  }
  stream_->stream_.ResetWithUserCode(kResetCodeDeliveryTimeout);
}

void OutgoingSubgroupStream::SendObjects() {
  SubscriptionPublisherInterface* visitor = visitor_.GetIfAvailable();
  if (visitor == nullptr) {
    return;
  }
  while (stream_.CanWrite()) {
    std::optional<PublishedObject> object = publisher_->GetCachedObject(
        index_.group, index_.subgroup, next_object_, already_delivered_);
    if (!object.has_value()) {
      break;
    }
    if (object->metadata.payload_length > 0 && object->payload.empty()) {
      QUICHE_BUG(OutgoingSubgroupStream_empty_payload)
          << "Received non-empty object with no payload";
      return;
    }
    QUICHE_DCHECK_EQ(object->metadata.location.group, index_.group);
    QUICHE_DCHECK(object->metadata.subgroup == index_.subgroup);
    if (!visitor->InWindow(object->metadata.location)) {
      // It is possible that the next object became irrelevant due to a
      // REQUEST_UPDATE.  Close the stream if so.
      absl::Status status = webtransport::SendFinOnStream(stream_);
      QUICHE_BUG_IF(OutgoingSubgroupStream_fin_due_to_update, !status.ok())
          << "Writing FIN failed despite CanWrite() being true.";
      return;
    }

    quic::QuicTimeDelta delivery_timeout = visitor->delivery_timeout();
    if (!visitor->alternate_delivery_timeout() &&
        visitor->clock()->ApproximateNow() - object->metadata.arrival_time >
            delivery_timeout) {
      visitor->OnStreamTimeout(index_);
      stream_.ResetWithUserCode(kResetCodeDeliveryTimeout);
      // No class access below this line.
      return;
    }
    uint64_t start_offset = already_delivered_;
    already_delivered_ +=
        quic::MemSliceSpanTotalSize(absl::MakeSpan(object->payload));
    object->fin_after_this &=
        already_delivered_ == object->metadata.payload_length;
    if (start_offset > 0) {  // Just send payload.
      if (already_delivered_ == start_offset) {
        // Partial delivery of an object but the payload is empty. This would
        // result in an infinite loop.
        QUICHE_BUG(OutgoingDataStream_empty_payload)
            << "Empty payload for partial object " << object->metadata.location;
        return;
      }
      webtransport::StreamWriteOptions options;
      options.set_send_fin(object->fin_after_this);
      absl::Status write_status =
          stream_.Writev(absl::MakeSpan(object->payload), options);
      if (!write_status.ok()) {
        QUICHE_BUG(MoqtSession_WriteObjectToStream_write_failed)
            << "Writing into MoQT stream failed despite CanWrite() being true "
               "before; status: "
            << write_status;
        stream_.ResetWithUserCode(kResetCodeInternalError);
        return;
      }
    } else {
      if (!WriteObjectToStream(*object)) {
        stream_.ResetWithUserCode(kResetCodeInternalError);
        // No class access below this line.
        return;
      }
      last_object_ = object->metadata;
      next_object_ = last_object_->location.object;
      visitor->OnObjectSent(object->metadata.location);
    }
    if (already_delivered_ != last_object_->payload_length) {
      return;
    }
    ++next_object_;
    already_delivered_ = 0;
    if (object->fin_after_this && !delivery_timeout.IsInfinite() &&
        !visitor->alternate_delivery_timeout()) {
      CreateAndSetAlarm(object->metadata.arrival_time + delivery_timeout);
    }
  }
}

void OutgoingSubgroupStream::Fin(Location last_object) {
  QUICHE_DCHECK_EQ(last_object.group, index_.group);
  if (next_object_ <= last_object.object) {
    // There is still data to send, do nothing.
    return;
  }
  // All data has already been sent; send a pure FIN.
  absl::Status status = webtransport::SendFinOnStream(stream_);
  QUICHE_BUG_IF(OutgoingSubgroupStream_fin_failed, !status.ok())
      << "Writing pure FIN failed.";
  SubscriptionPublisherInterface* visitor = visitor_.GetIfAvailable();
  if (visitor == nullptr) {
    return;
  }
  quic::QuicTimeDelta delivery_timeout = visitor->delivery_timeout();
  if (!delivery_timeout.IsInfinite()) {
    CreateAndSetAlarm(visitor->clock()->ApproximateNow() + delivery_timeout);
  }
}

void OutgoingSubgroupStream::CreateAndSetAlarm(quic::QuicTime deadline) {
  if (delivery_timeout_alarm_ != nullptr) {
    return;
  }
  SubscriptionPublisherInterface* visitor = visitor_.GetIfAvailable();
  if (visitor == nullptr) {
    return;
  }
  delivery_timeout_alarm_ = absl::WrapUnique(
      visitor->alarm_factory()->CreateAlarm(new DeliveryTimeoutDelegate(this)));
  delivery_timeout_alarm_->Set(deadline);
}

bool OutgoingSubgroupStream::WriteObjectToStream(PublishedObject& object) {
  MoqtObject header;
  header.track_alias = track_alias_;
  header.group_id = object.metadata.location.group;
  header.subgroup_id = object.metadata.subgroup;
  header.object_id = object.metadata.location.object;
  header.publisher_priority = object.metadata.publisher_priority;
  header.extension_headers = object.metadata.extensions;
  header.object_status = object.metadata.status;
  header.payload_length = object.metadata.payload_length;

  // Always include extension header length, because it's difficult to know
  // a priori if they're going to appear on a stream.
  if (!last_object_.has_value()) {
    type_ = MoqtDataStreamType::Subgroup(
        index_.subgroup, next_object_, false,
        object.metadata.publisher_priority ==
            publisher_->extensions().default_publisher_priority());
  }
  quiche::QuicheBuffer serialized_header =
      framer_.SerializeObjectHeader(header, type_, last_object_);
  std::vector<quiche::QuicheMemSlice> write_vector;
  write_vector.reserve(object.payload.size() + 1);
  write_vector.push_back(quiche::QuicheMemSlice(std::move(serialized_header)));
  for (auto& slice : object.payload) {
    write_vector.push_back(std::move(slice));
  }
  webtransport::StreamWriteOptions options;
  options.set_send_fin(object.fin_after_this);
  absl::Status write_status =
      stream_.Writev(absl::MakeSpan(write_vector), options);
  if (!write_status.ok()) {
    QUICHE_BUG(MoqtSession_WriteObjectToStream_write_failed)
        << "Writing into MoQT stream failed despite CanWrite being true "
           "before; status: "
        << write_status;
    return false;
  }
  QUICHE_DVLOG(1) << "Stream " << stream_.GetStreamId()
                  << " successfully wrote " << object.metadata.location
                  << ", fin = " << object.fin_after_this;
  return true;
}

}  // namespace moqt
