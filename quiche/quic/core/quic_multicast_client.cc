// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_multicast_client.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

#include "absl/algorithm/container.h"
#include "absl/strings/string_view.h"
#include "openssl/mem.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_rst_stream_frame.h"
#include "quiche/quic/core/frames/quic_stream_frame.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_connection.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_ip_address.h"

namespace quic {

namespace {

void Wipe(std::string& secret) { OPENSSL_cleanse(secret.data(), secret.size()); }

// A pending channel is held as a joined one: it counts toward the limits,
// takes newer keys, and LEAVE or RETIRE leaves it (A17).
bool JoinedOrPending(QuicMulticastControl::ChannelState state) {
  return state == QuicMulticastControl::ChannelState::kJoined ||
         state == QuicMulticastControl::ChannelState::kJoinPending;
}

}  // namespace

// ---------------------------------------------------------------------------
// QuicMulticastControl (C4): the transition table in quic_multicast_control.h.

QuicMulticastControl::QuicMulticastControl(
    Visitor* visitor, std::optional<std::vector<QuicIpAddress>> allowed_sources,
    QuicMcClientParams params)
    : visitor_(visitor),
      allowed_sources_(std::move(allowed_sources)),
      params_(std::move(params)) {}

std::optional<QuicMulticastControl::ChannelState>
QuicMulticastControl::channel_state(absl::string_view id) const {
  auto it = channels_.find(id);
  if (it == channels_.end()) {
    return std::nullopt;
  }
  return it->second.state;
}

bool QuicMulticastControl::Defer(DeferredFrame frame) {
  if (session_state_ == SessionState::kActive) {
    return false;
  }
  if (session_state_ == SessionState::kAwaitingOptIn &&
      deferred_.size() < kMaxDeferredFrames) {
    deferred_.push_back(std::move(frame));
  }
  return true;
}

void QuicMulticastControl::SendLimits() {
  QuicMcLimits frame;
  frame.sequence = ++limits_sequence_;
  frame.limits = params_.limits;
  frame.max_joined_count = params_.limits.max_channel_ids;
  visitor_->SendLimits(frame);
}

void QuicMulticastControl::SendState(absl::string_view id, Channel& channel,
                                     QuicMcChannelState state,
                                     uint64_t reason) {
  QuicMcState frame;
  frame.channel_id = std::string(id);
  frame.sequence = ++channel.state_sequence;
  frame.state = state;
  frame.reason_code = reason;
  visitor_->SendState(frame);
}

void QuicMulticastControl::ProtocolError(absl::string_view details) {
  // Nothing more is sent or joined on a connection that is being closed.
  session_state_ = SessionState::kRefused;
  deferred_.clear();
  visitor_->OnProtocolError(details);
}

void QuicMulticastControl::OnMulticastAccepted(bool server_sent_support,
                                               QuicTime now) {
  if (session_state_ != SessionState::kAwaitingOptIn) {
    return;
  }
  if (!server_sent_support) {
    session_state_ = SessionState::kRefused;
    deferred_.clear();
    return;
  }
  session_state_ = SessionState::kActive;
  SendLimits();
  std::deque<DeferredFrame> deferred;
  deferred.swap(deferred_);
  for (DeferredFrame& frame : deferred) {
    std::visit(
        [this, now](auto& f) {
          using T = std::decay_t<decltype(f)>;
          if constexpr (std::is_same_v<T, QuicMcAnnounce>) {
            OnAnnounce(std::move(f), now);
          } else if constexpr (std::is_same_v<T, QuicMcKey>) {
            OnKey(std::move(f), now);
          } else if constexpr (std::is_same_v<T, QuicMcJoin>) {
            OnJoin(f, now);
          } else if constexpr (std::is_same_v<T, QuicMcLeave>) {
            OnLeave(f, now);
          } else {
            OnRetire(f, now);
          }
        },
        frame);
  }
}

void QuicMulticastControl::OnAnnounce(QuicMcAnnounce frame, QuicTime /*now*/) {
  if (session_state_ != SessionState::kActive) {
    Defer(std::move(frame));
    return;
  }
  if (frame.header_protection_algorithm != kMcAes128GcmSha256 ||
      frame.aead_algorithm != kMcAes128GcmSha256 ||
      frame.integrity_hash_algorithm != kMcHashSha256) {
    ProtocolError("MC_ANNOUNCE with an algorithm the client did not offer");
    return;
  }
  const std::string id = frame.channel_id;
  auto it = channels_.find(id);
  if (it != channels_.end()) {
    if (!it->second.announce.has_value()) {  // Tracked since an early JOIN.
      it->second.announce = std::move(frame);
    } else if (*it->second.announce != frame) {
      ProtocolError("MC_ANNOUNCE changed a channel's properties");
    }
    return;
  }
  if (channels_.size() >= params_.limits.max_channel_ids) {
    return;  // Extra channels are ignored, as the fork does.
  }
  channels_[id].announce = std::move(frame);
}

void QuicMulticastControl::OnKey(QuicMcKey frame, QuicTime /*now*/) {
  if (session_state_ != SessionState::kActive) {
    Defer(std::move(frame));
    return;
  }
  auto it = channels_.find(frame.channel_id);
  if (it == channels_.end()) {
    Wipe(frame.secret);
    return;  // KEY on an untracked channel is ignored (fork).
  }
  Channel& channel = it->second;
  if (channel.key.has_value()) {
    if (frame.key_sequence <= channel.key->key_sequence) {
      const bool conflict = frame.key_sequence == channel.key->key_sequence &&
                            frame.secret != channel.key->secret;
      Wipe(frame.secret);
      if (conflict) {
        ProtocolError("MC_KEY reused a key sequence with another secret");
      }
      return;
    }
    Wipe(channel.key->secret);
  }
  channel.key = std::move(frame);
  if (JoinedOrPending(channel.state)) {
    visitor_->UpdateKey(*channel.key);  // Last: the visitor may re-enter.
  }
}

void QuicMulticastControl::OnJoin(const QuicMcJoin& frame, QuicTime now) {
  if (Defer(frame)) {
    return;
  }
  auto it = channels_.find(frame.channel_id);
  if (it == channels_.end()) {
    if (channels_.size() >= params_.limits.max_channel_ids) {
      Channel untracked;
      SendState(frame.channel_id, untracked, QuicMcChannelState::kDeclinedJoin,
                kMcReasonLimitViolation);
      return;
    }
    it = channels_.emplace(frame.channel_id, Channel()).first;
  }
  Channel& channel = it->second;
  if (JoinedOrPending(channel.state)) {
    return;  // Fork, Http3Session.cpp:1648-1653. CompleteJoin answers later.
  }
  channel.last_control_state =
      std::max(channel.last_control_state, frame.state_sequence);
  // Never decline for a stale MC_LIMITS or MC_STATE sequence (-08 10.3).
  uint64_t joined_count = 0;
  uint64_t joined_rate = 0;
  for (const auto& [id, c] : channels_) {
    if (JoinedOrPending(c.state)) {
      ++joined_count;
      joined_rate += c.announce->max_rate_kibps;
    }
  }
  uint64_t reason;
  if (!channel.announce.has_value() || !channel.key.has_value() ||
      channel.key->key_sequence < frame.key_sequence) {
    reason = kMcReasonUnsynchronizedProperties;
  } else if (allowed_sources_.has_value() &&
             !absl::c_linear_search(*allowed_sources_,
                                    channel.announce->source)) {
    reason = kMcReasonAdministrativeBlock;
  } else if (joined_count >= params_.limits.max_channel_ids ||
             joined_rate + channel.announce->max_rate_kibps >
                 params_.limits.max_rate_kibps) {
    reason = kMcReasonLimitViolation;
  } else {
    Answer(frame.channel_id, channel,
           visitor_->JoinChannel(*channel.announce, *channel.key), now);
    return;
  }
  Decline(frame.channel_id, channel, reason, now);
}

void QuicMulticastControl::Decline(absl::string_view id, Channel& channel,
                                   uint64_t reason, QuicTime now) {
  channel.state = ChannelState::kDeclined;
  if (reason == kMcReasonUnsynchronizedProperties) {
    channel.rejoin_deadline = now + kRejoinWait;  // Transient.
  } else {
    channel.rejoin_deadline.reset();  // Permanent: never bump for it.
  }
  SendState(id, channel, QuicMcChannelState::kDeclinedJoin, reason);
}

void QuicMulticastControl::Answer(absl::string_view id, Channel& channel,
                                  JoinResult result, QuicTime now) {
  switch (result) {
    case JoinResult::kJoined:
      channel.state = ChannelState::kJoined;
      channel.rejoin_deadline.reset();
      limits_bumps_ = 0;
      SendState(id, channel, QuicMcChannelState::kJoined,
                kMcReasonRequestedByServer);
      return;
    case JoinResult::kPending:
      channel.state = ChannelState::kJoinPending;  // CompleteJoin answers.
      channel.rejoin_deadline.reset();
      return;
    case JoinResult::kBlocked:
      Decline(id, channel, kMcReasonAdministrativeBlock, now);
      return;
    case JoinResult::kFailed:
      Decline(id, channel, kMcReasonUnspecifiedOther, now);
      return;
  }
}

void QuicMulticastControl::CompleteJoin(absl::string_view channel_id,
                                        JoinResult result, QuicTime now) {
  auto it = channels_.find(channel_id);
  // A LEAVE or RETIRE that came first cancelled the join. kPending stays
  // pending.
  if (session_state_ != SessionState::kActive || it == channels_.end() ||
      it->second.state != ChannelState::kJoinPending) {
    return;
  }
  Answer(channel_id, it->second, result, now);
}

void QuicMulticastControl::OnChannelLost(absl::string_view channel_id,
                                         uint64_t reason, QuicTime /*now*/) {
  auto it = channels_.find(channel_id);
  if (session_state_ != SessionState::kActive || it == channels_.end() ||
      it->second.state != ChannelState::kJoined) {
    return;
  }
  // As Leave(), but the embedder has already let the channel go.
  Channel& channel = it->second;
  channel.state = ChannelState::kLeft;
  channel.leave_after_packet.reset();
  SendState(channel_id, channel, QuicMcChannelState::kLeft, reason);
}

void QuicMulticastControl::Leave(absl::string_view id, Channel& channel) {
  visitor_->LeaveChannel(id);
  channel.state = ChannelState::kLeft;
  channel.leave_after_packet.reset();
  SendState(id, channel, QuicMcChannelState::kLeft,
            kMcReasonRequestedByServer);
}

void QuicMulticastControl::OnLeave(const QuicMcLeave& frame, QuicTime /*now*/) {
  if (Defer(frame)) {
    return;
  }
  auto it = channels_.find(frame.channel_id);
  if (it == channels_.end() || !JoinedOrPending(it->second.state)) {
    return;
  }
  Channel& channel = it->second;
  if (frame.state_sequence < channel.last_control_state) {
    return;  // Stale (-08 10.4).
  }
  channel.last_control_state = frame.state_sequence;
  // A pending channel gets no packets, so it leaves now.
  if (channel.state == ChannelState::kJoined && frame.after_packet_number > 0 &&
      channel.largest_packet_number.value_or(0) < frame.after_packet_number) {
    channel.leave_after_packet = frame.after_packet_number;
    return;
  }
  Leave(frame.channel_id, channel);
}

void QuicMulticastControl::Retire(
    absl::flat_hash_map<std::string, Channel>::iterator it) {
  const std::string id = it->first;
  Channel& channel = it->second;
  if (JoinedOrPending(channel.state)) {
    visitor_->LeaveChannel(id);
  }
  SendState(id, channel, QuicMcChannelState::kRetired,
            kMcReasonRequestedByServer);
  if (channel.key.has_value()) {
    Wipe(channel.key->secret);
  }
  channels_.erase(it);
}

void QuicMulticastControl::OnRetire(const QuicMcRetire& frame,
                                    QuicTime /*now*/) {
  if (Defer(frame)) {
    return;
  }
  auto it = channels_.find(frame.channel_id);
  if (it == channels_.end()) {
    Channel untracked;  // Fork, :1757-1790: RETIRED even when untracked.
    SendState(frame.channel_id, untracked, QuicMcChannelState::kRetired,
              kMcReasonRequestedByServer);
    return;
  }
  Channel& channel = it->second;
  if (channel.state == ChannelState::kJoined &&
      channel.largest_packet_number.has_value() &&
      frame.after_packet_number > 0 &&
      *channel.largest_packet_number < frame.after_packet_number) {
    channel.retire_after_packet = frame.after_packet_number;
    return;
  }
  Retire(it);
}

void QuicMulticastControl::OnChannelPacket(absl::string_view channel_id,
                                           uint64_t packet_number,
                                           QuicTime /*now*/) {
  if (session_state_ != SessionState::kActive) {
    return;
  }
  auto it = channels_.find(channel_id);
  if (it == channels_.end()) {
    return;
  }
  Channel& channel = it->second;
  channel.largest_packet_number =
      std::max(channel.largest_packet_number.value_or(0), packet_number);
  if (channel.retire_after_packet.has_value() &&
      packet_number >= *channel.retire_after_packet) {
    Retire(it);
    return;
  }
  if (channel.state == ChannelState::kJoined &&
      channel.leave_after_packet.has_value() &&
      packet_number >= *channel.leave_after_packet) {
    Leave(channel_id, channel);
  }
}

void QuicMulticastControl::OnAlarm(QuicTime now) {
  if (session_state_ != SessionState::kActive) {
    return;
  }
  bool bump = false;
  for (auto& [id, channel] : channels_) {
    if (channel.rejoin_deadline.has_value() &&
        *channel.rejoin_deadline <= now) {
      channel.rejoin_deadline.reset();
      bump |= channel.state != ChannelState::kJoined;
    }
  }
  // TQ re-JOINs after a decline only on a newer MC_LIMITS
  // (server_control.rs:1360-1372, :1420-1430).
  if (bump && limits_bumps_ < kMaxLimitsBumps) {
    ++limits_bumps_;
    SendLimits();
  }
}

std::optional<QuicTime> QuicMulticastControl::NextDeadline() const {
  std::optional<QuicTime> next;
  if (session_state_ != SessionState::kActive) {
    return next;
  }
  for (const auto& [id, channel] : channels_) {
    if (channel.rejoin_deadline.has_value() &&
        (!next.has_value() || *channel.rejoin_deadline < *next)) {
      next = channel.rejoin_deadline;
    }
  }
  return next;
}

// ---------------------------------------------------------------------------
// QuicMulticastClient (I3): decodes frames into the control, owns the
// channels (C5) and feeds their frames to the session.

class QuicMulticastClient::AlarmDelegate
    : public QuicAlarm::DelegateWithoutContext {
 public:
  explicit AlarmDelegate(QuicMulticastClient* client) : client_(client) {}
  void OnAlarm() override { client_->OnAlarm(); }

 private:
  QuicMulticastClient* client_;
};

QuicMulticastClient::QuicMulticastClient(QuicSession* session,
                                         Delegate* delegate)
    : session_(session),
      delegate_(delegate),
      control_(&control_visitor_, std::nullopt) {}

QuicMulticastClient::QuicMulticastClient(
    QuicSession* session, Delegate* delegate,
    std::vector<QuicIpAddress> allowed_sources)
    : session_(session),
      delegate_(delegate),
      control_(&control_visitor_, std::move(allowed_sources)) {}

QuicMulticastClient::~QuicMulticastClient() {
  if (alarm_ != nullptr) {
    alarm_->PermanentCancel();
  }
}

QuicTime QuicMulticastClient::Now() const {
  return session_->connection()->clock()->ApproximateNow();
}

QuicMulticastFrameStatus QuicMulticastClient::OnMulticastFrame(
    uint64_t frame_type, QuicDataReader* reader) {
  const QuicTime now = Now();
  bool ok = true;
  switch (frame_type) {
    case kMcAnnounceV4:
    case kMcAnnounceV6: {
      QuicMcAnnounce f;
      if ((ok = DecodeMcAnnounce(frame_type, reader, &f))) {
        control_.OnAnnounce(std::move(f), now);
      }
      break;
    }
    case kMcKey: {
      QuicMcKey f;
      if ((ok = DecodeMcKey(reader, &f))) {
        control_.OnKey(std::move(f), now);
      }
      break;
    }
    case kMcJoin: {
      QuicMcJoin f;
      if ((ok = DecodeMcJoin(reader, &f))) {
        control_.OnJoin(f, now);
      }
      break;
    }
    case kMcLeave: {
      QuicMcLeave f;
      if ((ok = DecodeMcLeave(reader, &f))) {
        control_.OnLeave(f, now);
      }
      break;
    }
    case kMcRetire: {
      QuicMcRetire f;
      if ((ok = DecodeMcRetire(reader, &f))) {
        control_.OnRetire(f, now);
      }
      break;
    }
    case kMcIntegrity:
    case kMcIntegrityWithLength: {
      // Every channel is SHA-256: ANNOUNCE refuses any other hash.
      QuicMcIntegrity f;
      if ((ok = DecodeMcIntegrity(frame_type, kMcSha256HashLength, reader,
                                  &f))) {
        auto it = channels_.find(f.channel_id);
        // ponytail: hashes for a channel not joined yet are dropped; buffer
        // them if a server sends MC_INTEGRITY before its JOIN.
        if (it != channels_.end()) {
          Deliver(it->first, it->second->OnIntegrity(f.packet_number_start,
                                                     f.packet_hashes, now));
        }
      }
      break;
    }
    // Client-sent types: consume the body and ignore them.
    case kMcLimits: {
      QuicMcLimits f;
      ok = DecodeMcLimits(reader, &f);
      break;
    }
    case kMcState:
    case kMcStateApplication: {
      QuicMcState f;
      ok = DecodeMcState(frame_type, reader, &f);
      break;
    }
    case kMcAck:
    case kMcAckEcn: {
      QuicMcAck f;
      ok = DecodeMcAck(frame_type, reader, &f);
      break;
    }
    default:
      return QuicMulticastFrameStatus::kNotHandled;
  }
  if (!ok) {
    return QuicMulticastFrameStatus::kError;
  }
  UpdateAlarm();
  return QuicMulticastFrameStatus::kContinue;
}

void QuicMulticastClient::OnMulticastAccepted() {
  const bool server_sent_support =
      session_->config()->received_custom_transport_parameters().contains(
          static_cast<TransportParameters::TransportParameterId>(
              kMcServerSupportId));
  control_.OnMulticastAccepted(server_sent_support, Now());
  UpdateAlarm();
}

void QuicMulticastClient::OnChannelPacket(absl::string_view channel_id,
                                          absl::string_view packet,
                                          QuicEcnCodepoint ecn,
                                          QuicTime receipt_time) {
  auto it = channels_.find(channel_id);
  if (it == channels_.end()) {
    return;
  }
  QuicConnection::ScopedPacketFlusher flusher(session_->connection());
  Deliver(it->first, it->second->OnPacket(packet, ecn, receipt_time));
  UpdateAlarm();
}

const QuicMulticastChannel::Stats* QuicMulticastClient::channel_stats(
    absl::string_view channel_id) const {
  auto it = channels_.find(channel_id);
  return it == channels_.end() ? nullptr : &it->second->stats();
}

void QuicMulticastClient::CompleteJoin(absl::string_view channel_id,
                                       JoinResult result) {
  QuicConnection::ScopedPacketFlusher flusher(session_->connection());
  control_.CompleteJoin(channel_id, result, Now());
  if (result == JoinResult::kBlocked || result == JoinResult::kFailed) {
    channels_.erase(channel_id);
  }
  UpdateAlarm();
}

void QuicMulticastClient::OnChannelLost(absl::string_view channel_id,
                                        uint64_t reason) {
  QuicConnection::ScopedPacketFlusher flusher(session_->connection());
  control_.OnChannelLost(channel_id, reason, Now());
  channels_.erase(channel_id);
  UpdateAlarm();
}

void QuicMulticastClient::Deliver(
    const std::string& channel_id,
    std::vector<QuicMulticastChannelFrame> frames) {
  const std::string id = channel_id;  // The channel may be erased below.
  for (QuicMulticastChannelFrame& f : frames) {
    if (!session_->connection()->connected()) {
      return;
    }
    if (f.multicast_frame_type != 0) {
      // The channel checked that -08 section 11 permits it and that it
      // decodes, so this handles it exactly as a unicast copy.
      QuicDataReader reader(f.data);
      const bool ok = OnMulticastFrame(f.multicast_frame_type, &reader) ==
                          QuicMulticastFrameStatus::kContinue &&
                      reader.IsDoneReading();
      Wipe(f.data);  // An MC_KEY body holds a secret.
      if (!ok) {
        control_visitor_.OnProtocolError("Bad MC frame in a channel packet");
        return;
      }
    } else if (f.reset) {
      session_->OnRstStream(QuicRstStreamFrame(
          kInvalidControlFrameId, f.stream_id,
          QuicResetStreamError::FromIetf(f.error_code), f.offset));
    } else {
      session_->OnStreamFrame(
          QuicStreamFrame(f.stream_id, f.fin, f.offset, f.data));
    }
    control_.OnChannelPacket(id, f.packet_number, Now());
  }
  auto it = channels_.find(id);
  if (it != channels_.end() && it->second->stats().forbidden_frames > 0 &&
      session_->connection()->connected()) {
    control_visitor_.OnProtocolError("Forbidden frame in a channel packet");
  }
}

void QuicMulticastClient::UpdateAlarm() {
  const QuicTime now = Now();
  std::optional<QuicTime> deadline = control_.NextDeadline();
  for (auto& [id, channel] : channels_) {
    const std::optional<QuicTime> due = channel->ack_deadline();
    if (!due.has_value()) {
      continue;
    }
    if (*due > now) {
      if (!deadline.has_value() || *due < *deadline) {
        deadline = due;
      }
      continue;
    }
    // C6: the channel's MC_ACK, on the unicast connection (-08 section 10.6).
    // It is sent as ACK is (-08 section 8: not ack-eliciting, never
    // retransmitted); a lost MC_ACK is covered by the next one.
    const std::optional<QuicMcAck> ack = channel->TakeAck();
    const std::string payload = ack.has_value() ? EncodeMcAck(*ack) : "";
    if (!payload.empty()) {
      session_->WriteMulticastControlFrame(
          ack->ecn.has_value() ? kMcAckEcn : kMcAck, payload);
    }
  }
  if (!deadline.has_value()) {
    if (alarm_ != nullptr) {
      alarm_->Cancel();
    }
    return;
  }
  if (alarm_ == nullptr) {
    alarm_.reset(session_->connection()->alarm_factory()->CreateAlarm(
        new AlarmDelegate(this)));
  }
  alarm_->Update(*deadline, QuicTime::Delta::FromMilliseconds(1));
}

void QuicMulticastClient::OnAlarm() {
  QuicConnection::ScopedPacketFlusher flusher(session_->connection());
  control_.OnAlarm(Now());
  UpdateAlarm();
}

void QuicMulticastClient::ControlVisitor::SendLimits(
    const QuicMcLimits& frame) {
  client_->session_->WriteMulticastControlFrame(kMcLimits,
                                                EncodeMcLimits(frame));
}

void QuicMulticastClient::ControlVisitor::SendState(const QuicMcState& frame) {
  client_->session_->WriteMulticastControlFrame(
      frame.application_reason ? kMcStateApplication : kMcState,
      EncodeMcState(frame));
}

QuicMulticastClient::JoinResult
QuicMulticastClient::ControlVisitor::JoinChannel(const QuicMcAnnounce& announce,
                                                 const QuicMcKey& key) {
  std::unique_ptr<QuicMulticastChannel> channel = QuicMulticastChannel::Create(
      announce.channel_id, announce.header_protection_algorithm,
      announce.header_secret, announce.aead_algorithm,
      announce.integrity_hash_algorithm, announce.max_ack_delay_ms);
  if (channel == nullptr) {
    return JoinResult::kFailed;
  }
  // No packet has arrived yet, so installing the key delivers nothing.
  channel->OnKey(key.key_sequence, key.secret, client_->Now());
  const JoinResult result = client_->delegate_->JoinChannelWithResult(
      announce.channel_id, announce.source, announce.group, announce.port);
  // A pending channel is kept too, so a key rotated while it waits reaches it.
  if (result == JoinResult::kJoined || result == JoinResult::kPending) {
    client_->channels_[announce.channel_id] = std::move(channel);
  }
  return result;
}

void QuicMulticastClient::ControlVisitor::LeaveChannel(
    absl::string_view channel_id) {
  client_->delegate_->LeaveChannel(channel_id);
  client_->channels_.erase(channel_id);
}

void QuicMulticastClient::ControlVisitor::UpdateKey(const QuicMcKey& key) {
  auto it = client_->channels_.find(key.channel_id);
  if (it != client_->channels_.end()) {
    client_->Deliver(it->first, it->second->OnKey(key.key_sequence, key.secret,
                                                  client_->Now()));
  }
}

void QuicMulticastClient::ControlVisitor::OnProtocolError(
    absl::string_view details) {
  // ponytail: -08 MC_EXTENSION_ERROR has no QuicErrorCode; this closes with
  // QUIC_INVALID_FRAME_DATA. Map a dedicated code when -10 lands (P6).
  client_->session_->connection()->CloseConnection(
      QUIC_INVALID_FRAME_DATA, std::string(details),
      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
}

}  // namespace quic
