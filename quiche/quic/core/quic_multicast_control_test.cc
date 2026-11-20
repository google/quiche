// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// C4 session tests (quic_multicast_control.h, "SESSION TESTS"): the pure
// state machine against TQ's re-JOIN rule and the fork oracle's flow.

#include "quiche/quic/core/quic_multicast_control.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace test {
namespace {

using ChannelState = QuicMulticastControl::ChannelState;
using JoinResult = QuicMulticastControl::JoinResult;
using SessionState = QuicMulticastControl::SessionState;

constexpr char kChannel[] = "demo-channel";

QuicIpAddress Ip(const char* literal) {
  QuicIpAddress ip;
  EXPECT_TRUE(ip.FromString(literal));
  return ip;
}

class FakeVisitor : public QuicMulticastControl::Visitor {
 public:
  void SendLimits(const QuicMcLimits& frame) override {
    limits.push_back(frame);
  }
  void SendState(const QuicMcState& frame) override { states.push_back(frame); }
  JoinResult JoinChannel(const QuicMcAnnounce& announce,
                         const QuicMcKey& /*key*/) override {
    joins.push_back(announce.channel_id);
    return join_result;
  }
  void LeaveChannel(absl::string_view channel_id) override {
    leaves.push_back(std::string(channel_id));
  }
  void UpdateKey(const QuicMcKey& key) override {
    key_updates.push_back(key.key_sequence);
  }
  void OnProtocolError(absl::string_view details) override {
    errors.push_back(std::string(details));
  }

  JoinResult join_result = JoinResult::kJoined;
  std::vector<QuicMcLimits> limits;
  std::vector<QuicMcState> states;
  std::vector<std::string> joins;
  std::vector<std::string> leaves;
  std::vector<uint64_t> key_updates;
  std::vector<std::string> errors;
};

class QuicMulticastControlTest : public QuicTest {
 protected:
  QuicMulticastControlTest()
      : control_(&visitor_, std::vector<QuicIpAddress>{Ip("192.0.2.1")}) {}

  static QuicMcAnnounce Announce(const char* source = "192.0.2.1",
                                 const char* id = kChannel) {
    QuicMcAnnounce f;
    f.channel_id = id;
    f.source = Ip(source);
    f.group = Ip("232.1.2.3");
    f.port = 5002;
    f.header_protection_algorithm = kMcAes128GcmSha256;
    f.header_secret = std::string(32, 'h');
    f.aead_algorithm = kMcAes128GcmSha256;
    f.integrity_hash_algorithm = kMcHashSha256;
    f.max_rate_kibps = 1000;
    f.max_ack_delay_ms = 25;
    return f;
  }
  static QuicMcKey Key(uint64_t sequence, char fill = 'k',
                       const char* id = kChannel) {
    QuicMcKey f;
    f.channel_id = id;
    f.key_sequence = sequence;
    f.secret = std::string(32, fill);
    return f;
  }
  static QuicMcJoin Join(uint64_t limits, uint64_t state, uint64_t key,
                         const char* id = kChannel) {
    QuicMcJoin f;
    f.channel_id = id;
    f.limits_sequence = limits;
    f.state_sequence = state;
    f.key_sequence = key;
    return f;
  }

  QuicTime At(int64_t ms) const {
    return QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(ms);
  }
  void Accept() { control_.OnMulticastAccepted(true, At(0)); }
  void Joined() {
    Accept();
    control_.OnAnnounce(Announce(), At(0));
    control_.OnKey(Key(1), At(0));
    control_.OnJoin(Join(1, 0, 1), At(0));
    ASSERT_EQ(control_.channel_state(kChannel), ChannelState::kJoined);
  }
  // As Joined(), but the visitor leaves the JOIN pending (A17).
  void Pending() {
    visitor_.join_result = JoinResult::kPending;
    Accept();
    control_.OnAnnounce(Announce(), At(0));
    control_.OnKey(Key(1), At(0));
    control_.OnJoin(Join(1, 0, 1), At(0));
    ASSERT_EQ(control_.channel_state(kChannel), ChannelState::kJoinPending);
  }
  void ExpectState(size_t index, QuicMcChannelState state, uint64_t sequence,
                   uint64_t reason) {
    ASSERT_LT(index, visitor_.states.size());
    EXPECT_EQ(visitor_.states[index].state, state);
    EXPECT_EQ(visitor_.states[index].sequence, sequence);
    EXPECT_EQ(visitor_.states[index].reason_code, reason);
    EXPECT_EQ(visitor_.states[index].channel_id, kChannel);
  }

  FakeVisitor visitor_;
  QuicMulticastControl control_;
};

TEST_F(QuicMulticastControlTest, NothingSentBeforeOptIn) {
  control_.OnAnnounce(Announce(), At(0));
  control_.OnKey(Key(1), At(0));
  control_.OnJoin(Join(0, 0, 1), At(0));
  EXPECT_TRUE(visitor_.limits.empty());
  EXPECT_TRUE(visitor_.states.empty());
  EXPECT_TRUE(visitor_.joins.empty());

  control_.OnMulticastAccepted(true, At(5));
  ASSERT_EQ(visitor_.limits.size(), 1u);
  EXPECT_EQ(visitor_.limits[0].sequence, 1u);
  EXPECT_EQ(visitor_.limits[0].limits, QuicMcDefaultClientParams().limits);
  EXPECT_EQ(visitor_.limits[0].max_joined_count, 32u);
  // The deferred frames replay in arrival order: the JOIN now succeeds.
  ExpectState(0, QuicMcChannelState::kJoined, 1, kMcReasonRequestedByServer);
  EXPECT_EQ(visitor_.joins, std::vector<std::string>{kChannel});
}

TEST_F(QuicMulticastControlTest, NoServerParameterRefusesForever) {
  control_.OnAnnounce(Announce(), At(0));
  control_.OnMulticastAccepted(false, At(0));
  EXPECT_EQ(control_.session_state(), SessionState::kRefused);
  control_.OnKey(Key(1), At(0));
  control_.OnJoin(Join(1, 0, 1), At(0));
  control_.OnMulticastAccepted(true, At(0));
  EXPECT_TRUE(visitor_.limits.empty());
  EXPECT_TRUE(visitor_.states.empty());
  EXPECT_TRUE(visitor_.joins.empty());
}

TEST_F(QuicMulticastControlTest, DeferredFramesAreCapped) {
  for (size_t i = 0; i < QuicMulticastControl::kMaxDeferredFrames + 10; ++i) {
    control_.OnJoin(Join(0, 0, 1), At(0));
  }
  Accept();
  // One decline for the first JOIN; later JOINs on a declined channel are
  // handled again, so count them: at most kMaxDeferredFrames.
  EXPECT_EQ(visitor_.states.size(), QuicMulticastControl::kMaxDeferredFrames);
}

// Fork oracle (main.rs:364-381, :528-544): ANNOUNCE + JOIN with no KEY at
// session start, then KEY and a re-JOIN. The first JOIN is declined; no JOIN
// is declined once its key is installed; no MC_LIMITS bump.
TEST_F(QuicMulticastControlTest, OracleRejoinAfterKey) {
  control_.OnAnnounce(Announce(), At(0));
  control_.OnJoin(Join(0, 0, 1), At(0));
  Accept();
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonUnsynchronizedProperties);
  EXPECT_EQ(control_.NextDeadline(), At(1000));

  control_.OnKey(Key(1), At(200));
  control_.OnJoin(Join(1, 1, 1), At(200));
  ExpectState(1, QuicMcChannelState::kJoined, 2, kMcReasonRequestedByServer);
  EXPECT_FALSE(control_.NextDeadline().has_value());
  control_.OnAlarm(At(1000));
  EXPECT_EQ(visitor_.limits.size(), 1u);  // No bump.
}

// TQ (server_control.rs:1360-1372, :1420-1430): JOIN only after MC_LIMITS,
// and no re-JOIN after a decline until a newer MC_LIMITS.
TEST_F(QuicMulticastControlTest, TqLostKeyBumpsLimits) {
  Accept();
  control_.OnAnnounce(Announce(), At(10));
  control_.OnJoin(Join(1, 0, 1), At(10));  // The KEY was lost.
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonUnsynchronizedProperties);
  ASSERT_EQ(control_.NextDeadline(), At(1010));
  control_.OnAlarm(At(1009));
  EXPECT_EQ(visitor_.limits.size(), 1u);
  control_.OnAlarm(At(1010));
  ASSERT_EQ(visitor_.limits.size(), 2u);
  EXPECT_EQ(visitor_.limits[1].sequence, 2u);
  EXPECT_EQ(visitor_.limits[1].limits, visitor_.limits[0].limits);

  control_.OnKey(Key(1), At(1100));
  control_.OnJoin(Join(2, 1, 1), At(1100));
  ExpectState(1, QuicMcChannelState::kJoined, 2, kMcReasonRequestedByServer);
}

TEST_F(QuicMulticastControlTest, LimitsBumpsAreBounded) {
  Accept();
  control_.OnAnnounce(Announce(), At(0));
  for (int i = 0; i < 10; ++i) {
    control_.OnJoin(Join(1, 0, 1), At(i * 1000));
    control_.OnAlarm(At(i * 1000 + 1000));
  }
  EXPECT_EQ(visitor_.limits.size(),
            1u + QuicMulticastControl::kMaxLimitsBumps);
}

TEST_F(QuicMulticastControlTest, SourceOutsideAllowlistNeverBumps) {
  Accept();
  control_.OnAnnounce(Announce("198.51.100.7"), At(0));
  control_.OnKey(Key(1), At(0));
  control_.OnJoin(Join(1, 0, 1), At(0));
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonAdministrativeBlock);
  EXPECT_TRUE(visitor_.joins.empty());
  EXPECT_FALSE(control_.NextDeadline().has_value());
  control_.OnAlarm(At(5000));
  EXPECT_EQ(visitor_.limits.size(), 1u);
}

TEST_F(QuicMulticastControlTest, SocketFailureDeclines) {
  visitor_.join_result = JoinResult::kFailed;
  Accept();
  control_.OnAnnounce(Announce(), At(0));
  control_.OnKey(Key(1), At(0));
  control_.OnJoin(Join(1, 0, 1), At(0));
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonUnspecifiedOther);
  EXPECT_FALSE(control_.NextDeadline().has_value());
}

TEST_F(QuicMulticastControlTest, RateLimitDeclines) {
  Accept();
  QuicMcAnnounce announce = Announce();
  announce.max_rate_kibps = 100'001;
  control_.OnAnnounce(announce, At(0));
  control_.OnKey(Key(1), At(0));
  control_.OnJoin(Join(1, 0, 1), At(0));
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonLimitViolation);
}

TEST_F(QuicMulticastControlTest, JoinWhileJoinedIsIgnored) {
  Joined();
  control_.OnJoin(Join(1, 1, 1), At(10));
  EXPECT_EQ(visitor_.states.size(), 1u);
  EXPECT_EQ(visitor_.joins.size(), 1u);
}

TEST_F(QuicMulticastControlTest, LeaveNow) {
  Joined();
  QuicMcLeave leave;
  leave.channel_id = kChannel;
  leave.state_sequence = 1;
  control_.OnLeave(leave, At(10));
  EXPECT_EQ(visitor_.leaves, std::vector<std::string>{kChannel});
  ExpectState(1, QuicMcChannelState::kLeft, 2, kMcReasonRequestedByServer);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kLeft);
}

TEST_F(QuicMulticastControlTest, StaleLeaveIsIgnored) {
  Accept();
  control_.OnAnnounce(Announce(), At(0));
  control_.OnKey(Key(1), At(0));
  control_.OnJoin(Join(1, 5, 1), At(0));
  QuicMcLeave leave;
  leave.channel_id = kChannel;
  leave.state_sequence = 4;
  control_.OnLeave(leave, At(10));
  EXPECT_TRUE(visitor_.leaves.empty());
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kJoined);
}

TEST_F(QuicMulticastControlTest, LeaveAfterPacketWaits) {
  Joined();
  QuicMcLeave leave;
  leave.channel_id = kChannel;
  leave.state_sequence = 1;
  leave.after_packet_number = 7;
  control_.OnLeave(leave, At(10));
  control_.OnChannelPacket(kChannel, 6, At(20));
  EXPECT_TRUE(visitor_.leaves.empty());
  control_.OnChannelPacket(kChannel, 7, At(30));
  EXPECT_EQ(visitor_.leaves, std::vector<std::string>{kChannel});
  ExpectState(1, QuicMcChannelState::kLeft, 2, kMcReasonRequestedByServer);
}

TEST_F(QuicMulticastControlTest, RetireDropsState) {
  Joined();
  QuicMcRetire retire;
  retire.channel_id = kChannel;
  control_.OnRetire(retire, At(10));
  EXPECT_EQ(visitor_.leaves, std::vector<std::string>{kChannel});
  ExpectState(1, QuicMcChannelState::kRetired, 2, kMcReasonRequestedByServer);
  EXPECT_FALSE(control_.channel_state(kChannel).has_value());
}

TEST_F(QuicMulticastControlTest, RetireAfterPacketWaitsForData) {
  Joined();
  control_.OnChannelPacket(kChannel, 2, At(5));
  QuicMcRetire retire;
  retire.channel_id = kChannel;
  retire.after_packet_number = 4;
  control_.OnRetire(retire, At(10));
  EXPECT_TRUE(visitor_.leaves.empty());
  control_.OnChannelPacket(kChannel, 4, At(20));
  EXPECT_EQ(visitor_.leaves, std::vector<std::string>{kChannel});
  ASSERT_EQ(visitor_.states.size(), 2u);  // JOINED, RETIRED: no LEFT.
  ExpectState(1, QuicMcChannelState::kRetired, 2, kMcReasonRequestedByServer);
}

TEST_F(QuicMulticastControlTest, RetireUntrackedChannel) {
  Accept();
  QuicMcRetire retire;
  retire.channel_id = kChannel;
  control_.OnRetire(retire, At(0));
  ExpectState(0, QuicMcChannelState::kRetired, 1, kMcReasonRequestedByServer);
}

TEST_F(QuicMulticastControlTest, UnsupportedAlgorithmIsProtocolError) {
  Accept();
  QuicMcAnnounce announce = Announce();
  announce.aead_algorithm = 0x1302;
  control_.OnAnnounce(announce, At(0));
  ASSERT_EQ(visitor_.errors.size(), 1u);
  EXPECT_EQ(control_.session_state(), SessionState::kRefused);
}

TEST_F(QuicMulticastControlTest, ChangedAnnounceIsProtocolError) {
  Accept();
  control_.OnAnnounce(Announce(), At(0));
  control_.OnAnnounce(Announce(), At(1));  // Identical: ignored.
  EXPECT_TRUE(visitor_.errors.empty());
  QuicMcAnnounce changed = Announce();
  changed.port = 5003;
  control_.OnAnnounce(changed, At(2));
  EXPECT_EQ(visitor_.errors.size(), 1u);
}

TEST_F(QuicMulticastControlTest, KeySequences) {
  Joined();
  control_.OnKey(Key(1), At(1));  // Repeat: ignored.
  control_.OnKey(Key(0, 'z'), At(1));  // Older: ignored.
  EXPECT_TRUE(visitor_.errors.empty());
  control_.OnKey(Key(2, 'n'), At(2));
  EXPECT_EQ(visitor_.key_updates, std::vector<uint64_t>{2});
  control_.OnKey(Key(2, 'x'), At(3));  // Same sequence, other secret.
  EXPECT_EQ(visitor_.errors.size(), 1u);
}

TEST_F(QuicMulticastControlTest, ExtraChannelsAreCapped) {
  QuicMcClientParams params = QuicMcDefaultClientParams();
  params.limits.max_channel_ids = 1;
  FakeVisitor visitor;
  QuicMulticastControl control(
      &visitor, std::vector<QuicIpAddress>{Ip("192.0.2.1")}, params);
  control.OnMulticastAccepted(true, At(0));
  control.OnAnnounce(Announce(), At(0));
  control.OnAnnounce(Announce("192.0.2.1", "second"), At(0));
  EXPECT_TRUE(control.channel_state(kChannel).has_value());
  EXPECT_FALSE(control.channel_state("second").has_value());
  control.OnJoin(Join(1, 0, 1, "second"), At(0));
  ASSERT_EQ(visitor.states.size(), 1u);
  EXPECT_EQ(visitor.states[0].reason_code, kMcReasonLimitViolation);
}

// A17: a JOIN the visitor leaves pending sends nothing and arms no deadline,
// so it never spends an MC_LIMITS bump.
TEST_F(QuicMulticastControlTest, PendingJoinSendsNothing) {
  Pending();
  EXPECT_EQ(visitor_.joins, std::vector<std::string>{kChannel});
  EXPECT_TRUE(visitor_.states.empty());
  EXPECT_FALSE(control_.NextDeadline().has_value());
  control_.OnAlarm(At(5000));
  EXPECT_EQ(visitor_.limits.size(), 1u);
}

TEST_F(QuicMulticastControlTest, CompleteJoinJoinedSendsJoined) {
  Pending();
  control_.CompleteJoin(kChannel, JoinResult::kJoined, At(2500));
  ExpectState(0, QuicMcChannelState::kJoined, 1, kMcReasonRequestedByServer);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kJoined);
  // Only a pending channel takes an answer.
  control_.CompleteJoin(kChannel, JoinResult::kFailed, At(2600));
  EXPECT_EQ(visitor_.states.size(), 1u);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kJoined);
}

TEST_F(QuicMulticastControlTest, CompleteJoinBlockedSendsAdministrativeBlock) {
  Pending();
  control_.CompleteJoin(kChannel, JoinResult::kBlocked, At(2500));
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonAdministrativeBlock);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kDeclined);
  EXPECT_FALSE(control_.NextDeadline().has_value());  // Permanent.
}

TEST_F(QuicMulticastControlTest, CompleteJoinFailedSendsUnspecifiedOther) {
  Pending();
  control_.CompleteJoin(kChannel, JoinResult::kFailed, At(2500));
  ExpectState(0, QuicMcChannelState::kDeclinedJoin, 1,
              kMcReasonUnspecifiedOther);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kDeclined);
  EXPECT_FALSE(control_.NextDeadline().has_value());  // Permanent.
}

TEST_F(QuicMulticastControlTest, JoinWhilePendingIsIgnored) {
  Pending();
  control_.OnJoin(Join(1, 1, 1), At(10));
  EXPECT_EQ(visitor_.joins.size(), 1u);
  EXPECT_TRUE(visitor_.states.empty());
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kJoinPending);
}

// LEAVE cancels a pending JOIN at once, whatever its After Packet Number: a
// pending channel gets no packets. LeaveChannel lets the embedder drop its
// wait, and a late CompleteJoin sends nothing.
TEST_F(QuicMulticastControlTest, LeaveWhilePendingCancels) {
  Pending();
  QuicMcLeave leave;
  leave.channel_id = kChannel;
  leave.state_sequence = 1;
  leave.after_packet_number = 7;
  control_.OnLeave(leave, At(10));
  EXPECT_EQ(visitor_.leaves, std::vector<std::string>{kChannel});
  ExpectState(0, QuicMcChannelState::kLeft, 1, kMcReasonRequestedByServer);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kLeft);
  control_.CompleteJoin(kChannel, JoinResult::kJoined, At(20));
  EXPECT_EQ(visitor_.states.size(), 1u);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kLeft);
}

TEST_F(QuicMulticastControlTest, RetireWhilePendingCancels) {
  Pending();
  QuicMcRetire retire;
  retire.channel_id = kChannel;
  retire.after_packet_number = 4;
  control_.OnRetire(retire, At(10));
  EXPECT_EQ(visitor_.leaves, std::vector<std::string>{kChannel});
  ASSERT_EQ(visitor_.states.size(), 1u);  // RETIRED, no separate LEFT.
  ExpectState(0, QuicMcChannelState::kRetired, 1, kMcReasonRequestedByServer);
  EXPECT_FALSE(control_.channel_state(kChannel).has_value());
  control_.CompleteJoin(kChannel, JoinResult::kJoined, At(20));
  EXPECT_EQ(visitor_.states.size(), 1u);
}

// A pending channel counts as joined: while it waits, a JOIN that would take
// the aggregate rate past max_rate_kibps gets LIMIT_VIOLATION (0x16), and so
// does one for a channel past max_channel_ids.
TEST_F(QuicMulticastControlTest, PendingCountsTowardLimits) {
  QuicMcClientParams params = QuicMcDefaultClientParams();
  params.limits.max_channel_ids = 2;
  params.limits.max_rate_kibps = 1500;
  FakeVisitor visitor;
  visitor.join_result = JoinResult::kPending;
  QuicMulticastControl control(
      &visitor, std::vector<QuicIpAddress>{Ip("192.0.2.1")}, params);
  control.OnMulticastAccepted(true, At(0));
  for (const char* id : {kChannel, "second"}) {
    control.OnAnnounce(Announce("192.0.2.1", id), At(0));  // 1000 Kibps.
    control.OnKey(Key(1, 'k', id), At(0));
  }
  control.OnJoin(Join(1, 0, 1), At(0));
  ASSERT_EQ(control.channel_state(kChannel), ChannelState::kJoinPending);
  control.OnJoin(Join(1, 0, 1, "second"), At(0));
  control.OnJoin(Join(1, 0, 1, "third"), At(0));
  EXPECT_EQ(visitor.joins, std::vector<std::string>{kChannel});
  ASSERT_EQ(visitor.states.size(), 2u);
  EXPECT_EQ(visitor.states[0].channel_id, "second");
  EXPECT_EQ(visitor.states[0].reason_code, kMcReasonLimitViolation);
  EXPECT_EQ(visitor.states[1].channel_id, "third");
  EXPECT_EQ(visitor.states[1].reason_code, kMcReasonLimitViolation);
}

// CRITIQUE I5: the wait can last the gate's 60 s fetch timeout, so a key
// rotated meanwhile must reach the channel built with the JOIN's key.
TEST_F(QuicMulticastControlTest, KeyRotationWhilePendingReachesChannel) {
  Pending();
  control_.OnKey(Key(2, 'n'), At(10));
  EXPECT_EQ(visitor_.key_updates, std::vector<uint64_t>{2});
  control_.CompleteJoin(kChannel, JoinResult::kJoined, At(20));
  ExpectState(0, QuicMcChannelState::kJoined, 1, kMcReasonRequestedByServer);
}

// -08 section 10.9: LEFT carries why the embedder lost a joined channel, and
// Visitor::LeaveChannel is not called. The server may JOIN it again.
TEST_F(QuicMulticastControlTest, ChannelLostSendsLeftWithReason) {
  Joined();
  control_.OnChannelLost(kChannel, kMcReasonAdministrativeBlock, At(10));
  ExpectState(1, QuicMcChannelState::kLeft, 2, kMcReasonAdministrativeBlock);
  EXPECT_EQ(control_.channel_state(kChannel), ChannelState::kLeft);

  control_.OnJoin(Join(1, 2, 1), At(20));
  ExpectState(2, QuicMcChannelState::kJoined, 3, kMcReasonRequestedByServer);
  control_.OnChannelLost(kChannel, kMcReasonMaxRateExceeded, At(30));
  ExpectState(3, QuicMcChannelState::kLeft, 4, kMcReasonMaxRateExceeded);

  control_.OnJoin(Join(1, 4, 1), At(40));
  control_.OnChannelLost(kChannel, kMcReasonUnspecifiedOther, At(50));
  ExpectState(5, QuicMcChannelState::kLeft, 6, kMcReasonUnspecifiedOther);

  control_.OnChannelLost(kChannel, kMcReasonUnspecifiedOther, At(60));
  EXPECT_EQ(visitor_.states.size(), 6u);  // Not joined: ignored.
  EXPECT_EQ(visitor_.joins.size(), 3u);
  EXPECT_TRUE(visitor_.leaves.empty());
}

// With no allowlist the visitor decides every source: it joins one that the
// lab list would block, and its kBlocked is 0x2, permanent.
TEST_F(QuicMulticastControlTest, NoAllowlistLeavesSourceToDelegate) {
  FakeVisitor visitor;
  QuicMulticastControl control(&visitor, std::nullopt);
  control.OnMulticastAccepted(true, At(0));
  control.OnAnnounce(Announce("198.51.100.7"), At(0));
  control.OnKey(Key(1), At(0));
  control.OnJoin(Join(1, 0, 1), At(0));
  EXPECT_EQ(control.channel_state(kChannel), ChannelState::kJoined);

  visitor.join_result = JoinResult::kBlocked;
  control.OnAnnounce(Announce("198.51.100.8", "second"), At(0));
  control.OnKey(Key(1, 'k', "second"), At(0));
  control.OnJoin(Join(1, 0, 1, "second"), At(0));
  EXPECT_EQ(visitor.joins, (std::vector<std::string>{kChannel, "second"}));
  ASSERT_EQ(visitor.states.size(), 2u);
  EXPECT_EQ(visitor.states[1].state, QuicMcChannelState::kDeclinedJoin);
  EXPECT_EQ(visitor.states[1].reason_code, kMcReasonAdministrativeBlock);
  EXPECT_FALSE(control.NextDeadline().has_value());
}

}  // namespace
}  // namespace test
}  // namespace quic
