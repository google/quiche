// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_ping_manager.h"

#include "quiche/quic/core/quic_one_block_arena.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {

class QuicPingManagerPeer {
 public:
  static QuicAlarm* GetAlarm(QuicPingManager* manager) {
    return manager->alarm_.get();
  }

  static void SetPerspective(QuicPingManager* manager,
                             Perspective perspective) {
    manager->perspective_ = perspective;
  }
};

namespace {

const bool kShouldKeepAlive = true;
const bool kHasInflightPackets = true;

class MockDelegate : public QuicPingManager::Delegate {
 public:
  MOCK_METHOD(void, OnKeepAliveTimeout, (), (override));
  MOCK_METHOD(void, OnRetransmissibleOnWireTimeout, (), (override));
};

class QuicPingManagerTest : public QuicTest {
 public:
  QuicPingManagerTest()
      : manager_(Perspective::IS_CLIENT, &delegate_, &arena_, &alarm_factory_,
                 /*context=*/nullptr),
        alarm_(static_cast<MockAlarmFactory::TestAlarm*>(
            QuicPingManagerPeer::GetAlarm(&manager_))) {
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  }

 protected:
  testing::StrictMock<MockDelegate> delegate_;
  MockClock clock_;
  QuicConnectionArena arena_;
  MockAlarmFactory alarm_factory_;
  QuicPingManager manager_;
  MockAlarmFactory::TestAlarm* alarm_;
};

TEST_F(QuicPingManagerTest, KeepAliveTimeout) {
  EXPECT_FALSE(alarm_->IsSet());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  // Set alarm with in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  // Reset alarm with no in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  // Verify the deadline is set slightly less than 15 seconds in the future,
  // because of the 1s alarm granularity.
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs) -
                QuicTime::Delta::FromMilliseconds(5),
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(kPingTimeoutSecs));
  EXPECT_CALL(delegate_, OnKeepAliveTimeout());
  alarm_->Fire();
  EXPECT_FALSE(alarm_->IsSet());
  // Reset alarm with in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());

  // Verify alarm is not armed if !kShouldKeepAlive.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  manager_.SetAlarm(clock_.ApproximateNow(), !kShouldKeepAlive,
                    kHasInflightPackets);
  EXPECT_FALSE(alarm_->IsSet());
}

TEST_F(QuicPingManagerTest, CustomizedKeepAliveTimeout) {
  EXPECT_FALSE(alarm_->IsSet());

  // Set customized keep-alive timeout.
  manager_.set_keep_alive_timeout(QuicTime::Delta::FromSeconds(10));

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  // Set alarm with in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(10),
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  // Set alarm with no in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  // The deadline is set slightly less than 10 seconds in the future, because
  // of the 1s alarm granularity.
  EXPECT_EQ(
      QuicTime::Delta::FromSeconds(10) - QuicTime::Delta::FromMilliseconds(5),
      alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(10));
  EXPECT_CALL(delegate_, OnKeepAliveTimeout());
  alarm_->Fire();
  EXPECT_FALSE(alarm_->IsSet());
  // Reset alarm with in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());

  // Verify alarm is not armed if !kShouldKeepAlive.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  manager_.SetAlarm(clock_.ApproximateNow(), !kShouldKeepAlive,
                    kHasInflightPackets);
  EXPECT_FALSE(alarm_->IsSet());
}

TEST_F(QuicPingManagerTest, RetransmissibleOnWireTimeout) {
  const QuicTime::Delta kRetransmissibleOnWireTimeout =
      QuicTime::Delta::FromMilliseconds(50);
  manager_.set_initial_retransmissible_on_wire_timeout(
      kRetransmissibleOnWireTimeout);

  EXPECT_FALSE(alarm_->IsSet());

  // Set alarm with in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  // Verify alarm is in keep-alive mode.
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  // Set alarm with no in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  // Verify alarm is in retransmissible-on-wire mode.
  EXPECT_EQ(kRetransmissibleOnWireTimeout,
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(kRetransmissibleOnWireTimeout);
  EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
  alarm_->Fire();
  EXPECT_FALSE(alarm_->IsSet());
  // Reset alarm with in flight packets.
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  // Verify the alarm is in keep-alive mode.
  ASSERT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());
}

TEST_F(QuicPingManagerTest, RetransmissibleOnWireTimeoutExponentiallyBackOff) {
  const int kMaxAggressiveRetransmissibleOnWireCount = 5;
  SetQuicFlag(quic_max_aggressive_retransmissible_on_wire_ping_count,
              kMaxAggressiveRetransmissibleOnWireCount);
  const QuicTime::Delta initial_retransmissible_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  manager_.set_initial_retransmissible_on_wire_timeout(
      initial_retransmissible_on_wire_timeout);

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(alarm_->IsSet());
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  // Verify alarm is in keep-alive mode.
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());

  // Verify no exponential backoff on the first few retransmissible on wire
  // timeouts.
  for (int i = 0; i <= kMaxAggressiveRetransmissibleOnWireCount; ++i) {
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    // Reset alarm with no in flight packets.
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      !kHasInflightPackets);
    EXPECT_TRUE(alarm_->IsSet());
    // Verify alarm is in retransmissible-on-wire mode.
    EXPECT_EQ(initial_retransmissible_on_wire_timeout,
              alarm_->deadline() - clock_.ApproximateNow());
    clock_.AdvanceTime(initial_retransmissible_on_wire_timeout);
    EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
    alarm_->Fire();
    EXPECT_FALSE(alarm_->IsSet());
    // Reset alarm with in flight packets.
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      kHasInflightPackets);
  }

  QuicTime::Delta retransmissible_on_wire_timeout =
      initial_retransmissible_on_wire_timeout;

  // Verify subsequent retransmissible-on-wire timeout is exponentially backed
  // off.
  while (retransmissible_on_wire_timeout * 2 <
         QuicTime::Delta::FromSeconds(kPingTimeoutSecs)) {
    retransmissible_on_wire_timeout = retransmissible_on_wire_timeout * 2;
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      !kHasInflightPackets);
    EXPECT_TRUE(alarm_->IsSet());
    EXPECT_EQ(retransmissible_on_wire_timeout,
              alarm_->deadline() - clock_.ApproximateNow());

    clock_.AdvanceTime(retransmissible_on_wire_timeout);
    EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
    alarm_->Fire();
    EXPECT_FALSE(alarm_->IsSet());
    // Reset alarm with in flight packets.
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      kHasInflightPackets);
  }

  // Verify alarm is in keep-alive mode.
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  // Reset alarm with no in flight packets
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  // Verify alarm is in keep-alive mode because retransmissible-on-wire deadline
  // is later.
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs) -
                QuicTime::Delta::FromMilliseconds(5),
            alarm_->deadline() - clock_.ApproximateNow());
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(kPingTimeoutSecs) -
                     QuicTime::Delta::FromMilliseconds(5));
  EXPECT_CALL(delegate_, OnKeepAliveTimeout());
  alarm_->Fire();
  EXPECT_FALSE(alarm_->IsSet());
}

TEST_F(QuicPingManagerTest,
       ResetRetransmissibleOnWireTimeoutExponentiallyBackOff) {
  const int kMaxAggressiveRetransmissibleOnWireCount = 3;
  SetQuicFlag(quic_max_aggressive_retransmissible_on_wire_ping_count,
              kMaxAggressiveRetransmissibleOnWireCount);
  const QuicTime::Delta initial_retransmissible_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  manager_.set_initial_retransmissible_on_wire_timeout(
      initial_retransmissible_on_wire_timeout);

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_FALSE(alarm_->IsSet());
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);
  // Verify alarm is in keep-alive mode.
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  // Verify alarm is in retransmissible-on-wire mode.
  EXPECT_EQ(initial_retransmissible_on_wire_timeout,
            alarm_->deadline() - clock_.ApproximateNow());

  EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
  clock_.AdvanceTime(initial_retransmissible_on_wire_timeout);
  alarm_->Fire();

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(initial_retransmissible_on_wire_timeout,
            alarm_->deadline() - clock_.ApproximateNow());

  manager_.reset_consecutive_retransmissible_on_wire_count();
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_EQ(initial_retransmissible_on_wire_timeout,
            alarm_->deadline() - clock_.ApproximateNow());
  EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
  clock_.AdvanceTime(initial_retransmissible_on_wire_timeout);
  alarm_->Fire();

  for (int i = 0; i < kMaxAggressiveRetransmissibleOnWireCount; i++) {
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      !kHasInflightPackets);
    EXPECT_TRUE(alarm_->IsSet());
    EXPECT_EQ(initial_retransmissible_on_wire_timeout,
              alarm_->deadline() - clock_.ApproximateNow());
    clock_.AdvanceTime(initial_retransmissible_on_wire_timeout);
    EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
    alarm_->Fire();
    // Reset alarm with in flight packets.
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      kHasInflightPackets);
    // Advance 5ms to receive next packet.
    clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  }

  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(initial_retransmissible_on_wire_timeout * 2,
            alarm_->deadline() - clock_.ApproximateNow());

  clock_.AdvanceTime(2 * initial_retransmissible_on_wire_timeout);
  EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
  alarm_->Fire();

  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  manager_.reset_consecutive_retransmissible_on_wire_count();
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(initial_retransmissible_on_wire_timeout,
            alarm_->deadline() - clock_.ApproximateNow());
}

TEST_F(QuicPingManagerTest, RetransmissibleOnWireLimit) {
  static constexpr int kMaxRetransmissibleOnWirePingCount = 3;
  SetQuicFlag(quic_max_retransmissible_on_wire_ping_count,
              kMaxRetransmissibleOnWirePingCount);
  static constexpr QuicTime::Delta initial_retransmissible_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  static constexpr QuicTime::Delta kShortDelay =
      QuicTime::Delta::FromMilliseconds(5);
  ASSERT_LT(kShortDelay * 10, initial_retransmissible_on_wire_timeout);
  manager_.set_initial_retransmissible_on_wire_timeout(
      initial_retransmissible_on_wire_timeout);

  clock_.AdvanceTime(kShortDelay);
  EXPECT_FALSE(alarm_->IsSet());
  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    kHasInflightPackets);

  EXPECT_TRUE(alarm_->IsSet());
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());

  for (int i = 0; i <= kMaxRetransmissibleOnWirePingCount; i++) {
    clock_.AdvanceTime(kShortDelay);
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      !kHasInflightPackets);
    EXPECT_TRUE(alarm_->IsSet());
    EXPECT_EQ(initial_retransmissible_on_wire_timeout,
              alarm_->deadline() - clock_.ApproximateNow());
    clock_.AdvanceTime(initial_retransmissible_on_wire_timeout);
    EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
    alarm_->Fire();
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      kHasInflightPackets);
  }

  manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                    !kHasInflightPackets);
  EXPECT_TRUE(alarm_->IsSet());
  // Verify alarm is in keep-alive mode.
  EXPECT_EQ(QuicTime::Delta::FromSeconds(kPingTimeoutSecs),
            alarm_->deadline() - clock_.ApproximateNow());
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(kPingTimeoutSecs));
  EXPECT_CALL(delegate_, OnKeepAliveTimeout());
  alarm_->Fire();
  EXPECT_FALSE(alarm_->IsSet());
}

TEST_F(QuicPingManagerTest, MaxRetransmissibleOnWireDelayShift) {
  QuicPingManagerPeer::SetPerspective(&manager_, Perspective::IS_SERVER);
  const int kMaxAggressiveRetransmissibleOnWireCount = 3;
  SetQuicFlag(quic_max_aggressive_retransmissible_on_wire_ping_count,
              kMaxAggressiveRetransmissibleOnWireCount);
  const QuicTime::Delta initial_retransmissible_on_wire_timeout =
      QuicTime::Delta::FromMilliseconds(200);
  manager_.set_initial_retransmissible_on_wire_timeout(
      initial_retransmissible_on_wire_timeout);

  for (int i = 0; i <= kMaxAggressiveRetransmissibleOnWireCount; i++) {
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      !kHasInflightPackets);
    EXPECT_TRUE(alarm_->IsSet());
    EXPECT_EQ(initial_retransmissible_on_wire_timeout,
              alarm_->deadline() - clock_.ApproximateNow());
    clock_.AdvanceTime(initial_retransmissible_on_wire_timeout);
    EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
    alarm_->Fire();
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      kHasInflightPackets);
  }
  for (int i = 1; i <= 20; ++i) {
    manager_.SetAlarm(clock_.ApproximateNow(), kShouldKeepAlive,
                      !kHasInflightPackets);
    EXPECT_TRUE(alarm_->IsSet());
    if (i <= 10) {
      EXPECT_EQ(initial_retransmissible_on_wire_timeout * (1 << i),
                alarm_->deadline() - clock_.ApproximateNow());
    } else {
      // Verify shift is capped.
      EXPECT_EQ(initial_retransmissible_on_wire_timeout * (1 << 10),
                alarm_->deadline() - clock_.ApproximateNow());
    }
    clock_.AdvanceTime(alarm_->deadline() - clock_.ApproximateNow());
    EXPECT_CALL(delegate_, OnRetransmissibleOnWireTimeout());
    alarm_->Fire();
  }
}

}  // namespace

}  // namespace test
}  // namespace quic
