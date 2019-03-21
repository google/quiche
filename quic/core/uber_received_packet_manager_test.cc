// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/uber_received_packet_manager.h"

#include "net/third_party/quiche/src/quic/core/congestion_control/rtt_stats.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_protocol.h"
#include "net/third_party/quiche/src/quic/core/quic_connection_stats.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/test_tools/mock_clock.h"

namespace quic {
namespace test {

class UberReceivedPacketManagerPeer {
 public:
  static void SetAckMode(UberReceivedPacketManager* manager, AckMode ack_mode) {
    manager->received_packet_manager_.ack_mode_ = ack_mode;
  }

  static void SetFastAckAfterQuiescence(UberReceivedPacketManager* manager,
                                        bool fast_ack_after_quiescence) {
    manager->received_packet_manager_.fast_ack_after_quiescence_ =
        fast_ack_after_quiescence;
  }

  static void SetAckDecimationDelay(UberReceivedPacketManager* manager,
                                    float ack_decimation_delay) {
    manager->received_packet_manager_.ack_decimation_delay_ =
        ack_decimation_delay;
  }
};

namespace {

const bool kInstigateAck = true;
const QuicTime::Delta kMinRttMs = QuicTime::Delta::FromMilliseconds(40);
const QuicTime::Delta kDelayedAckTime =
    QuicTime::Delta::FromMilliseconds(kDefaultDelayedAckTimeMs);

class UberReceivedPacketManagerTest : public QuicTest {
 protected:
  UberReceivedPacketManagerTest() {
    SetQuicReloadableFlag(quic_deprecate_ack_bundling_mode, true);
    SetQuicReloadableFlag(quic_rpm_decides_when_to_send_acks, true);
    manager_ = QuicMakeUnique<UberReceivedPacketManager>(&stats_);
    clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
    rtt_stats_.UpdateRtt(kMinRttMs, QuicTime::Delta::Zero(), QuicTime::Zero());
    manager_->set_save_timestamps(true);
  }

  void RecordPacketReceipt(uint64_t packet_number) {
    RecordPacketReceipt(packet_number, QuicTime::Zero());
  }

  void RecordPacketReceipt(uint64_t packet_number, QuicTime receipt_time) {
    QuicPacketHeader header;
    header.packet_number = QuicPacketNumber(packet_number);
    manager_->RecordPacketReceived(header, receipt_time);
  }

  bool HasPendingAck() { return manager_->GetAckTimeout().IsInitialized(); }

  void MaybeUpdateAckTimeout(bool should_last_packet_instigate_acks,
                             uint64_t last_received_packet_number) {
    manager_->MaybeUpdateAckTimeout(
        should_last_packet_instigate_acks,
        QuicPacketNumber(last_received_packet_number), clock_.ApproximateNow(),
        clock_.ApproximateNow(), &rtt_stats_, kDelayedAckTime);
  }

  void CheckAckTimeout(QuicTime time) {
    DCHECK(HasPendingAck() && manager_->GetAckTimeout() == time);
    if (time <= clock_.ApproximateNow()) {
      // ACK timeout expires, send an ACK.
      manager_->ResetAckStates();
      DCHECK(!HasPendingAck());
    }
  }

  MockClock clock_;
  RttStats rtt_stats_;
  QuicConnectionStats stats_;
  std::unique_ptr<UberReceivedPacketManager> manager_;
};

TEST_F(UberReceivedPacketManagerTest, DontWaitForPacketsBefore) {
  QuicPacketHeader header;
  header.packet_number = QuicPacketNumber(2u);
  manager_->RecordPacketReceived(header, QuicTime::Zero());
  header.packet_number = QuicPacketNumber(7u);
  manager_->RecordPacketReceived(header, QuicTime::Zero());
  EXPECT_TRUE(manager_->IsAwaitingPacket(QuicPacketNumber(3u)));
  EXPECT_TRUE(manager_->IsAwaitingPacket(QuicPacketNumber(6u)));
  manager_->DontWaitForPacketsBefore(QuicPacketNumber(4));
  EXPECT_FALSE(manager_->IsAwaitingPacket(QuicPacketNumber(3u)));
  EXPECT_TRUE(manager_->IsAwaitingPacket(QuicPacketNumber(6u)));
}

TEST_F(UberReceivedPacketManagerTest, GetUpdatedAckFrame) {
  QuicPacketHeader header;
  header.packet_number = QuicPacketNumber(2u);
  QuicTime two_ms = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(2);
  EXPECT_FALSE(manager_->AckFrameUpdated());
  manager_->RecordPacketReceived(header, two_ms);
  EXPECT_TRUE(manager_->AckFrameUpdated());

  QuicFrame ack = manager_->GetUpdatedAckFrame(QuicTime::Zero());
  manager_->ResetAckStates();
  EXPECT_FALSE(manager_->AckFrameUpdated());
  // When UpdateReceivedPacketInfo with a time earlier than the time of the
  // largest observed packet, make sure that the delta is 0, not negative.
  EXPECT_EQ(QuicTime::Delta::Zero(), ack.ack_frame->ack_delay_time);
  EXPECT_EQ(1u, ack.ack_frame->received_packet_times.size());

  QuicTime four_ms = QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(4);
  ack = manager_->GetUpdatedAckFrame(four_ms);
  manager_->ResetAckStates();
  EXPECT_FALSE(manager_->AckFrameUpdated());
  // When UpdateReceivedPacketInfo after not having received a new packet,
  // the delta should still be accurate.
  EXPECT_EQ(QuicTime::Delta::FromMilliseconds(2),
            ack.ack_frame->ack_delay_time);
  // And received packet times won't have change.
  EXPECT_EQ(1u, ack.ack_frame->received_packet_times.size());

  header.packet_number = QuicPacketNumber(999u);
  manager_->RecordPacketReceived(header, two_ms);
  header.packet_number = QuicPacketNumber(4u);
  manager_->RecordPacketReceived(header, two_ms);
  header.packet_number = QuicPacketNumber(1000u);
  manager_->RecordPacketReceived(header, two_ms);
  EXPECT_TRUE(manager_->AckFrameUpdated());
  ack = manager_->GetUpdatedAckFrame(two_ms);
  manager_->ResetAckStates();
  EXPECT_FALSE(manager_->AckFrameUpdated());
  // UpdateReceivedPacketInfo should discard any times which can't be
  // expressed on the wire.
  EXPECT_EQ(2u, ack.ack_frame->received_packet_times.size());
}

TEST_F(UberReceivedPacketManagerTest, UpdateReceivedConnectionStats) {
  EXPECT_FALSE(manager_->AckFrameUpdated());
  RecordPacketReceipt(1);
  EXPECT_TRUE(manager_->AckFrameUpdated());
  RecordPacketReceipt(6);
  RecordPacketReceipt(2,
                      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1));

  EXPECT_EQ(4u, stats_.max_sequence_reordering);
  EXPECT_EQ(1000, stats_.max_time_reordering_us);
  EXPECT_EQ(1u, stats_.packets_reordered);
}

TEST_F(UberReceivedPacketManagerTest, LimitAckRanges) {
  manager_->set_max_ack_ranges(10);
  EXPECT_FALSE(manager_->AckFrameUpdated());
  for (int i = 0; i < 100; ++i) {
    RecordPacketReceipt(1 + 2 * i);
    EXPECT_TRUE(manager_->AckFrameUpdated());
    manager_->GetUpdatedAckFrame(QuicTime::Zero());
    EXPECT_GE(10u, manager_->ack_frame().packets.NumIntervals());
    EXPECT_EQ(QuicPacketNumber(1u + 2 * i),
              manager_->ack_frame().packets.Max());
    for (int j = 0; j < std::min(10, i + 1); ++j) {
      ASSERT_GE(i, j);
      EXPECT_TRUE(manager_->ack_frame().packets.Contains(
          QuicPacketNumber(1 + (i - j) * 2)));
      if (i > j) {
        EXPECT_FALSE(manager_->ack_frame().packets.Contains(
            QuicPacketNumber((i - j) * 2)));
      }
    }
  }
}

TEST_F(UberReceivedPacketManagerTest, IgnoreOutOfOrderTimestamps) {
  EXPECT_FALSE(manager_->AckFrameUpdated());
  RecordPacketReceipt(1, QuicTime::Zero());
  EXPECT_TRUE(manager_->AckFrameUpdated());
  EXPECT_EQ(1u, manager_->ack_frame().received_packet_times.size());
  RecordPacketReceipt(2,
                      QuicTime::Zero() + QuicTime::Delta::FromMilliseconds(1));
  EXPECT_EQ(2u, manager_->ack_frame().received_packet_times.size());
  RecordPacketReceipt(3, QuicTime::Zero());
  EXPECT_EQ(2u, manager_->ack_frame().received_packet_times.size());
}

TEST_F(UberReceivedPacketManagerTest, OutOfOrderReceiptCausesAckSent) {
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(3, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 3);
  if (GetQuicRestartFlag(quic_enable_accept_random_ipn)) {
    // Delayed ack is scheduled.
    CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
  } else {
    // Should ack immediately since we have missing packets.
    CheckAckTimeout(clock_.ApproximateNow());
  }

  RecordPacketReceipt(2, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 2);
  CheckAckTimeout(clock_.ApproximateNow());

  RecordPacketReceipt(1, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 1);
  // Should ack immediately, since this fills the last hole.
  CheckAckTimeout(clock_.ApproximateNow());

  RecordPacketReceipt(4, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 4);
  // Delayed ack is scheduled.
  CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
}

TEST_F(UberReceivedPacketManagerTest, OutOfOrderAckReceiptCausesNoAck) {
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(2, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(!kInstigateAck, 2);
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(1, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(!kInstigateAck, 1);
  EXPECT_FALSE(HasPendingAck());
}

TEST_F(UberReceivedPacketManagerTest, AckReceiptCausesAckSend) {
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(1, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(!kInstigateAck, 1);
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(2, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(!kInstigateAck, 2);
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(3, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 3);
  // Delayed ack is scheduled.
  CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
  clock_.AdvanceTime(kDelayedAckTime);
  CheckAckTimeout(clock_.ApproximateNow());

  RecordPacketReceipt(4, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(!kInstigateAck, 4);
  EXPECT_FALSE(HasPendingAck());

  RecordPacketReceipt(5, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(!kInstigateAck, 5);
  EXPECT_FALSE(HasPendingAck());
}

TEST_F(UberReceivedPacketManagerTest, AckSentEveryNthPacket) {
  EXPECT_FALSE(HasPendingAck());
  manager_->set_ack_frequency_before_ack_decimation(3);

  // Receives packets 1 - 39.
  for (size_t i = 1; i <= 39; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 3 == 0) {
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }
}

TEST_F(UberReceivedPacketManagerTest, AckDecimationReducesAcks) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(),
                                            ACK_DECIMATION_WITH_REORDERING);

  // Start ack decimation from 10th packet.
  manager_->set_min_received_before_ack_decimation(10);

  // Receives packets 1 - 29.
  for (size_t i = 1; i <= 29; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i <= 10) {
      // For packets 1-10, ack every 2 packets.
      if (i % 2 == 0) {
        CheckAckTimeout(clock_.ApproximateNow());
      } else {
        CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
      }
      continue;
    }
    // ack at 20.
    if (i == 20) {
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kMinRttMs * 0.25);
    }
  }

  // We now receive the 30th packet, and so we send an ack.
  RecordPacketReceipt(30, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 30);
  CheckAckTimeout(clock_.ApproximateNow());
}

TEST_F(UberReceivedPacketManagerTest, SendDelayedAfterQuiescence) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetFastAckAfterQuiescence(manager_.get(),
                                                           true);
  // The beginning of the connection counts as quiescence.
  QuicTime ack_time =
      clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(1);

  RecordPacketReceipt(1, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 1);
  CheckAckTimeout(ack_time);
  // Simulate delayed ack alarm firing.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  CheckAckTimeout(clock_.ApproximateNow());

  // Process another packet immediately after sending the ack and expect the
  // ack timeout to be set delayed ack time in the future.
  ack_time = clock_.ApproximateNow() + kDelayedAckTime;
  RecordPacketReceipt(2, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 2);
  CheckAckTimeout(ack_time);
  // Simulate delayed ack alarm firing.
  clock_.AdvanceTime(kDelayedAckTime);
  CheckAckTimeout(clock_.ApproximateNow());

  // Wait 1 second and enesure the ack timeout is set to 1ms in the future.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  ack_time = clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(1);
  RecordPacketReceipt(3, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 3);
  CheckAckTimeout(ack_time);
}

TEST_F(UberReceivedPacketManagerTest, SendDelayedAckDecimation) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(), ACK_DECIMATION);
  // The ack time should be based on min_rtt * 1/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.25;

  // Process all the packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  // The 10th received packet causes an ack to be sent.
  for (uint64_t i = 1; i < 10; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + i);
  }
  CheckAckTimeout(clock_.ApproximateNow());
}

TEST_F(UberReceivedPacketManagerTest,
       SendDelayedAckAckDecimationAfterQuiescence) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(), ACK_DECIMATION);
  UberReceivedPacketManagerPeer::SetFastAckAfterQuiescence(manager_.get(),
                                                           true);
  // The beginning of the connection counts as quiescence.
  QuicTime ack_time =
      clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(1);
  RecordPacketReceipt(1, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 1);
  CheckAckTimeout(ack_time);
  // Simulate delayed ack alarm firing.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  CheckAckTimeout(clock_.ApproximateNow());

  // Process another packet immedately after sending the ack and expect the
  // ack timeout to be set delayed ack time in the future.
  ack_time = clock_.ApproximateNow() + kDelayedAckTime;
  RecordPacketReceipt(2, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 2);
  CheckAckTimeout(ack_time);
  // Simulate delayed ack alarm firing.
  clock_.AdvanceTime(kDelayedAckTime);
  CheckAckTimeout(clock_.ApproximateNow());

  // Wait 1 second and enesure the ack timeout is set to 1ms in the future.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  ack_time = clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(1);
  RecordPacketReceipt(3, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, 3);
  CheckAckTimeout(ack_time);
  // Process enough packets to get into ack decimation behavior.
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  ack_time = clock_.ApproximateNow() + kMinRttMs * 0.25;
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 4; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }
  EXPECT_FALSE(HasPendingAck());
  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  // The 10th received packet causes an ack to be sent.
  for (uint64_t i = 1; i < 10; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + i);
  }
  CheckAckTimeout(clock_.ApproximateNow());

  // Wait 1 second and enesure the ack timeout is set to 1ms in the future.
  clock_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
  ack_time = clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(1);
  RecordPacketReceipt(kFirstDecimatedPacket + 10, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 10);
  CheckAckTimeout(ack_time);
}

TEST_F(UberReceivedPacketManagerTest,
       SendDelayedAckDecimationUnlimitedAggregation) {
  EXPECT_FALSE(HasPendingAck());
  QuicConfig config;
  QuicTagVector connection_options;
  connection_options.push_back(kACKD);
  // No limit on the number of packets received before sending an ack.
  connection_options.push_back(kAKDU);
  config.SetConnectionOptionsToSend(connection_options);
  manager_->SetFromConfig(config, Perspective::IS_CLIENT);

  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.25;

  // Process all the initial packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  // 18 packets will not cause an ack to be sent.  19 will because when
  // stop waiting frames are in use, we ack every 20 packets no matter what.
  for (int i = 1; i <= 18; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + i);
  }
  CheckAckTimeout(ack_time);
}

TEST_F(UberReceivedPacketManagerTest, SendDelayedAckDecimationEighthRtt) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(), ACK_DECIMATION);
  UberReceivedPacketManagerPeer::SetAckDecimationDelay(manager_.get(), 0.125);

  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.125;

  // Process all the packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  // The 10th received packet causes an ack to be sent.
  for (uint64_t i = 1; i < 10; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + i);
  }
  CheckAckTimeout(clock_.ApproximateNow());
}

TEST_F(UberReceivedPacketManagerTest, SendDelayedAckDecimationWithReordering) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(),
                                            ACK_DECIMATION_WITH_REORDERING);

  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.25;
  // Process all the packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  // Receive one packet out of order and then the rest in order.
  // The loop leaves a one packet gap between acks sent to simulate some loss.
  for (int j = 0; j < 3; ++j) {
    // Process packet 10 first and ensure the timeout is one eighth min_rtt.
    RecordPacketReceipt(kFirstDecimatedPacket + 9 + (j * 11),
                        clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 9 + (j * 11));
    ack_time = clock_.ApproximateNow() + QuicTime::Delta::FromMilliseconds(5);
    CheckAckTimeout(ack_time);

    // The 10th received packet causes an ack to be sent.
    for (int i = 0; i < 9; ++i) {
      RecordPacketReceipt(kFirstDecimatedPacket + i + (j * 11),
                          clock_.ApproximateNow());
      MaybeUpdateAckTimeout(kInstigateAck,
                            kFirstDecimatedPacket + i + (j * 11));
    }
    CheckAckTimeout(clock_.ApproximateNow());
  }
}

TEST_F(UberReceivedPacketManagerTest,
       SendDelayedAckDecimationWithLargeReordering) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(),
                                            ACK_DECIMATION_WITH_REORDERING);
  // The ack time should be based on min_rtt/4, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.25;

  // Process all the packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  RecordPacketReceipt(kFirstDecimatedPacket + 19, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 19);
  ack_time = clock_.ApproximateNow() + kMinRttMs * 0.125;
  CheckAckTimeout(ack_time);

  // The 10th received packet causes an ack to be sent.
  for (int i = 1; i < 9; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + i);
  }
  CheckAckTimeout(clock_.ApproximateNow());

  // The next packet received in order will cause an immediate ack, because it
  // fills a hole.
  RecordPacketReceipt(kFirstDecimatedPacket + 10, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 10);
  CheckAckTimeout(clock_.ApproximateNow());
}

TEST_F(UberReceivedPacketManagerTest,
       SendDelayedAckDecimationWithReorderingEighthRtt) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(),
                                            ACK_DECIMATION_WITH_REORDERING);
  UberReceivedPacketManagerPeer::SetAckDecimationDelay(manager_.get(), 0.125);
  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.125;

  // Process all the packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  // Process packet 10 first and ensure the timeout is one eighth min_rtt.
  RecordPacketReceipt(kFirstDecimatedPacket + 9, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 9);
  CheckAckTimeout(ack_time);

  // The 10th received packet causes an ack to be sent.
  for (int i = 1; i < 9; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck + i, kFirstDecimatedPacket);
  }
  CheckAckTimeout(clock_.ApproximateNow());
}

TEST_F(UberReceivedPacketManagerTest,
       SendDelayedAckDecimationWithLargeReorderingEighthRtt) {
  EXPECT_FALSE(HasPendingAck());
  UberReceivedPacketManagerPeer::SetAckMode(manager_.get(),
                                            ACK_DECIMATION_WITH_REORDERING);
  UberReceivedPacketManagerPeer::SetAckDecimationDelay(manager_.get(), 0.125);

  // The ack time should be based on min_rtt/8, since it's less than the
  // default delayed ack time.
  QuicTime ack_time = clock_.ApproximateNow() + kMinRttMs * 0.125;
  // Process all the packets in order so there aren't missing packets.
  uint64_t kFirstDecimatedPacket = 101;
  for (uint64_t i = 1; i < kFirstDecimatedPacket; ++i) {
    RecordPacketReceipt(i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, i);
    if (i % 2 == 0) {
      // Ack every 2 packets by default.
      CheckAckTimeout(clock_.ApproximateNow());
    } else {
      CheckAckTimeout(clock_.ApproximateNow() + kDelayedAckTime);
    }
  }

  RecordPacketReceipt(kFirstDecimatedPacket, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket);
  CheckAckTimeout(ack_time);

  RecordPacketReceipt(kFirstDecimatedPacket + 19, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 19);
  CheckAckTimeout(ack_time);

  // The 10th received packet causes an ack to be sent.
  for (int i = 1; i < 9; ++i) {
    RecordPacketReceipt(kFirstDecimatedPacket + i, clock_.ApproximateNow());
    MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + i);
  }
  CheckAckTimeout(clock_.ApproximateNow());

  // The next packet received in order will cause an immediate ack, because it
  // fills a hole.
  RecordPacketReceipt(kFirstDecimatedPacket + 10, clock_.ApproximateNow());
  MaybeUpdateAckTimeout(kInstigateAck, kFirstDecimatedPacket + 10);
  CheckAckTimeout(clock_.ApproximateNow());
}

}  // namespace
}  // namespace test
}  // namespace quic
