// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_control_frame_manager.h"

#include <memory>
#include <utility>
#include <vector>

#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/frames/quic_ack_frequency_frame.h"
#include "quiche/quic/core/frames/quic_reset_stream_at_frame.h"
#include "quiche/quic/core/frames/quic_retire_connection_id_frame.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_flags.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

using testing::_;
using testing::InSequence;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {

class QuicControlFrameManagerPeer {
 public:
  static size_t QueueSize(QuicControlFrameManager* manager) {
    return manager->control_frames_.size();
  }
};

namespace {

const QuicStreamId kTestStreamId = 5;
const QuicRstStreamErrorCode kTestStopSendingCode =
    QUIC_STREAM_ENCODER_STREAM_ERROR;

class QuicControlFrameManagerTest : public QuicTest {
 public:
  QuicControlFrameManagerTest()
      : connection_(new MockQuicConnection(&helper_, &alarm_factory_,
                                           Perspective::IS_SERVER)),
        session_(std::make_unique<StrictMock<MockQuicSession>>(connection_)),
        manager_(std::make_unique<QuicControlFrameManager>(session_.get())) {
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
  }

 protected:
  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;
  std::unique_ptr<StrictMock<MockQuicSession>> session_;
  std::unique_ptr<QuicControlFrameManager> manager_;
};

TEST_F(QuicControlFrameManagerTest, InitialState) {
  EXPECT_EQ(0u, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, WriteOrBufferRstStream) {
  QuicRstStreamFrame rst_stream = {1, kTestStreamId, QUIC_STREAM_CANCELLED, 0};
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(
          [&rst_stream](const QuicFrame& frame, TransmissionType /*type*/) {
            EXPECT_EQ(RST_STREAM_FRAME, frame.type);
            EXPECT_EQ(rst_stream, *frame.rst_stream_frame);
            ClearControlFrame(frame);
            return true;
          });
  manager_->WriteOrBufferRstStream(
      rst_stream.stream_id,
      QuicResetStreamError::FromInternal(rst_stream.error_code),
      rst_stream.byte_offset);
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&rst_stream)));
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, WriteOrBufferResetStreamAt) {
  QuicResetStreamAtFrame reset_stream_at = {1, kTestStreamId,
                                            QUIC_STREAM_CANCELLED, 20, 10};
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&reset_stream_at](const QuicFrame& frame,
                                   TransmissionType /*type*/) {
        EXPECT_EQ(RESET_STREAM_AT_FRAME, frame.type);
        EXPECT_EQ(reset_stream_at, *frame.reset_stream_at_frame);
        ClearControlFrame(frame);
        return true;
      });
  manager_->WriteOrBufferResetStreamAt(
      reset_stream_at.stream_id,
      QuicResetStreamError::FromIetf(reset_stream_at.error),
      reset_stream_at.final_offset, reset_stream_at.reliable_offset);
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&reset_stream_at)));
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, WriteOrBufferGoAway) {
  QuicGoAwayFrame goaway = {1, QUIC_PEER_GOING_AWAY, kTestStreamId,
                            "Going away."};
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&goaway](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(GOAWAY_FRAME, frame.type);
        EXPECT_EQ(goaway, *frame.goaway_frame);
        ClearControlFrame(frame);
        return true;
      });
  manager_->WriteOrBufferGoAway(goaway.error_code, goaway.last_good_stream_id,
                                goaway.reason_phrase);
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&goaway)));
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, WriteOrBufferWindowUpdate) {
  QuicWindowUpdateFrame window_update = {1, kTestStreamId, 100};
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(
          [&window_update](const QuicFrame& frame, TransmissionType /*type*/) {
            EXPECT_EQ(WINDOW_UPDATE_FRAME, frame.type);
            EXPECT_EQ(window_update, frame.window_update_frame);
            ClearControlFrame(frame);
            return true;
          });
  manager_->WriteOrBufferWindowUpdate(window_update.stream_id,
                                      window_update.max_data);
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(window_update)));
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, WriteOrBufferBlocked) {
  QuicBlockedFrame blocked = {1, kTestStreamId, 10};
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&blocked](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(BLOCKED_FRAME, frame.type);
        EXPECT_EQ(blocked, frame.blocked_frame);
        ClearControlFrame(frame);
        return true;
      });
  manager_->WriteOrBufferBlocked(blocked.stream_id, blocked.offset);
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(blocked)));
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, WriteOrBufferStopSending) {
  QuicStopSendingFrame stop_sending = {1, kTestStreamId, kTestStopSendingCode};
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(
          [&stop_sending](const QuicFrame& frame, TransmissionType /*type*/) {
            EXPECT_EQ(STOP_SENDING_FRAME, frame.type);
            EXPECT_EQ(stop_sending, frame.stop_sending_frame);
            ClearControlFrame(frame);
            return true;
          });
  manager_->WriteOrBufferStopSending(
      QuicResetStreamError::FromInternal(stop_sending.error_code),
      stop_sending.stream_id);
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(stop_sending)));
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, BufferWhenWriteControlFrameReturnsFalse) {
  QuicBlockedFrame blocked = {1, kTestStreamId, 0};

  // Attempt write a control frame, but since WriteControlFrame returns false,
  // the frame will be buffered.
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  manager_->WriteOrBufferBlocked(blocked.stream_id, blocked.offset);
  EXPECT_TRUE(manager_->WillingToWrite());
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(blocked)));

  // OnCanWrite will send the frame.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, BufferThenSendThenBuffer) {
  InSequence s;
  QuicBlockedFrame frame1 = {1, kTestStreamId, 0};
  QuicBlockedFrame frame2 = {2, kTestStreamId + 1, 1};

  // Attempt write a control frame, but since WriteControlFrame returns false,
  // the frame will be buffered.
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  manager_->WriteOrBufferBlocked(frame1.stream_id, frame1.offset);
  manager_->WriteOrBufferBlocked(frame2.stream_id, frame2.offset);
  EXPECT_TRUE(manager_->WillingToWrite());
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(frame1)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(frame2)));

  // OnCanWrite will send the first frame, but WriteControlFrame will return
  // false and the second frame will remain buffered.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  manager_->OnCanWrite();
  EXPECT_TRUE(manager_->WillingToWrite());

  // Now the second frame will finally be sent.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, OnControlFrameAcked) {
  QuicRstStreamFrame frame1 = {1, kTestStreamId, QUIC_STREAM_CANCELLED, 0};
  QuicGoAwayFrame frame2 = {2, QUIC_PEER_GOING_AWAY, kTestStreamId,
                            "Going away."};
  QuicWindowUpdateFrame frame3 = {3, kTestStreamId, 100};
  QuicBlockedFrame frame4 = {4, kTestStreamId, 0};
  QuicStopSendingFrame frame5 = {5, kTestStreamId, kTestStopSendingCode};

  // Write 5 all frames.
  InSequence s;
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(5)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferRstStream(
      frame1.stream_id, QuicResetStreamError::FromInternal(frame1.error_code),
      frame1.byte_offset);
  manager_->WriteOrBufferGoAway(frame2.error_code, frame2.last_good_stream_id,
                                frame2.reason_phrase);
  manager_->WriteOrBufferWindowUpdate(frame3.stream_id, frame3.max_data);
  manager_->WriteOrBufferBlocked(frame4.stream_id, frame4.offset);
  manager_->WriteOrBufferStopSending(
      QuicResetStreamError::FromInternal(frame5.error_code), frame5.stream_id);

  // Verify all 5 are still outstanding.
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&frame1)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&frame2)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(frame3)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(frame4)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(frame5)));
  EXPECT_FALSE(manager_->HasPendingRetransmission());

  // Ack the third frame, but since the first is still in the queue, the size
  // will not shrink.
  EXPECT_TRUE(manager_->OnControlFrameAcked(QuicFrame(frame3)));
  EXPECT_FALSE(manager_->IsControlFrameOutstanding(QuicFrame(frame3)));
  EXPECT_EQ(5, QuicControlFrameManagerPeer::QueueSize(manager_.get()));

  // Ack the second frame, but since the first is still in the queue, the size
  // will not shrink.
  EXPECT_TRUE(manager_->OnControlFrameAcked(QuicFrame(&frame2)));
  EXPECT_FALSE(manager_->IsControlFrameOutstanding(QuicFrame(&frame2)));
  EXPECT_EQ(5, QuicControlFrameManagerPeer::QueueSize(manager_.get()));

  // Only after the first frame in the queue is acked do the frames get
  // removed ... now see that the length has been reduced by 3.
  EXPECT_TRUE(manager_->OnControlFrameAcked(QuicFrame(&frame1)));
  EXPECT_FALSE(manager_->IsControlFrameOutstanding(QuicFrame(&frame1)));
  EXPECT_EQ(2, QuicControlFrameManagerPeer::QueueSize(manager_.get()));

  // Duplicate ack should change nothing.
  EXPECT_FALSE(manager_->OnControlFrameAcked(QuicFrame(&frame2)));
  EXPECT_FALSE(manager_->IsControlFrameOutstanding(QuicFrame(&frame1)));
  EXPECT_EQ(2, QuicControlFrameManagerPeer::QueueSize(manager_.get()));

  // Ack the fourth frame which will shrink the queue.
  EXPECT_TRUE(manager_->OnControlFrameAcked(QuicFrame(frame4)));
  EXPECT_FALSE(manager_->IsControlFrameOutstanding(QuicFrame(frame4)));
  EXPECT_EQ(1, QuicControlFrameManagerPeer::QueueSize(manager_.get()));

  // Ack the fourth frame which will empty the queue.
  EXPECT_TRUE(manager_->OnControlFrameAcked(QuicFrame(frame5)));
  EXPECT_FALSE(manager_->IsControlFrameOutstanding(QuicFrame(frame5)));
  EXPECT_EQ(0, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
}

TEST_F(QuicControlFrameManagerTest, OnControlFrameLost) {
  QuicRstStreamFrame frame1 = {1, kTestStreamId, QUIC_STREAM_CANCELLED, 0};
  QuicGoAwayFrame frame2 = {2, QUIC_PEER_GOING_AWAY, kTestStreamId,
                            "Going away."};
  QuicWindowUpdateFrame frame3 = {3, kTestStreamId, 100};
  QuicBlockedFrame frame4 = {4, kTestStreamId, 0};
  QuicStopSendingFrame frame5 = {5, kTestStreamId, kTestStopSendingCode};

  // Write the first 3 frames, but leave the second two buffered.
  InSequence s;
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(3)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferRstStream(
      frame1.stream_id, QuicResetStreamError::FromInternal(frame1.error_code),
      frame1.byte_offset);
  manager_->WriteOrBufferGoAway(frame2.error_code, frame2.last_good_stream_id,
                                frame2.reason_phrase);
  manager_->WriteOrBufferWindowUpdate(frame3.stream_id, frame3.max_data);
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  manager_->WriteOrBufferBlocked(frame4.stream_id, frame4.offset);
  manager_->WriteOrBufferStopSending(
      QuicResetStreamError::FromInternal(frame5.error_code), frame5.stream_id);

  // Lose frames 1, 2, 3.
  manager_->OnControlFrameLost(QuicFrame(&frame1));
  manager_->OnControlFrameLost(QuicFrame(&frame2));
  manager_->OnControlFrameLost(QuicFrame(frame3));
  EXPECT_TRUE(manager_->HasPendingRetransmission());
  // Verify that the lost frames are still outstanding.
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&frame1)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(&frame2)));
  EXPECT_TRUE(manager_->IsControlFrameOutstanding(QuicFrame(frame3)));

  // Ack control frame 2.
  manager_->OnControlFrameAcked(QuicFrame(&frame2));

  // OnCanWrite will retransmit the lost frames, but will not sent the
  // not-yet-sent frames.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame1](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(RST_STREAM_FRAME, frame.type);
        EXPECT_EQ(frame1, *frame.rst_stream_frame);
        ClearControlFrame(frame);
        return true;
      });
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame3](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(WINDOW_UPDATE_FRAME, frame.type);
        EXPECT_EQ(frame3, frame.window_update_frame);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_TRUE(manager_->WillingToWrite());

  // Send control frames 4, and 5.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame4](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(BLOCKED_FRAME, frame.type);
        EXPECT_EQ(frame4, frame.blocked_frame);
        ClearControlFrame(frame);
        return true;
      });
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame5](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(STOP_SENDING_FRAME, frame.type);
        EXPECT_EQ(frame5, frame.stop_sending_frame);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, RetransmitControlFrame) {
  QuicRstStreamFrame frame1 = {1, kTestStreamId, QUIC_STREAM_CANCELLED, 0};
  QuicGoAwayFrame frame2 = {2, QUIC_PEER_GOING_AWAY, kTestStreamId,
                            "Going away."};
  QuicWindowUpdateFrame frame3 = {3, kTestStreamId, 100};
  QuicBlockedFrame frame4 = {4, kTestStreamId, 0};

  // Send all 4 frames.
  InSequence s;
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(4)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferRstStream(
      frame1.stream_id, QuicResetStreamError::FromInternal(frame1.error_code),
      frame1.byte_offset);
  manager_->WriteOrBufferGoAway(frame2.error_code, frame2.last_good_stream_id,
                                frame2.reason_phrase);
  manager_->WriteOrBufferWindowUpdate(frame3.stream_id, frame3.max_data);
  manager_->WriteOrBufferBlocked(frame4.stream_id, frame4.offset);

  // Ack control frame 2.
  manager_->OnControlFrameAcked(QuicFrame(&frame2));
  // Do not retransmit an acked frame
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).Times(0);
  EXPECT_TRUE(
      manager_->RetransmitControlFrame(QuicFrame(&frame2), PTO_RETRANSMISSION));

  // Retransmit frame 3.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame3](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(WINDOW_UPDATE_FRAME, frame.type);
        EXPECT_EQ(frame3, frame.window_update_frame);
        ClearControlFrame(frame);
        return true;
      });
  EXPECT_TRUE(
      manager_->RetransmitControlFrame(QuicFrame(frame3), PTO_RETRANSMISSION));

  // Retransmit frame 4, but since WriteControlFrame returned false the
  // frame will still need retransmission.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame4](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(BLOCKED_FRAME, frame.type);
        EXPECT_EQ(frame4, frame.blocked_frame);
        return false;
      });
  EXPECT_FALSE(
      manager_->RetransmitControlFrame(QuicFrame(frame4), PTO_RETRANSMISSION));
}

TEST_F(QuicControlFrameManagerTest, SendAndAckAckFrequencyFrame) {
  // Send AckFrequencyFrame
  QuicAckFrequencyFrame frame_to_send;
  frame_to_send.ack_eliciting_threshold = 10;
  frame_to_send.requested_max_ack_delay = QuicTime::Delta::FromMilliseconds(24);
  frame_to_send.reordering_threshold = 3;
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferAckFrequency(frame_to_send);

  // Ack AckFrequencyFrame.
  QuicAckFrequencyFrame expected_ack_frequency = frame_to_send;
  expected_ack_frequency.control_frame_id = 1;
  expected_ack_frequency.sequence_number = 1;
  EXPECT_TRUE(
      manager_->OnControlFrameAcked(QuicFrame(&expected_ack_frequency)));
}

TEST_F(QuicControlFrameManagerTest, NewAndRetireConnectionIdFrames) {
  // Send NewConnectionIdFrame
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  QuicNewConnectionIdFrame new_connection_id_frame(
      1, TestConnectionId(3), /*sequence_number=*/1,
      /*stateless_reset_token=*/
      {0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1}, /*retire_prior_to=*/1);
  manager_->WriteOrBufferNewConnectionId(
      new_connection_id_frame.connection_id,
      new_connection_id_frame.sequence_number,
      new_connection_id_frame.retire_prior_to,
      new_connection_id_frame.stateless_reset_token);

  // Send RetireConnectionIdFrame
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  QuicRetireConnectionIdFrame retire_connection_id_frame(2,
                                                         /*sequence_number=*/0);
  manager_->WriteOrBufferRetireConnectionId(
      retire_connection_id_frame.sequence_number);

  // Ack both frames.
  EXPECT_TRUE(
      manager_->OnControlFrameAcked(QuicFrame(&new_connection_id_frame)));
  EXPECT_TRUE(
      manager_->OnControlFrameAcked(QuicFrame(&retire_connection_id_frame)));
}

TEST_F(QuicControlFrameManagerTest, DonotRetransmitOldWindowUpdates) {
  // Send two window updates for the same stream.
  QuicWindowUpdateFrame window_update1(1, kTestStreamId, 200);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferWindowUpdate(window_update1.stream_id,
                                      window_update1.max_data);

  QuicWindowUpdateFrame window_update2(2, kTestStreamId, 300);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferWindowUpdate(window_update2.stream_id,
                                      window_update2.max_data);

  // Mark both window updates as lost.
  manager_->OnControlFrameLost(QuicFrame(window_update1));
  manager_->OnControlFrameLost(QuicFrame(window_update2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());
  EXPECT_TRUE(manager_->WillingToWrite());

  // Verify only the latest window update gets retransmitted.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(
          [&window_update2](const QuicFrame& frame, TransmissionType /*type*/) {
            EXPECT_EQ(WINDOW_UPDATE_FRAME, frame.type);
            EXPECT_EQ(window_update2, frame.window_update_frame);
            ClearControlFrame(frame);
            return true;
          });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, RetransmitWindowUpdateOfDifferentStreams) {
  // Send two window updates for different streams.
  QuicWindowUpdateFrame window_update1(1, kTestStreamId + 2, 200);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferWindowUpdate(window_update1.stream_id,
                                      window_update1.max_data);

  QuicWindowUpdateFrame window_update2(2, kTestStreamId + 4, 300);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferWindowUpdate(window_update2.stream_id,
                                      window_update2.max_data);

  // Mark both window updates as lost.
  manager_->OnControlFrameLost(QuicFrame(window_update1));
  manager_->OnControlFrameLost(QuicFrame(window_update2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());
  EXPECT_TRUE(manager_->WillingToWrite());

  // Verify both window updates get retransmitted.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(2)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, TooManyBufferedControlFrames) {
  // Write 1000 control frames.
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  for (size_t i = 0; i < 1000; ++i) {
    manager_->WriteOrBufferRstStream(
        kTestStreamId,
        QuicResetStreamError::FromInternal(QUIC_STREAM_CANCELLED), 0);
  }
  // Verify that writing one more control frame causes connection close.
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_TOO_MANY_BUFFERED_CONTROL_FRAMES, _,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  manager_->WriteOrBufferRstStream(
      kTestStreamId, QuicResetStreamError::FromInternal(QUIC_STREAM_CANCELLED),
      0);
}

TEST_F(QuicControlFrameManagerTest, NumBufferedMaxStreams) {
  std::vector<QuicMaxStreamsFrame> max_streams_frames;
  size_t expected_buffered_frames = 0;
  for (int i = 0; i < 5; ++i) {
    // Save the frame so it can be ACK'd later.
    EXPECT_CALL(*session_, WriteControlFrame(_, _))
        .WillOnce([&max_streams_frames](const QuicFrame& frame,
                                        TransmissionType /*type*/) {
          max_streams_frames.push_back(frame.max_streams_frame);
          ClearControlFrame(frame);
          return true;
        });

    // The contents of the frame don't matter for this test.
    manager_->WriteOrBufferMaxStreams(0, false);
    EXPECT_EQ(++expected_buffered_frames, manager_->NumBufferedMaxStreams());
  }

  for (const QuicMaxStreamsFrame& frame : max_streams_frames) {
    manager_->OnControlFrameAcked(QuicFrame(frame));
    EXPECT_EQ(--expected_buffered_frames, manager_->NumBufferedMaxStreams());
  }
  EXPECT_EQ(0, manager_->NumBufferedMaxStreams());
}

TEST_F(QuicControlFrameManagerTest, DonotRetransmitOldAckFrequency) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  QuicAckFrequencyFrame frame1(
      /*control_frame_id=*/1, /*sequence_number=*/1,
      /*ack_eliciting_threshold=*/10, QuicTime::Delta::FromMilliseconds(24),
      /*reordering_threshold=*/3);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferAckFrequency(frame1);

  QuicAckFrequencyFrame frame2(
      /*control_frame_id=*/2, /*sequence_number=*/2,
      /*ack_eliciting_threshold=*/5, QuicTime::Delta::FromMilliseconds(12),
      /*reordering_threshold=*/2);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferAckFrequency(frame2);

  // Mark both AckFrequency frames as lost.
  manager_->OnControlFrameLost(QuicFrame(&frame1));
  manager_->OnControlFrameLost(QuicFrame(&frame2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());
  EXPECT_TRUE(manager_->WillingToWrite());

  // Verify only the latest AckFrequency frame gets retransmitted.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame2](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(ACK_FREQUENCY_FRAME, frame.type);
        EXPECT_EQ(frame2.control_frame_id,
                  frame.ack_frequency_frame->control_frame_id);
        EXPECT_EQ(frame2.sequence_number,
                  frame.ack_frequency_frame->sequence_number);
        EXPECT_EQ(frame2.ack_eliciting_threshold,
                  frame.ack_frequency_frame->ack_eliciting_threshold);
        EXPECT_EQ(frame2.requested_max_ack_delay,
                  frame.ack_frequency_frame->requested_max_ack_delay);
        EXPECT_EQ(frame2.reordering_threshold,
                  frame.ack_frequency_frame->reordering_threshold);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, DonotRetransmitOldNewToken) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  QuicNewTokenFrame frame1(1, "token1");
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferNewToken(frame1.token);

  QuicNewTokenFrame frame2(2, "token2");
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferNewToken(frame2.token);

  // Mark both NewToken frames as lost.
  manager_->OnControlFrameLost(QuicFrame(&frame1));
  manager_->OnControlFrameLost(QuicFrame(&frame2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());
  EXPECT_TRUE(manager_->WillingToWrite());

  // Verify only the latest NewToken frame gets retransmitted.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame2](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(NEW_TOKEN_FRAME, frame.type);
        EXPECT_EQ(frame2.control_frame_id,
                  frame.new_token_frame->control_frame_id);
        EXPECT_EQ(frame2.token, frame.new_token_frame->token);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, RetransmitOldNewTokenWhenFlagFalse) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, false);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  QuicNewTokenFrame frame1(1, "token1");
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferNewToken(frame1.token);

  QuicNewTokenFrame frame2(2, "token2");
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferNewToken(frame2.token);

  manager_->OnControlFrameLost(QuicFrame(&frame1));
  manager_->OnControlFrameLost(QuicFrame(&frame2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());

  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(2)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
}

TEST_F(QuicControlFrameManagerTest, DonotRetransmitBlocked) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  QuicBlockedFrame blocked1(1, kTestStreamId, 100);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferBlocked(blocked1.stream_id, blocked1.offset);

  QuicBlockedFrame blocked2(2, kTestStreamId + 4, 50);
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferBlocked(blocked2.stream_id, blocked2.offset);

  manager_->OnControlFrameLost(QuicFrame(blocked1));
  manager_->OnControlFrameLost(QuicFrame(blocked2));
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
  EXPECT_EQ(0u, QuicControlFrameManagerPeer::QueueSize(manager_.get()));
}

TEST_F(QuicControlFrameManagerTest, DonotRetransmitOldStreamsBlocked) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  QuicStreamsBlockedFrame bidi1(1, 10, /*unidirectional=*/false);
  QuicStreamsBlockedFrame uni1(2, 5, /*unidirectional=*/true);
  QuicStreamsBlockedFrame bidi2(3, 20, /*unidirectional=*/false);
  QuicStreamsBlockedFrame uni2(4, 15, /*unidirectional=*/true);

  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(4)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferStreamsBlocked(bidi1.stream_count,
                                        bidi1.unidirectional);
  manager_->WriteOrBufferStreamsBlocked(uni1.stream_count, uni1.unidirectional);
  manager_->WriteOrBufferStreamsBlocked(bidi2.stream_count,
                                        bidi2.unidirectional);
  manager_->WriteOrBufferStreamsBlocked(uni2.stream_count, uni2.unidirectional);

  manager_->OnControlFrameLost(QuicFrame(bidi1));
  manager_->OnControlFrameLost(QuicFrame(uni1));
  manager_->OnControlFrameLost(QuicFrame(bidi2));
  manager_->OnControlFrameLost(QuicFrame(uni2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());

  InSequence s;
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&bidi2](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(STREAMS_BLOCKED_FRAME, frame.type);
        EXPECT_EQ(bidi2.control_frame_id,
                  frame.streams_blocked_frame.control_frame_id);
        EXPECT_EQ(bidi2.stream_count, frame.streams_blocked_frame.stream_count);
        EXPECT_EQ(bidi2.unidirectional,
                  frame.streams_blocked_frame.unidirectional);
        ClearControlFrame(frame);
        return true;
      });
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&uni2](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(STREAMS_BLOCKED_FRAME, frame.type);
        EXPECT_EQ(uni2.control_frame_id,
                  frame.streams_blocked_frame.control_frame_id);
        EXPECT_EQ(uni2.stream_count, frame.streams_blocked_frame.stream_count);
        EXPECT_EQ(uni2.unidirectional,
                  frame.streams_blocked_frame.unidirectional);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest, DonotRetransmitOldGoAway) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  QuicGoAwayFrame goaway1(1, QUIC_PEER_GOING_AWAY, kTestStreamId + 4, "first");
  QuicGoAwayFrame goaway2(2, QUIC_PEER_GOING_AWAY, kTestStreamId, "second");

  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .Times(2)
      .WillRepeatedly(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferGoAway(goaway1.error_code, goaway1.last_good_stream_id,
                                goaway1.reason_phrase);
  manager_->WriteOrBufferGoAway(goaway2.error_code, goaway2.last_good_stream_id,
                                goaway2.reason_phrase);

  manager_->OnControlFrameLost(QuicFrame(&goaway1));
  manager_->OnControlFrameLost(QuicFrame(&goaway2));
  EXPECT_TRUE(manager_->HasPendingRetransmission());

  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&goaway2](const QuicFrame& frame, TransmissionType /*type*/) {
        EXPECT_EQ(GOAWAY_FRAME, frame.type);
        EXPECT_EQ(goaway2, *frame.goaway_frame);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest,
       DonotRetransmitLostFrameWhenNewerFrameIsBuffered) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  // Send first NewToken frame.
  QuicNewTokenFrame frame1(1, "token1");
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferNewToken(frame1.token);

  // Connection is write-blocked when the newer NewToken frame is queued.
  QuicNewTokenFrame frame2(2, "token2");
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  manager_->WriteOrBufferNewToken(frame2.token);
  EXPECT_TRUE(manager_->WillingToWrite());

  // Mark the first NewToken frame as lost while the second is still buffered.
  manager_->OnControlFrameLost(QuicFrame(&frame1));
  EXPECT_FALSE(manager_->HasPendingRetransmission());

  // When connection becomes writable, only the newer buffered NewToken frame is
  // sent, without retransmitting the stale lost one.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame2](const QuicFrame& frame, TransmissionType type) {
        EXPECT_EQ(NOT_RETRANSMISSION, type);
        EXPECT_EQ(NEW_TOKEN_FRAME, frame.type);
        EXPECT_EQ(frame2.control_frame_id,
                  frame.new_token_frame->control_frame_id);
        EXPECT_EQ(frame2.token, frame.new_token_frame->token);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

TEST_F(QuicControlFrameManagerTest,
       DonotRetransmitLostFrameWhenNewerFrameQueuedAfterLoss) {
  SetQuicReloadableFlag(quic_no_stale_control_frames, true);
  manager_ = std::make_unique<QuicControlFrameManager>(session_.get());

  // Send first NewToken frame.
  QuicNewTokenFrame frame1(1, "token1");
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce(&ClearControlFrameWithTransmissionType);
  manager_->WriteOrBufferNewToken(frame1.token);

  // Mark the first NewToken frame as lost before a newer one is queued.
  manager_->OnControlFrameLost(QuicFrame(&frame1));
  EXPECT_TRUE(manager_->HasPendingRetransmission());

  // Connection is write-blocked when the newer NewToken frame is queued.
  // Queuing the newer frame should immediately ack the lost stale frame and
  // remove it from pending_retransmissions_.
  QuicNewTokenFrame frame2(2, "token2");
  EXPECT_CALL(*session_, WriteControlFrame(_, _)).WillOnce(Return(false));
  manager_->WriteOrBufferNewToken(frame2.token);
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_TRUE(manager_->WillingToWrite());

  // When connection becomes writable, only the newer buffered NewToken frame is
  // sent, without retransmitting the stale lost one.
  EXPECT_CALL(*session_, WriteControlFrame(_, _))
      .WillOnce([&frame2](const QuicFrame& frame, TransmissionType type) {
        EXPECT_EQ(NOT_RETRANSMISSION, type);
        EXPECT_EQ(NEW_TOKEN_FRAME, frame.type);
        EXPECT_EQ(frame2.control_frame_id,
                  frame.new_token_frame->control_frame_id);
        EXPECT_EQ(frame2.token, frame.new_token_frame->token);
        ClearControlFrame(frame);
        return true;
      });
  manager_->OnCanWrite();
  EXPECT_FALSE(manager_->HasPendingRetransmission());
  EXPECT_FALSE(manager_->WillingToWrite());
}

}  // namespace
}  // namespace test
}  // namespace quic
