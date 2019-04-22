// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/uber_quic_stream_id_manager.h"

#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_session_peer.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_stream_id_manager_peer.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"

using testing::_;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

class UberQuicStreamIdManagerTest : public QuicTestWithParam<Perspective> {
 public:
  bool SaveControlFrame(const QuicFrame& frame) {
    frame_ = frame;
    return true;
  }

 protected:
  UberQuicStreamIdManagerTest()
      : connection_(new MockQuicConnection(
            &helper_,
            &alarm_factory_,
            GetParam(),
            ParsedQuicVersionVector(
                {{PROTOCOL_QUIC_CRYPTO, QUIC_VERSION_99}}))) {
    session_ = QuicMakeUnique<StrictMock<MockQuicSession>>(connection_);
    manager_ = QuicSessionPeer::v99_streamid_manager(session_.get());
  }

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_CLIENT) +
           kV99StreamIdIncrement * n;
  }

  QuicStreamId GetNthClientInitiatedUnidirectionalId(int n) {
    return QuicUtils::GetFirstUnidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_CLIENT) +
           kV99StreamIdIncrement * n;
  }

  QuicStreamId GetNthServerInitiatedBidirectionalId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_SERVER) +
           kV99StreamIdIncrement * n;
  }

  QuicStreamId GetNthServerInitiatedUnidirectionalId(int n) {
    return QuicUtils::GetFirstUnidirectionalStreamId(
               connection_->transport_version(), Perspective::IS_SERVER) +
           kV99StreamIdIncrement * n;
  }

  QuicStreamId StreamCountToId(QuicStreamCount stream_count,
                               Perspective perspective,
                               bool bidirectional) {
    return ((bidirectional) ? QuicUtils::GetFirstBidirectionalStreamId(
                                  QUIC_VERSION_99, perspective)
                            : QuicUtils::GetFirstUnidirectionalStreamId(
                                  QUIC_VERSION_99, perspective)) +
           ((stream_count - 1) * QuicUtils::StreamIdDelta(QUIC_VERSION_99));
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_;
  std::unique_ptr<StrictMock<MockQuicSession>> session_;
  UberQuicStreamIdManager* manager_;
  QuicFrame frame_;
};

INSTANTIATE_TEST_SUITE_P(Tests,
                         UberQuicStreamIdManagerTest,
                         ::testing::ValuesIn({Perspective::IS_CLIENT,
                                              Perspective::IS_SERVER}));

TEST_P(UberQuicStreamIdManagerTest, Initialization) {
  if (GetParam() == Perspective::IS_SERVER) {
    EXPECT_EQ(GetNthServerInitiatedBidirectionalId(0),
              manager_->next_outgoing_bidirectional_stream_id());
    EXPECT_EQ(GetNthServerInitiatedUnidirectionalId(0),
              manager_->next_outgoing_unidirectional_stream_id());
  } else {
    EXPECT_EQ(GetNthClientInitiatedBidirectionalId(0),
              manager_->next_outgoing_bidirectional_stream_id());
    EXPECT_EQ(GetNthClientInitiatedUnidirectionalId(0),
              manager_->next_outgoing_unidirectional_stream_id());
  }
}

TEST_P(UberQuicStreamIdManagerTest, RegisterStaticStream) {
  QuicStreamId first_incoming_bidirectional_stream_id =
      GetParam() == Perspective::IS_SERVER
          ? GetNthClientInitiatedBidirectionalId(0)
          : GetNthServerInitiatedBidirectionalId(0);
  QuicStreamId first_incoming_unidirectional_stream_id =
      GetParam() == Perspective::IS_SERVER
          ? GetNthClientInitiatedUnidirectionalId(0)
          : GetNthServerInitiatedUnidirectionalId(0);

  QuicStreamCount actual_max_allowed_incoming_bidirectional_streams =
      manager_->actual_max_allowed_incoming_bidirectional_streams();
  QuicStreamCount actual_max_allowed_incoming_unidirectional_streams =
      manager_->actual_max_allowed_incoming_unidirectional_streams();
  manager_->RegisterStaticStream(first_incoming_bidirectional_stream_id);
  // Verify actual_max_allowed_incoming_bidirectional_streams increases.
  EXPECT_EQ(actual_max_allowed_incoming_bidirectional_streams + 1u,
            manager_->actual_max_allowed_incoming_bidirectional_streams());
  // Verify actual_max_allowed_incoming_unidirectional_streams does not
  // change.
  EXPECT_EQ(actual_max_allowed_incoming_unidirectional_streams,
            manager_->actual_max_allowed_incoming_unidirectional_streams());

  manager_->RegisterStaticStream(first_incoming_unidirectional_stream_id);
  EXPECT_EQ(actual_max_allowed_incoming_bidirectional_streams + 1u,
            manager_->actual_max_allowed_incoming_bidirectional_streams());
  EXPECT_EQ(actual_max_allowed_incoming_unidirectional_streams + 1u,
            manager_->actual_max_allowed_incoming_unidirectional_streams());
}

TEST_P(UberQuicStreamIdManagerTest, SetMaxOpenOutgoingStreams) {
  const size_t kNumMaxOutgoingStream = 123;
  manager_->SetMaxOpenOutgoingStreams(kNumMaxOutgoingStream);
  EXPECT_EQ(kNumMaxOutgoingStream,
            manager_->max_allowed_outgoing_bidirectional_streams());
  EXPECT_EQ(kNumMaxOutgoingStream,
            manager_->max_allowed_outgoing_unidirectional_streams());
}

TEST_P(UberQuicStreamIdManagerTest, SetMaxOpenIncomingStreams) {
  const size_t kNumMaxIncomingStreams = 456;
  manager_->SetMaxOpenIncomingStreams(kNumMaxIncomingStreams);
  EXPECT_EQ(kNumMaxIncomingStreams,
            manager_->GetMaxAllowdIncomingBidirectionalStreams());
  EXPECT_EQ(kNumMaxIncomingStreams,
            manager_->GetMaxAllowdIncomingUnidirectionalStreams());
  EXPECT_EQ(manager_->actual_max_allowed_incoming_bidirectional_streams(),
            manager_->advertised_max_allowed_incoming_bidirectional_streams());
  EXPECT_EQ(manager_->actual_max_allowed_incoming_unidirectional_streams(),
            manager_->advertised_max_allowed_incoming_unidirectional_streams());
}

TEST_P(UberQuicStreamIdManagerTest, GetNextOutgoingStreamId) {
  if (GetParam() == Perspective::IS_SERVER) {
    EXPECT_EQ(GetNthServerInitiatedBidirectionalId(0),
              manager_->GetNextOutgoingBidirectionalStreamId());
    EXPECT_EQ(GetNthServerInitiatedBidirectionalId(1),
              manager_->GetNextOutgoingBidirectionalStreamId());
    EXPECT_EQ(GetNthServerInitiatedUnidirectionalId(0),
              manager_->GetNextOutgoingUnidirectionalStreamId());
    EXPECT_EQ(GetNthServerInitiatedUnidirectionalId(1),
              manager_->GetNextOutgoingUnidirectionalStreamId());
  } else {
    EXPECT_EQ(GetNthClientInitiatedBidirectionalId(0),
              manager_->GetNextOutgoingBidirectionalStreamId());
    EXPECT_EQ(GetNthClientInitiatedBidirectionalId(1),
              manager_->GetNextOutgoingBidirectionalStreamId());
    EXPECT_EQ(GetNthClientInitiatedUnidirectionalId(0),
              manager_->GetNextOutgoingUnidirectionalStreamId());
    EXPECT_EQ(GetNthClientInitiatedUnidirectionalId(1),
              manager_->GetNextOutgoingUnidirectionalStreamId());
  }
}

TEST_P(UberQuicStreamIdManagerTest, AvailableStreams) {
  if (GetParam() == Perspective::IS_SERVER) {
    EXPECT_TRUE(manager_->MaybeIncreaseLargestPeerStreamId(
        GetNthClientInitiatedBidirectionalId(3)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthClientInitiatedBidirectionalId(1)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthClientInitiatedBidirectionalId(2)));

    EXPECT_TRUE(manager_->MaybeIncreaseLargestPeerStreamId(
        GetNthClientInitiatedUnidirectionalId(3)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthClientInitiatedUnidirectionalId(1)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthClientInitiatedUnidirectionalId(2)));
  } else {
    EXPECT_TRUE(manager_->MaybeIncreaseLargestPeerStreamId(
        GetNthServerInitiatedBidirectionalId(3)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthServerInitiatedBidirectionalId(1)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthServerInitiatedBidirectionalId(2)));

    EXPECT_TRUE(manager_->MaybeIncreaseLargestPeerStreamId(
        GetNthServerInitiatedUnidirectionalId(3)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthServerInitiatedUnidirectionalId(1)));
    EXPECT_TRUE(
        manager_->IsAvailableStream(GetNthServerInitiatedUnidirectionalId(2)));
  }
}

TEST_P(UberQuicStreamIdManagerTest, MaybeIncreaseLargestPeerStreamId) {
  EXPECT_CALL(*connection_, CloseConnection(_, _, _)).Times(0);
  EXPECT_TRUE(manager_->MaybeIncreaseLargestPeerStreamId(StreamCountToId(
      manager_->actual_max_allowed_incoming_bidirectional_streams(),
      /* Perspective=*/GetParam() == Perspective::IS_SERVER
          ? Perspective::IS_CLIENT
          : Perspective::IS_SERVER,
      /* bidirectional=*/true)));
  EXPECT_TRUE(manager_->MaybeIncreaseLargestPeerStreamId(StreamCountToId(
      manager_->actual_max_allowed_incoming_bidirectional_streams(),
      /* Perspective=*/GetParam() == Perspective::IS_SERVER
          ? Perspective::IS_CLIENT
          : Perspective::IS_SERVER,
      /* bidirectional=*/false)));

  std::string error_details =
      GetParam() == Perspective::IS_SERVER
          ? "Stream id 404 would exceed stream count limit 100"
          : "Stream id 401 would exceed stream count limit 100";

  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_STREAM_ID, error_details, _));
  EXPECT_FALSE(manager_->MaybeIncreaseLargestPeerStreamId(StreamCountToId(
      manager_->actual_max_allowed_incoming_bidirectional_streams() + 1,
      /* Perspective=*/GetParam() == Perspective::IS_SERVER
          ? Perspective::IS_CLIENT
          : Perspective::IS_SERVER,
      /* bidirectional=*/true)));
  error_details = GetParam() == Perspective::IS_SERVER
                      ? "Stream id 402 would exceed stream count limit 100"
                      : "Stream id 403 would exceed stream count limit 100";
  EXPECT_CALL(*connection_,
              CloseConnection(QUIC_INVALID_STREAM_ID, error_details, _));
  EXPECT_FALSE(manager_->MaybeIncreaseLargestPeerStreamId(StreamCountToId(
      manager_->actual_max_allowed_incoming_bidirectional_streams() + 1,
      /* Perspective=*/GetParam() == Perspective::IS_SERVER
          ? Perspective::IS_CLIENT
          : Perspective::IS_SERVER,
      /* bidirectional=*/false)));
}

TEST_P(UberQuicStreamIdManagerTest, OnMaxStreamsFrame) {
  QuicStreamCount max_allowed_outgoing_bidirectional_stream_count =
      manager_->max_allowed_outgoing_bidirectional_streams();

  QuicStreamCount max_allowed_outgoing_unidirectional_stream_count =
      manager_->max_allowed_outgoing_unidirectional_streams();

  // Inject a MAX_STREAMS frame that does not increase the limit and then
  // check that there are no changes. First try the bidirectional manager.
  QuicMaxStreamsFrame frame(kInvalidControlFrameId,
                            max_allowed_outgoing_bidirectional_stream_count,
                            /*unidirectional=*/false);
  EXPECT_TRUE(manager_->OnMaxStreamsFrame(frame));
  EXPECT_EQ(max_allowed_outgoing_bidirectional_stream_count,
            manager_->max_allowed_outgoing_bidirectional_streams());

  // Now try the unidirectioanl manager
  frame.stream_count = max_allowed_outgoing_unidirectional_stream_count;
  frame.unidirectional = true;
  EXPECT_TRUE(manager_->OnMaxStreamsFrame(frame));
  EXPECT_EQ(max_allowed_outgoing_unidirectional_stream_count,
            manager_->max_allowed_outgoing_unidirectional_streams());

  // Now try to increase the bidirectional stream count.
  frame.stream_count = max_allowed_outgoing_bidirectional_stream_count + 1;
  frame.unidirectional = false;
  EXPECT_TRUE(manager_->OnMaxStreamsFrame(frame));
  EXPECT_EQ(max_allowed_outgoing_bidirectional_stream_count + 1,
            manager_->max_allowed_outgoing_bidirectional_streams());
  // Make sure that the unidirectional state does not change.
  EXPECT_EQ(max_allowed_outgoing_unidirectional_stream_count,
            manager_->max_allowed_outgoing_unidirectional_streams());

  // Now check that a MAX_STREAMS for the unidirectional manager increases
  // just the unidirectiomal manager's state.
  frame.stream_count = max_allowed_outgoing_unidirectional_stream_count + 1;
  frame.unidirectional = true;
  EXPECT_TRUE(manager_->OnMaxStreamsFrame(frame));
  EXPECT_EQ(max_allowed_outgoing_bidirectional_stream_count + 1,
            manager_->max_allowed_outgoing_bidirectional_streams());
  EXPECT_EQ(max_allowed_outgoing_unidirectional_stream_count + 1,
            manager_->max_allowed_outgoing_unidirectional_streams());
}

TEST_P(UberQuicStreamIdManagerTest, OnStreamsBlockedFrame) {
  // Set up to capture calls to SendControlFrame - when a STREAMS_BLOCKED
  // frame is received, it will result in a a new MAX_STREAMS frame being
  // sent (if new streams can be made available).
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(
          Invoke(this, &UberQuicStreamIdManagerTest::SaveControlFrame));

  QuicStreamCount stream_count =
      manager_->advertised_max_allowed_incoming_bidirectional_streams() - 1;

  QuicStreamsBlockedFrame frame(kInvalidControlFrameId, stream_count,
                                /*unidirectional=*/false);
  session_->OnStreamsBlockedFrame(frame);
  EXPECT_EQ(MAX_STREAMS_FRAME, frame_.type);
  EXPECT_EQ(manager_->actual_max_allowed_incoming_bidirectional_streams(),
            frame_.max_streams_frame.stream_count);

  stream_count =
      manager_->advertised_max_allowed_incoming_unidirectional_streams() - 1;
  frame.stream_count = stream_count;
  frame.unidirectional = true;

  session_->OnStreamsBlockedFrame(frame);
  EXPECT_EQ(MAX_STREAMS_FRAME, frame_.type);
  EXPECT_EQ(manager_->actual_max_allowed_incoming_unidirectional_streams(),
            frame_.max_streams_frame.stream_count);
}

TEST_P(UberQuicStreamIdManagerTest, IsIncomingStream) {
  if (GetParam() == Perspective::IS_SERVER) {
    EXPECT_TRUE(
        manager_->IsIncomingStream(GetNthClientInitiatedBidirectionalId(0)));
    EXPECT_TRUE(
        manager_->IsIncomingStream(GetNthClientInitiatedUnidirectionalId(0)));
    EXPECT_FALSE(
        manager_->IsIncomingStream(GetNthServerInitiatedBidirectionalId(0)));
    EXPECT_FALSE(
        manager_->IsIncomingStream(GetNthServerInitiatedUnidirectionalId(0)));
  } else {
    EXPECT_FALSE(
        manager_->IsIncomingStream(GetNthClientInitiatedBidirectionalId(0)));
    EXPECT_FALSE(
        manager_->IsIncomingStream(GetNthClientInitiatedUnidirectionalId(0)));
    EXPECT_TRUE(
        manager_->IsIncomingStream(GetNthServerInitiatedBidirectionalId(0)));
    EXPECT_TRUE(
        manager_->IsIncomingStream(GetNthServerInitiatedUnidirectionalId(0)));
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
