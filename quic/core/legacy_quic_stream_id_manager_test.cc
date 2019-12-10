// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/legacy_quic_stream_id_manager.h"

#include <utility>

#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/core/quic_versions.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_session_peer.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
namespace {

using testing::_;
using testing::StrictMock;

class LegacyQuicStreamIdManagerTest : public QuicTest {
 public:
  LegacyQuicStreamIdManagerTest(Perspective perspective,
                                QuicTransportVersion transport_version)
      : transport_version_(transport_version),
        manager_(perspective,
                 transport_version,
                 kDefaultMaxStreamsPerConnection,
                 kDefaultMaxStreamsPerConnection) {
    // LegacyQuicStreamIdManager is only used for versions < 99.
    // TODO(b/145768765) parameterize this test by version.
    SetQuicReloadableFlag(quic_enable_version_q099, false);
    SetQuicReloadableFlag(quic_enable_version_t099, false);
  }

 protected:
  QuicStreamId GetNthClientInitiatedId(int n) {
    return QuicUtils::GetFirstBidirectionalStreamId(transport_version_,
                                                    Perspective::IS_CLIENT) +
           2 * n;
  }

  QuicStreamId GetNthServerInitiatedId(int n) { return 2 + 2 * n; }

  QuicTransportVersion transport_version_;
  LegacyQuicStreamIdManager manager_;
};

class LegacyQuicStreamIdManagerTestServer
    : public LegacyQuicStreamIdManagerTest {
 protected:
  LegacyQuicStreamIdManagerTestServer()
      : LegacyQuicStreamIdManagerTest(Perspective::IS_SERVER,
                                      QuicTransportVersion::QUIC_VERSION_46) {}
};

TEST_F(LegacyQuicStreamIdManagerTestServer, CanOpenNextOutgoingStream) {
  EXPECT_TRUE(manager_.CanOpenNextOutgoingStream(
      manager_.max_open_outgoing_streams() - 1));
  EXPECT_FALSE(
      manager_.CanOpenNextOutgoingStream(manager_.max_open_outgoing_streams()));
}

TEST_F(LegacyQuicStreamIdManagerTestServer, CanOpenIncomingStream) {
  EXPECT_TRUE(
      manager_.CanOpenIncomingStream(manager_.max_open_incoming_streams() - 1));
  EXPECT_FALSE(
      manager_.CanOpenIncomingStream(manager_.max_open_incoming_streams()));
}

TEST_F(LegacyQuicStreamIdManagerTestServer, AvailableStreams) {
  ASSERT_TRUE(
      manager_.MaybeIncreaseLargestPeerStreamId(GetNthClientInitiatedId(3)));
  EXPECT_TRUE(manager_.IsAvailableStream(GetNthClientInitiatedId(1)));
  EXPECT_TRUE(manager_.IsAvailableStream(GetNthClientInitiatedId(2)));
  ASSERT_TRUE(
      manager_.MaybeIncreaseLargestPeerStreamId(GetNthClientInitiatedId(2)));
  ASSERT_TRUE(
      manager_.MaybeIncreaseLargestPeerStreamId(GetNthClientInitiatedId(1)));
}

TEST_F(LegacyQuicStreamIdManagerTestServer, MaxAvailableStreams) {
  // Test that the server closes the connection if a client makes too many data
  // streams available.  The server accepts slightly more than the negotiated
  // stream limit to deal with rare cases where a client FIN/RST is lost.
  const size_t kMaxStreamsForTest = 10;
  const size_t kAvailableStreamLimit = manager_.MaxAvailableStreams();
  EXPECT_EQ(
      manager_.max_open_incoming_streams() * kMaxAvailableStreamsMultiplier,
      manager_.MaxAvailableStreams());
  // The protocol specification requires that there can be at least 10 times
  // as many available streams as the connection's maximum open streams.
  EXPECT_LE(10 * kMaxStreamsForTest, kAvailableStreamLimit);

  EXPECT_TRUE(
      manager_.MaybeIncreaseLargestPeerStreamId(GetNthClientInitiatedId(0)));

  // Establish available streams up to the server's limit.
  const int kLimitingStreamId =
      GetNthClientInitiatedId(kAvailableStreamLimit + 1);
  // This exceeds the stream limit. In versions other than 99
  // this is allowed. Version 99 hews to the IETF spec and does
  // not allow it.
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(kLimitingStreamId));

  // This forces stream kLimitingStreamId + 2 to become available, which
  // violates the quota.
  EXPECT_FALSE(
      manager_.MaybeIncreaseLargestPeerStreamId(kLimitingStreamId + 2 * 2));
}

TEST_F(LegacyQuicStreamIdManagerTestServer, MaximumAvailableOpenedStreams) {
  QuicStreamId stream_id = GetNthClientInitiatedId(0);
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(stream_id));

  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(
      stream_id + 2 * (manager_.max_open_incoming_streams() - 1)));
}

TEST_F(LegacyQuicStreamIdManagerTestServer, TooManyAvailableStreams) {
  QuicStreamId stream_id = GetNthClientInitiatedId(0);
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(stream_id));

  // A stream ID which is too large to create.
  QuicStreamId stream_id2 =
      GetNthClientInitiatedId(2 * manager_.MaxAvailableStreams() + 4);
  EXPECT_FALSE(manager_.MaybeIncreaseLargestPeerStreamId(stream_id2));
}

TEST_F(LegacyQuicStreamIdManagerTestServer, ManyAvailableStreams) {
  // When max_open_streams_ is 200, should be able to create 200 streams
  // out-of-order, that is, creating the one with the largest stream ID first.
  manager_.set_max_open_incoming_streams(200);
  QuicStreamId stream_id = GetNthClientInitiatedId(0);
  EXPECT_TRUE(manager_.MaybeIncreaseLargestPeerStreamId(stream_id));

  // Create the largest stream ID of a threatened total of 200 streams.
  // GetNth... starts at 0, so for 200 streams, get the 199th.
  EXPECT_TRUE(
      manager_.MaybeIncreaseLargestPeerStreamId(GetNthClientInitiatedId(199)));
}

TEST_F(LegacyQuicStreamIdManagerTestServer,
       TestMaxIncomingAndOutgoingStreamsAllowed) {
  EXPECT_EQ(manager_.max_open_incoming_streams(),
            kDefaultMaxStreamsPerConnection);
  EXPECT_EQ(manager_.max_open_outgoing_streams(),
            kDefaultMaxStreamsPerConnection);
}

class LegacyQuicStreamIdManagerTestClient
    : public LegacyQuicStreamIdManagerTest {
 protected:
  LegacyQuicStreamIdManagerTestClient()
      : LegacyQuicStreamIdManagerTest(Perspective::IS_CLIENT,
                                      QuicTransportVersion::QUIC_VERSION_46) {}
};

TEST_F(LegacyQuicStreamIdManagerTestClient,
       TestMaxIncomingAndOutgoingStreamsAllowed) {
  EXPECT_EQ(manager_.max_open_incoming_streams(),
            kDefaultMaxStreamsPerConnection);
  EXPECT_EQ(manager_.max_open_outgoing_streams(),
            kDefaultMaxStreamsPerConnection);
}

}  // namespace
}  // namespace test
}  // namespace quic
