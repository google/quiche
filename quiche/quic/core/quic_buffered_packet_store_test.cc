// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_buffered_packet_store.h"

#include <list>
#include <memory>
#include <string>

#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/first_flight.h"
#include "quiche/quic/test_tools/mock_clock.h"
#include "quiche/quic/test_tools/quic_buffered_packet_store_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
static const size_t kDefaultMaxConnectionsInStore = 100;
static const size_t kMaxConnectionsWithoutCHLO =
    kDefaultMaxConnectionsInStore / 2;

namespace test {
namespace {

const absl::optional<ParsedClientHello> kNoParsedChlo;
const absl::optional<ParsedClientHello> kDefaultParsedChlo =
    absl::make_optional<ParsedClientHello>();

using BufferedPacket = QuicBufferedPacketStore::BufferedPacket;
using BufferedPacketList = QuicBufferedPacketStore::BufferedPacketList;
using EnqueuePacketResult = QuicBufferedPacketStore::EnqueuePacketResult;
using ::testing::A;
using ::testing::Conditional;
using ::testing::Each;
using ::testing::ElementsAre;
using ::testing::Ne;
using ::testing::SizeIs;
using ::testing::Truly;

class QuicBufferedPacketStoreVisitor
    : public QuicBufferedPacketStore::VisitorInterface {
 public:
  QuicBufferedPacketStoreVisitor() {}

  ~QuicBufferedPacketStoreVisitor() override {}

  void OnExpiredPackets(QuicConnectionId /*connection_id*/,
                        BufferedPacketList early_arrived_packets) override {
    last_expired_packet_queue_ = std::move(early_arrived_packets);
  }

  // The packets queue for most recently expirect connection.
  BufferedPacketList last_expired_packet_queue_;
};

class QuicBufferedPacketStoreTest : public QuicTest {
 public:
  QuicBufferedPacketStoreTest()
      : store_(&visitor_, &clock_, &alarm_factory_),
        self_address_(QuicIpAddress::Any6(), 65535),
        peer_address_(QuicIpAddress::Any6(), 65535),
        packet_content_("some encrypted content"),
        packet_time_(QuicTime::Zero() + QuicTime::Delta::FromMicroseconds(42)),
        packet_(packet_content_.data(), packet_content_.size(), packet_time_),
        invalid_version_(UnsupportedQuicVersion()),
        valid_version_(CurrentSupportedVersions().front()) {}

 protected:
  QuicBufferedPacketStoreVisitor visitor_;
  MockClock clock_;
  MockAlarmFactory alarm_factory_;
  QuicBufferedPacketStore store_;
  QuicSocketAddress self_address_;
  QuicSocketAddress peer_address_;
  std::string packet_content_;
  QuicTime packet_time_;
  QuicReceivedPacket packet_;
  const ParsedQuicVersion invalid_version_;
  const ParsedQuicVersion valid_version_;
};

TEST_F(QuicBufferedPacketStoreTest, SimpleEnqueueAndDeliverPacket) {
  QuicConnectionId connection_id = TestConnectionId(1);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  auto packets = store_.DeliverPackets(connection_id);
  const std::list<BufferedPacket>& queue = packets.buffered_packets;
  ASSERT_EQ(1u, queue.size());
  ASSERT_FALSE(packets.parsed_chlo.has_value());
  // There is no valid version because CHLO has not arrived.
  EXPECT_EQ(invalid_version_, packets.version);
  // Check content of the only packet in the queue.
  EXPECT_EQ(packet_content_, queue.front().packet->AsStringPiece());
  EXPECT_EQ(packet_time_, queue.front().packet->receipt_time());
  EXPECT_EQ(peer_address_, queue.front().peer_address);
  EXPECT_EQ(self_address_, queue.front().self_address);
  // No more packets on connection 1 should remain in the store.
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
}

TEST_F(QuicBufferedPacketStoreTest, DifferentPacketAddressOnOneConnection) {
  QuicSocketAddress addr_with_new_port(QuicIpAddress::Any4(), 256);
  QuicConnectionId connection_id = TestConnectionId(1);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       addr_with_new_port, invalid_version_, kNoParsedChlo);
  std::list<BufferedPacket> queue =
      store_.DeliverPackets(connection_id).buffered_packets;
  ASSERT_EQ(2u, queue.size());
  // The address migration path should be preserved.
  EXPECT_EQ(peer_address_, queue.front().peer_address);
  EXPECT_EQ(addr_with_new_port, queue.back().peer_address);
}

TEST_F(QuicBufferedPacketStoreTest,
       EnqueueAndDeliverMultiplePacketsOnMultipleConnections) {
  size_t num_connections = 10;
  for (uint64_t conn_id = 1; conn_id <= num_connections; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                         peer_address_, invalid_version_, kNoParsedChlo);
    store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                         peer_address_, invalid_version_, kNoParsedChlo);
  }

  // Deliver packets in reversed order.
  for (uint64_t conn_id = num_connections; conn_id > 0; --conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    std::list<BufferedPacket> queue =
        store_.DeliverPackets(connection_id).buffered_packets;
    ASSERT_EQ(2u, queue.size());
  }
}

TEST_F(QuicBufferedPacketStoreTest,
       FailToBufferTooManyPacketsOnExistingConnection) {
  // Tests that for one connection, only limited number of packets can be
  // buffered.
  size_t num_packets = kDefaultMaxUndecryptablePackets + 1;
  QuicConnectionId connection_id = TestConnectionId(1);
  // Arrived CHLO packet shouldn't affect how many non-CHLO pacekts store can
  // keep.
  EXPECT_EQ(
      QuicBufferedPacketStore::SUCCESS,
      store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                           peer_address_, valid_version_, kDefaultParsedChlo));
  for (size_t i = 1; i <= num_packets; ++i) {
    // Only first |kDefaultMaxUndecryptablePackets packets| will be buffered.
    EnqueuePacketResult result =
        store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                             peer_address_, invalid_version_, kNoParsedChlo);
    if (i <= kDefaultMaxUndecryptablePackets) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_PACKETS, result);
    }
  }

  // Only first |kDefaultMaxUndecryptablePackets| non-CHLO packets and CHLO are
  // buffered.
  EXPECT_EQ(kDefaultMaxUndecryptablePackets + 1,
            store_.DeliverPackets(connection_id).buffered_packets.size());
}

TEST_F(QuicBufferedPacketStoreTest, ReachNonChloConnectionUpperLimit) {
  // Tests that store can only keep early arrived packets for limited number of
  // connections.
  const size_t kNumConnections = kMaxConnectionsWithoutCHLO + 1;
  for (uint64_t conn_id = 1; conn_id <= kNumConnections; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EnqueuePacketResult result =
        store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                             peer_address_, invalid_version_, kNoParsedChlo);
    if (conn_id <= kMaxConnectionsWithoutCHLO) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, result);
    }
  }
  // Store only keeps early arrived packets upto |kNumConnections| connections.
  for (uint64_t conn_id = 1; conn_id <= kNumConnections; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    std::list<BufferedPacket> queue =
        store_.DeliverPackets(connection_id).buffered_packets;
    if (conn_id <= kMaxConnectionsWithoutCHLO) {
      EXPECT_EQ(1u, queue.size());
    } else {
      EXPECT_EQ(0u, queue.size());
    }
  }
}

TEST_F(QuicBufferedPacketStoreTest,
       FullStoreFailToBufferDataPacketOnNewConnection) {
  // Send enough CHLOs so that store gets full before number of connections
  // without CHLO reaches its upper limit.
  size_t num_chlos =
      kDefaultMaxConnectionsInStore - kMaxConnectionsWithoutCHLO + 1;
  for (uint64_t conn_id = 1; conn_id <= num_chlos; ++conn_id) {
    EXPECT_EQ(EnqueuePacketResult::SUCCESS,
              store_.EnqueuePacket(TestConnectionId(conn_id), false, packet_,
                                   self_address_, peer_address_, valid_version_,
                                   kDefaultParsedChlo));
  }

  // Send data packets on another |kMaxConnectionsWithoutCHLO| connections.
  // Store should only be able to buffer till it's full.
  for (uint64_t conn_id = num_chlos + 1;
       conn_id <= (kDefaultMaxConnectionsInStore + 1); ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EnqueuePacketResult result =
        store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                             peer_address_, valid_version_, kDefaultParsedChlo);
    if (conn_id <= kDefaultMaxConnectionsInStore) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, result);
    } else {
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, result);
    }
  }
}

TEST_F(QuicBufferedPacketStoreTest, EnqueueChloOnTooManyDifferentConnections) {
  // Buffer data packets on different connections upto limit.
  for (uint64_t conn_id = 1; conn_id <= kMaxConnectionsWithoutCHLO; ++conn_id) {
    QuicConnectionId connection_id = TestConnectionId(conn_id);
    EXPECT_EQ(
        EnqueuePacketResult::SUCCESS,
        store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                             peer_address_, invalid_version_, kNoParsedChlo));
  }

  // Buffer CHLOs on other connections till store is full.
  for (size_t i = kMaxConnectionsWithoutCHLO + 1;
       i <= kDefaultMaxConnectionsInStore + 1; ++i) {
    QuicConnectionId connection_id = TestConnectionId(i);
    EnqueuePacketResult rs =
        store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                             peer_address_, valid_version_, kDefaultParsedChlo);
    if (i <= kDefaultMaxConnectionsInStore) {
      EXPECT_EQ(EnqueuePacketResult::SUCCESS, rs);
      EXPECT_TRUE(store_.HasChloForConnection(connection_id));
    } else {
      // Last CHLO can't be buffered because store is full.
      EXPECT_EQ(EnqueuePacketResult::TOO_MANY_CONNECTIONS, rs);
      EXPECT_FALSE(store_.HasChloForConnection(connection_id));
    }
  }

  // But buffering a CHLO belonging to a connection already has data packet
  // buffered in the store should success. This is the connection should be
  // delivered at last.
  EXPECT_EQ(
      EnqueuePacketResult::SUCCESS,
      store_.EnqueuePacket(
          /*connection_id=*/TestConnectionId(1), false, packet_, self_address_,
          peer_address_, valid_version_, kDefaultParsedChlo));
  EXPECT_TRUE(store_.HasChloForConnection(
      /*connection_id=*/TestConnectionId(1)));

  QuicConnectionId delivered_conn_id;
  for (size_t i = 0;
       i < kDefaultMaxConnectionsInStore - kMaxConnectionsWithoutCHLO + 1;
       ++i) {
    if (i < kDefaultMaxConnectionsInStore - kMaxConnectionsWithoutCHLO) {
      // Only CHLO is buffered.
      EXPECT_EQ(1u, store_.DeliverPacketsForNextConnection(&delivered_conn_id)
                        .buffered_packets.size());
      EXPECT_EQ(TestConnectionId(i + kMaxConnectionsWithoutCHLO + 1),
                delivered_conn_id);
    } else {
      EXPECT_EQ(2u, store_.DeliverPacketsForNextConnection(&delivered_conn_id)
                        .buffered_packets.size());
      EXPECT_EQ(TestConnectionId(1u), delivered_conn_id);
    }
  }
  EXPECT_FALSE(store_.HasChlosBuffered());
}

// Tests that store expires long-staying connections appropriately for
// connections both with and without CHLOs.
TEST_F(QuicBufferedPacketStoreTest, PacketQueueExpiredBeforeDelivery) {
  QuicConnectionId connection_id = TestConnectionId(1);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  EXPECT_EQ(
      EnqueuePacketResult::SUCCESS,
      store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                           peer_address_, valid_version_, kDefaultParsedChlo));
  QuicConnectionId connection_id2 = TestConnectionId(2);
  EXPECT_EQ(
      EnqueuePacketResult::SUCCESS,
      store_.EnqueuePacket(connection_id2, false, packet_, self_address_,
                           peer_address_, invalid_version_, kNoParsedChlo));

  // CHLO on connection 3 arrives 1ms later.
  clock_.AdvanceTime(QuicTime::Delta::FromMilliseconds(1));
  QuicConnectionId connection_id3 = TestConnectionId(3);
  // Use different client address to differetiate packets from different
  // connections.
  QuicSocketAddress another_client_address(QuicIpAddress::Any4(), 255);
  store_.EnqueuePacket(connection_id3, false, packet_, self_address_,
                       another_client_address, valid_version_,
                       kDefaultParsedChlo);

  // Advance clock to the time when connection 1 and 2 expires.
  clock_.AdvanceTime(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline() -
      clock_.ApproximateNow());
  ASSERT_GE(clock_.ApproximateNow(),
            QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline());
  // Fire alarm to remove long-staying connection 1 and 2 packets.
  alarm_factory_.FireAlarm(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_));
  EXPECT_EQ(1u, visitor_.last_expired_packet_queue_.buffered_packets.size());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id2));

  // Try to deliver packets, but packet queue has been removed so no
  // packets can be returned.
  ASSERT_EQ(0u, store_.DeliverPackets(connection_id).buffered_packets.size());
  ASSERT_EQ(0u, store_.DeliverPackets(connection_id2).buffered_packets.size());
  QuicConnectionId delivered_conn_id;
  auto queue = store_.DeliverPacketsForNextConnection(&delivered_conn_id)
                   .buffered_packets;
  // Connection 3 is the next to be delivered as connection 1 already expired.
  EXPECT_EQ(connection_id3, delivered_conn_id);
  ASSERT_EQ(1u, queue.size());
  // Packets in connection 3 should use another peer address.
  EXPECT_EQ(another_client_address, queue.front().peer_address);

  // Test the alarm is reset by enqueueing 2 packets for 4th connection and wait
  // for them to expire.
  QuicConnectionId connection_id4 = TestConnectionId(4);
  store_.EnqueuePacket(connection_id4, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id4, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  clock_.AdvanceTime(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_)->deadline() -
      clock_.ApproximateNow());
  alarm_factory_.FireAlarm(
      QuicBufferedPacketStorePeer::expiration_alarm(&store_));
  // |last_expired_packet_queue_| should be updated.
  EXPECT_EQ(2u, visitor_.last_expired_packet_queue_.buffered_packets.size());
}

TEST_F(QuicBufferedPacketStoreTest, SimpleDiscardPackets) {
  QuicConnectionId connection_id = TestConnectionId(1);

  // Enqueue some packets
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());

  // Dicard the packets
  store_.DiscardPackets(connection_id);

  // No packets on connection 1 should remain in the store
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());

  // Check idempotency
  store_.DiscardPackets(connection_id);
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, DiscardWithCHLOs) {
  QuicConnectionId connection_id = TestConnectionId(1);

  // Enqueue some packets, which include a CHLO
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, valid_version_, kDefaultParsedChlo);
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Dicard the packets
  store_.DiscardPackets(connection_id);

  // No packets on connection 1 should remain in the store
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());

  // Check idempotency
  store_.DiscardPackets(connection_id);
  EXPECT_TRUE(store_.DeliverPackets(connection_id).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, MultipleDiscardPackets) {
  QuicConnectionId connection_id_1 = TestConnectionId(1);
  QuicConnectionId connection_id_2 = TestConnectionId(2);

  // Enqueue some packets for two connection IDs
  store_.EnqueuePacket(connection_id_1, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id_1, false, packet_, self_address_,
                       peer_address_, invalid_version_, kNoParsedChlo);

  ParsedClientHello parsed_chlo;
  parsed_chlo.alpns.push_back("h3");
  parsed_chlo.sni = TestHostname();
  store_.EnqueuePacket(connection_id_2, false, packet_, self_address_,
                       peer_address_, valid_version_, parsed_chlo);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id_1));
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id_2));
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Discard the packets for connection 1
  store_.DiscardPackets(connection_id_1);

  // No packets on connection 1 should remain in the store
  EXPECT_TRUE(store_.DeliverPackets(connection_id_1).buffered_packets.empty());
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id_1));
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Packets on connection 2 should remain
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id_2));
  auto packets = store_.DeliverPackets(connection_id_2);
  EXPECT_EQ(1u, packets.buffered_packets.size());
  ASSERT_EQ(1u, packets.parsed_chlo->alpns.size());
  EXPECT_EQ("h3", packets.parsed_chlo->alpns[0]);
  EXPECT_EQ(TestHostname(), packets.parsed_chlo->sni);
  // Since connection_id_2's chlo arrives, verify version is set.
  EXPECT_EQ(valid_version_, packets.version);
  EXPECT_TRUE(store_.HasChlosBuffered());

  // Discard the packets for connection 2
  store_.DiscardPackets(connection_id_2);
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, DiscardPacketsEmpty) {
  // Check that DiscardPackets on an unknown connection ID is safe and does
  // nothing.
  QuicConnectionId connection_id = TestConnectionId(11235);
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
  store_.DiscardPackets(connection_id);
  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.HasChlosBuffered());
}

TEST_F(QuicBufferedPacketStoreTest, IngestPacketForTlsChloExtraction) {
  QuicConnectionId connection_id = TestConnectionId(1);
  std::vector<std::string> alpns;
  std::vector<uint16_t> supported_groups;
  std::string sni;
  bool resumption_attempted = false;
  bool early_data_attempted = false;
  QuicConfig config;
  absl::optional<uint8_t> tls_alert;

  EXPECT_FALSE(store_.HasBufferedPackets(connection_id));
  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, valid_version_, kNoParsedChlo);
  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));

  // The packet in 'packet_' is not a TLS CHLO packet.
  EXPECT_FALSE(store_.IngestPacketForTlsChloExtraction(
      connection_id, valid_version_, packet_, &supported_groups, &alpns, &sni,
      &resumption_attempted, &early_data_attempted, &tls_alert));

  store_.DiscardPackets(connection_id);

  // Force the TLS CHLO to span multiple packets.
  constexpr auto kCustomParameterId =
      static_cast<TransportParameters::TransportParameterId>(0xff33);
  std::string kCustomParameterValue(2000, '-');
  config.custom_transport_parameters_to_send()[kCustomParameterId] =
      kCustomParameterValue;
  auto packets = GetFirstFlightOfPackets(valid_version_, config);
  ASSERT_EQ(packets.size(), 2u);

  store_.EnqueuePacket(connection_id, false, *packets[0], self_address_,
                       peer_address_, valid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id, false, *packets[1], self_address_,
                       peer_address_, valid_version_, kNoParsedChlo);

  EXPECT_TRUE(store_.HasBufferedPackets(connection_id));
  EXPECT_FALSE(store_.IngestPacketForTlsChloExtraction(
      connection_id, valid_version_, *packets[0], &supported_groups, &alpns,
      &sni, &resumption_attempted, &early_data_attempted, &tls_alert));
  EXPECT_TRUE(store_.IngestPacketForTlsChloExtraction(
      connection_id, valid_version_, *packets[1], &supported_groups, &alpns,
      &sni, &resumption_attempted, &early_data_attempted, &tls_alert));

  EXPECT_THAT(alpns, ElementsAre(AlpnForVersion(valid_version_)));
  if (GetQuicReloadableFlag(quic_extract_supported_groups_early)) {
    EXPECT_FALSE(supported_groups.empty());
  } else {
    EXPECT_TRUE(supported_groups.empty());
  }
  EXPECT_EQ(sni, TestHostname());

  EXPECT_FALSE(resumption_attempted);
  EXPECT_FALSE(early_data_attempted);
}

TEST_F(QuicBufferedPacketStoreTest, DeliverInitialPacketsFirst) {
  QuicConfig config;
  QuicConnectionId connection_id = TestConnectionId(1);

  // Force the TLS CHLO to span multiple packets.
  constexpr auto kCustomParameterId =
      static_cast<TransportParameters::TransportParameterId>(0xff33);
  std::string custom_parameter_value(2000, '-');
  config.custom_transport_parameters_to_send()[kCustomParameterId] =
      custom_parameter_value;
  auto initial_packets = GetFirstFlightOfPackets(valid_version_, config);
  ASSERT_THAT(initial_packets, SizeIs(2));

  // Verify that the packets generated are INITIAL packets.
  EXPECT_THAT(
      initial_packets,
      Each(Truly([](const std::unique_ptr<QuicReceivedPacket>& packet) {
        QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
        PacketHeaderFormat unused_format;
        bool unused_version_flag;
        bool unused_use_length_prefix;
        QuicVersionLabel unused_version_label;
        ParsedQuicVersion unused_parsed_version = UnsupportedQuicVersion();
        QuicConnectionId unused_destination_connection_id;
        QuicConnectionId unused_source_connection_id;
        absl::optional<absl::string_view> unused_retry_token;
        std::string unused_detailed_error;
        QuicErrorCode error_code = QuicFramer::ParsePublicHeaderDispatcher(
            *packet, kQuicDefaultConnectionIdLength, &unused_format,
            &long_packet_type, &unused_version_flag, &unused_use_length_prefix,
            &unused_version_label, &unused_parsed_version,
            &unused_destination_connection_id, &unused_source_connection_id,
            &unused_retry_token, &unused_detailed_error);
        return error_code == QUIC_NO_ERROR && long_packet_type == INITIAL;
      })));

  QuicLongHeaderType long_packet_type = INVALID_PACKET_TYPE;
  PacketHeaderFormat unused_format;
  bool unused_version_flag;
  bool unused_use_length_prefix;
  QuicVersionLabel unused_version_label;
  ParsedQuicVersion unused_parsed_version = UnsupportedQuicVersion();
  QuicConnectionId unused_destination_connection_id;
  QuicConnectionId unused_source_connection_id;
  absl::optional<absl::string_view> unused_retry_token;
  std::string unused_detailed_error;
  QuicErrorCode error_code = QUIC_NO_ERROR;

  // Verify that packet_ is not an INITIAL packet.
  error_code = QuicFramer::ParsePublicHeaderDispatcher(
      packet_, kQuicDefaultConnectionIdLength, &unused_format,
      &long_packet_type, &unused_version_flag, &unused_use_length_prefix,
      &unused_version_label, &unused_parsed_version,
      &unused_destination_connection_id, &unused_source_connection_id,
      &unused_retry_token, &unused_detailed_error);
  EXPECT_THAT(error_code, IsQuicNoError());
  EXPECT_NE(long_packet_type, INITIAL);

  store_.EnqueuePacket(connection_id, false, packet_, self_address_,
                       peer_address_, valid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id, false, *initial_packets[0], self_address_,
                       peer_address_, valid_version_, kNoParsedChlo);
  store_.EnqueuePacket(connection_id, false, *initial_packets[1], self_address_,
                       peer_address_, valid_version_, kNoParsedChlo);

  BufferedPacketList delivered_packets = store_.DeliverPackets(connection_id);
  EXPECT_THAT(delivered_packets.buffered_packets, SizeIs(3));

  QuicLongHeaderType previous_packet_type = INITIAL;
  for (const auto& packet : delivered_packets.buffered_packets) {
    error_code = QuicFramer::ParsePublicHeaderDispatcher(
        *packet.packet, kQuicDefaultConnectionIdLength, &unused_format,
        &long_packet_type, &unused_version_flag, &unused_use_length_prefix,
        &unused_version_label, &unused_parsed_version,
        &unused_destination_connection_id, &unused_source_connection_id,
        &unused_retry_token, &unused_detailed_error);
    EXPECT_THAT(error_code, IsQuicNoError());

    // INITIAL packets should not follow a non-INITIAL packet.
    EXPECT_THAT(long_packet_type,
                Conditional(previous_packet_type == INITIAL,
                            A<QuicLongHeaderType>(), Ne(INITIAL)));
    previous_packet_type = long_packet_type;
  }
}
}  // namespace
}  // namespace test
}  // namespace quic
