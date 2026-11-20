// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// QuicMulticastClient (I3) on a mock session: the reader contract for each
// frame type, deferral before the opt-in, and a JOIN reaching the delegate.
// Then channel ingress through the client (C5, C6, lead decision 7): MC
// frames from a channel packet, MC_ACK on the unicast connection, and the
// unidirectional stream credit that channel streams use and give back.

#include "quiche/quic/core/quic_multicast_client.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/digest.h"
#include "openssl/sha.h"
#include "openssl/tls1.h"
#include "quiche/quic/core/crypto/crypto_utils.h"
#include "quiche/quic/core/crypto/quic_encrypter.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/frames/quic_frame.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_stream_id_manager.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace test {
namespace {

using ::testing::_;
using ::testing::AnyNumber;
using ::testing::Eq;
using ::testing::Return;

using JoinResult = QuicMulticastClient::JoinResult;

constexpr char kChannel[] = "demo-channel";

class MockDelegate : public QuicMulticastClient::Delegate {
 public:
  MOCK_METHOD(bool, JoinChannel,
              (absl::string_view, const QuicIpAddress&, const QuicIpAddress&,
               uint16_t),
              (override));
  MOCK_METHOD(void, LeaveChannel, (absl::string_view), (override));
};

// A17's embedder answers in JoinChannelWithResult. As a StrictMock it also
// proves that JoinChannel is never asked.
class MockResultDelegate : public QuicMulticastClient::Delegate {
 public:
  MOCK_METHOD(bool, JoinChannel,
              (absl::string_view, const QuicIpAddress&, const QuicIpAddress&,
               uint16_t),
              (override));
  MOCK_METHOD(JoinResult, JoinChannelWithResult,
              (absl::string_view, const QuicIpAddress&, const QuicIpAddress&,
               uint16_t),
              (override));
  MOCK_METHOD(void, LeaveChannel, (absl::string_view), (override));
};

// The type varint, then the body: one frame as it sits in a packet.
std::string Frame(uint64_t type, const std::string& body) {
  char buf[8];
  QuicDataWriter writer(sizeof(buf), buf);
  EXPECT_TRUE(writer.WriteVarInt62(type));
  return std::string(buf, writer.length()) + body;
}

QuicIpAddress Ip(const char* literal) {
  QuicIpAddress ip;
  EXPECT_TRUE(ip.FromString(literal));
  return ip;
}

absl::Span<const uint8_t> Bytes(absl::string_view s) {
  return absl::MakeConstSpan(reinterpret_cast<const uint8_t*>(s.data()),
                             s.size());
}

std::string Sha256(absl::string_view data) {
  std::string out(SHA256_DIGEST_LENGTH, '\0');
  SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(),
         reinterpret_cast<uint8_t*>(out.data()));
  return out;
}

// The C10 secrets, which the test channel uses.
std::string HeaderSecret() { return std::string(32, '\x11'); }
std::string KeySecret() { return std::string(32, '\x22'); }

// Seals |payload| as channel packet |pn| as Q's ChannelSendState does. The
// same sealer is in quic_multicast_channel_test.cc, where SealMatchesQ checks
// it byte for byte against Q's own packet. A rotated key passes its secret
// and its key phase (the sequence's parity).
std::string Seal(uint64_t pn, absl::string_view payload,
                 const std::string& key_secret = KeySecret(),
                 bool key_phase = true) {
  std::unique_ptr<QuicEncrypter> encrypter =
      QuicEncrypter::CreateFromCipherSuite(TLS1_3_CK_AES_128_GCM_SHA256);
  const std::string header_secret = HeaderSecret();
  CryptoUtils::SetKeyAndIV(EVP_sha256(), Bytes(key_secret),
                           ParsedQuicVersion::RFCv1(), encrypter.get());
  std::string hp_key(encrypter->GetKeySize(), '\0');
  EXPECT_TRUE(CryptoUtils::GenerateHeaderProtectionKey(
      EVP_sha256(), Bytes(header_secret), ParsedQuicVersion::RFCv1(),
      absl::MakeSpan(reinterpret_cast<uint8_t*>(hp_key.data()),
                     hp_key.size())));
  EXPECT_TRUE(encrypter->SetHeaderProtectionKey(hp_key));
  std::string packet =
      (key_phase ? "\x47" : "\x43") + std::string(kChannel);
  const size_t pn_offset = packet.size();
  for (int shift = 24; shift >= 0; shift -= 8) {
    packet.push_back(static_cast<char>(pn >> shift));
  }
  std::string sealed(payload.size() + 16, '\0');
  size_t sealed_length = 0;
  EXPECT_TRUE(encrypter->EncryptPacket(pn, packet, payload, sealed.data(),
                                       &sealed_length, sealed.size()));
  packet += sealed.substr(0, sealed_length);
  const std::string mask = encrypter->GenerateHeaderProtectionMask(
      absl::string_view(packet).substr(pn_offset + 4, 16));
  packet[0] ^= mask[0] & 0x1f;
  for (size_t i = 0; i < 4; ++i) {
    packet[pn_offset + i] ^= mask[1 + i];
  }
  return packet;
}

// STREAM with offset and length, and FIN if |fin|.
std::string StreamFrame(QuicStreamId id, uint64_t offset,
                        absl::string_view data, bool fin) {
  char buf[64];
  QuicDataWriter writer(sizeof(buf), buf);
  EXPECT_TRUE(writer.WriteVarInt62(fin ? 0x0f : 0x0e) &&
              writer.WriteVarInt62(id) && writer.WriteVarInt62(offset) &&
              writer.WriteVarInt62(data.size()) &&
              writer.WriteStringPiece(data));
  return std::string(buf, writer.length());
}

// Remembers the last alarm made with CreateAlarm(Delegate*): after the
// session's own, that is QuicMulticastClient's.
class RecordingAlarmFactory : public MockAlarmFactory {
 public:
  using MockAlarmFactory::CreateAlarm;
  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override {
    last_alarm = MockAlarmFactory::CreateAlarm(delegate);
    return last_alarm;
  }
  QuicAlarm* last_alarm = nullptr;
};

// Lets the session write control frames (WriteMulticastControlFrame needs
// 1-RTT keys).
class OneRttCryptoStream : public MockQuicCryptoStream {
 public:
  using MockQuicCryptoStream::MockQuicCryptoStream;
  bool one_rtt_keys_available() const override { return true; }
};

// A server unidirectional stream that discards data as it arrives, so the
// stream closes once its FIN is in.
class ReadOnlyStream : public QuicStream {
 public:
  ReadOnlyStream(QuicStreamId id, QuicSession* session)
      : QuicStream(id, session, /*is_static=*/false, READ_UNIDIRECTIONAL) {
    sequencer()->StopReading();
  }
  void OnDataAvailable() override {}
};

class QuicMulticastClientTest : public QuicTest {
 protected:
  QuicMulticastClientTest()
      : connection_(new MockQuicConnection(&helper_, &alarm_factory_,
                                           Perspective::IS_CLIENT)),
        session_(connection_) {
    auto client = std::make_unique<QuicMulticastClient>(
        &session_, &delegate_, std::vector<QuicIpAddress>{Ip("192.0.2.1")});
    client_ = client.get();
    session_.set_multicast_client(std::move(client));
  }

  // Feeds |frames| to the client as the framer would: read a type, hand the
  // reader over, go on while it answers kContinue.
  std::vector<QuicMulticastFrameStatus> Feed(const std::string& frames,
                                             size_t* remaining = nullptr) {
    QuicDataReader reader(frames);
    std::vector<QuicMulticastFrameStatus> statuses;
    while (!reader.IsDoneReading()) {
      uint64_t type;
      if (!reader.ReadVarInt62(&type)) {
        ADD_FAILURE() << "bad type varint";
        break;
      }
      const size_t before = reader.BytesRemaining();
      statuses.push_back(client_->OnMulticastFrame(type, &reader));
      if (statuses.back() != QuicMulticastFrameStatus::kContinue) {
        if (statuses.back() == QuicMulticastFrameStatus::kNotHandled) {
          EXPECT_EQ(reader.BytesRemaining(), before);  // Reader untouched.
        }
        break;
      }
    }
    if (remaining != nullptr) {
      *remaining = reader.BytesRemaining();
    }
    return statuses;
  }

  void ReceiveServerSupport() {
    TransportParameters params;
    params.custom_parameters[static_cast<TransportParameters::TransportParameterId>(
        kMcServerSupportId)] = "";
    std::string details;
    ASSERT_EQ(session_.config()->ProcessTransportParameters(
                  params, /*is_resumption=*/false, &details),
              QUIC_NO_ERROR)
        << details;
  }

  static QuicMcAnnounce Announce() {
    QuicMcAnnounce f;
    f.channel_id = kChannel;
    f.source = Ip("192.0.2.1");
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
  static std::string JoinFrames() {
    QuicMcKey key;
    key.channel_id = kChannel;
    key.key_sequence = 1;
    key.secret = std::string(32, 'k');
    QuicMcJoin join;
    join.channel_id = kChannel;
    join.key_sequence = 1;
    return Frame(kMcAnnounceV4, EncodeMcAnnounce(Announce())) +
           Frame(kMcKey, EncodeMcKey(key)) + Frame(kMcJoin, EncodeMcJoin(join));
  }

  // A17's client in place of the fixture's: no allowlist, and
  // result_delegate_ answers every JOIN.
  void UseResultDelegate() {
    auto client =
        std::make_unique<QuicMulticastClient>(&session_, &result_delegate_);
    client_ = client.get();
    session_.set_multicast_client(std::move(client));
  }

  // ANNOUNCE (the C10 header secret, Max ACK Delay 25 ms), KEY (the C10 key)
  // and JOIN after the opt-in. Control frames written from here on are
  // recorded in written_ and max_streams_.
  void JoinDemoChannel() {
    AcceptMulticast();
    EXPECT_CALL(delegate_, JoinChannel(Eq(kChannel), _, _, _))
        .WillOnce(Return(true));
    FeedDemoJoin();
    ASSERT_EQ(written_.size(), 2u);  // MC_LIMITS, MC_STATE JOINED.
    EXPECT_EQ(written_[1].first, kMcState);
    written_.clear();
  }

  // The opt-in, after which control frames written are recorded in written_
  // and max_streams_.
  void AcceptMulticast() {
    // OnChannelPacket's ScopedPacketFlusher asks the connection's visitor
    // whether it can write; an initialized session is that visitor. A clock
    // at zero reads as unset to QuicAlarm.
    connection_->set_visitor(&session_);
    helper_.AdvanceTime(QuicTime::Delta::FromSeconds(1));
    session_.SetCryptoStream(
        new testing::NiceMock<OneRttCryptoStream>(&session_));
    EXPECT_CALL(session_, WriteControlFrame(_, _))
        .Times(AnyNumber())
        .WillRepeatedly([this](const QuicFrame& frame, TransmissionType) {
          if (frame.type == MULTICAST_CONTROL_FRAME) {
            written_.emplace_back(frame.multicast_control_frame->frame_type,
                                  frame.multicast_control_frame->payload);
          } else if (frame.type == MAX_STREAMS_FRAME &&
                     frame.max_streams_frame.unidirectional) {
            max_streams_.push_back(frame.max_streams_frame.stream_count);
          }
          if (frame.type == MULTICAST_CONTROL_FRAME) {
            // -08 section 8: MC_ACK never goes through the manager.
            EXPECT_TRUE(QuicMulticastControlFrame::IsRetransmittable(
                frame.multicast_control_frame->frame_type));
          }
          return ClearControlFrame(frame);
        });
    // MC_ACK goes out as ACK does, outside the control frame manager.
    EXPECT_CALL(*connection_, SendNonRetransmittableMulticastFrame(_))
        .Times(AnyNumber())
        .WillRepeatedly([this](QuicMulticastControlFrame* frame) {
          EXPECT_FALSE(
              QuicMulticastControlFrame::IsRetransmittable(frame->frame_type));
          written_.emplace_back(frame->frame_type, frame->payload);
          delete frame;
          return true;
        });
    ReceiveServerSupport();
    client_->OnMulticastAccepted();
  }

  // The demo channel's ANNOUNCE, KEY and JOIN, on the unicast connection.
  void FeedDemoJoin() {
    QuicMcAnnounce announce = Announce();
    announce.header_secret = HeaderSecret();
    QuicMcKey key;
    key.channel_id = kChannel;
    key.key_sequence = 1;
    key.secret = KeySecret();
    QuicMcJoin join;
    join.channel_id = kChannel;
    join.limits_sequence = 1;
    join.key_sequence = 1;
    Feed(Frame(kMcAnnounceV4, EncodeMcAnnounce(announce)) +
         Frame(kMcKey, EncodeMcKey(key)) + Frame(kMcJoin, EncodeMcJoin(join)));
  }

  // Sends |payload| as channel packet |pn|: its MC_INTEGRITY on the unicast
  // connection, then the packet on the channel.
  void SendOnChannel(uint64_t pn, absl::string_view payload,
                     QuicEcnCodepoint ecn = ECN_NOT_ECT) {
    SendSealedOnChannel(pn, Seal(pn, payload), ecn);
  }
  void SendSealedOnChannel(uint64_t pn, const std::string& packet,
                           QuicEcnCodepoint ecn = ECN_NOT_ECT) {
    QuicMcIntegrity integrity;
    integrity.channel_id = kChannel;
    integrity.packet_number_start = pn;
    integrity.packet_hash_count = 1;
    integrity.packet_hashes = Sha256(packet);
    Feed(Frame(kMcIntegrityWithLength, EncodeMcIntegrity(integrity)));
    client_->OnChannelPacket(kChannel, packet, ecn, Now());
  }

  QuicTime Now() { return helper_.GetClock()->Now(); }

  std::pair<uint64_t, std::string> Ack(const QuicMcAck& ack) {
    return {ack.ecn.has_value() ? kMcAckEcn : kMcAck, EncodeMcAck(ack)};
  }

  MockQuicConnectionHelper helper_;
  RecordingAlarmFactory alarm_factory_;
  testing::StrictMock<MockDelegate> delegate_;
  testing::StrictMock<MockResultDelegate> result_delegate_;
  MockQuicConnection* connection_;  // Owned by session_.
  MockQuicSession session_;
  QuicMulticastClient* client_;  // Owned by session_.
  std::vector<std::pair<uint64_t, std::string>> written_;  // MC frames.
  std::vector<QuicStreamCount> max_streams_;  // Unidirectional MAX_STREAMS.
};

TEST_F(QuicMulticastClientTest, UnknownTypeIsNotHandled) {
  EXPECT_EQ(Feed(Frame(0xff3e8ff, "xyz")),
            std::vector<QuicMulticastFrameStatus>{
                QuicMulticastFrameStatus::kNotHandled});
}

TEST_F(QuicMulticastClientTest, TruncatedBodyIsError) {
  const std::string announce = EncodeMcAnnounce(Announce());
  EXPECT_EQ(Feed(Frame(kMcAnnounceV4, announce.substr(0, 5))),
            std::vector<QuicMulticastFrameStatus>{
                QuicMulticastFrameStatus::kError});
}

// Each decoder consumes exactly one body, so back-to-back frames all parse,
// including the client-sent types the client ignores.
TEST_F(QuicMulticastClientTest, ConsumesExactlyOneBodyPerFrame) {
  QuicMcLimits limits;
  limits.sequence = 1;
  limits.limits = QuicMcDefaultClientParams().limits;
  QuicMcState state;
  state.channel_id = kChannel;
  state.sequence = 1;
  state.state = QuicMcChannelState::kJoined;
  state.reason_code = kMcReasonRequestedByServer;
  QuicMcAck ack;
  ack.channel_id = kChannel;
  const std::string frames = JoinFrames() + Frame(kMcLimits, EncodeMcLimits(limits)) +
                             Frame(kMcState, EncodeMcState(state)) +
                             Frame(kMcAck, EncodeMcAck(ack));
  size_t remaining = 1;
  EXPECT_EQ(Feed(frames, &remaining),
            std::vector<QuicMulticastFrameStatus>(
                6, QuicMulticastFrameStatus::kContinue));
  EXPECT_EQ(remaining, 0u);
}

TEST_F(QuicMulticastClientTest, JoinWaitsForOptIn) {
  Feed(JoinFrames());  // StrictMock: no JoinChannel yet.
  ReceiveServerSupport();
  EXPECT_CALL(delegate_, JoinChannel(Eq(kChannel), Ip("192.0.2.1"),
                                     Ip("232.1.2.3"), 5002))
      .WillOnce(Return(true));
  client_->OnMulticastAccepted();
}

TEST_F(QuicMulticastClientTest, NoServerSupportNeverJoins) {
  Feed(JoinFrames());
  client_->OnMulticastAccepted();  // No TP 0xff3e808: StrictMock, no call.
  Feed(JoinFrames());
}

TEST_F(QuicMulticastClientTest, SourceOutsideAllowlistSkipsDelegate) {
  ReceiveServerSupport();
  client_->OnMulticastAccepted();
  QuicMcAnnounce announce = Announce();
  announce.source = Ip("198.51.100.7");
  QuicMcKey key;
  key.channel_id = kChannel;
  key.key_sequence = 1;
  key.secret = std::string(32, 'k');
  QuicMcJoin join;
  join.channel_id = kChannel;
  join.key_sequence = 1;
  Feed(Frame(kMcAnnounceV4, EncodeMcAnnounce(announce)) +
       Frame(kMcKey, EncodeMcKey(key)) + Frame(kMcJoin, EncodeMcJoin(join)));
}

// C6: the first MC_ACK for a channel goes on the unicast connection at once,
// as MC_ACK_ECN since its packet was ECT(0). The next packet waits Max ACK
// Delay; then the alarm sends one MC_ACK that covers both packet numbers.
TEST_F(QuicMulticastClientTest, ChannelPacketsAreAckedOnUnicast) {
  JoinDemoChannel();
  const std::string ping(1, '\x01');
  SendOnChannel(0, ping, ECN_ECT0);
  QuicMcAck want;
  want.channel_id = kChannel;
  want.ecn = QuicEcnCounts(1, 0, 0);
  ASSERT_EQ(written_.size(), 1u);
  EXPECT_EQ(written_[0], Ack(want));

  helper_.AdvanceTime(QuicTime::Delta::FromMilliseconds(5));
  const QuicTime second = Now();
  SendOnChannel(3, ping);
  EXPECT_EQ(written_.size(), 1u);
  ASSERT_NE(alarm_factory_.last_alarm, nullptr);
  EXPECT_EQ(alarm_factory_.last_alarm->deadline(),
            second + QuicTime::Delta::FromMilliseconds(25));

  helper_.AdvanceTime(QuicTime::Delta::FromMilliseconds(25));
  alarm_factory_.FireAlarm(alarm_factory_.last_alarm);
  want.largest_acknowledged = 3;
  want.ranges = {{/*gap=*/1, /*length=*/0}};  // PN 0, below the gap at 1-2.
  ASSERT_EQ(written_.size(), 2u);
  EXPECT_EQ(written_[1], Ack(want));
}

// The fork oracle's key rotation (main.rs, KeyReleaseDelay): channel packet
// 1 is sealed under key sequence 2 (key phase 0), its MC_INTEGRITY comes
// first, and MC_KEY 2 only after the packet. The packet waits for its key,
// then is acknowledged on the unicast connection.
TEST_F(QuicMulticastClientTest, PacketBeforeItsRotatedKeyIsAckedAfterIt) {
  JoinDemoChannel();
  const std::string rotated(32, '\x33');
  SendSealedOnChannel(1, Seal(1, std::string(1, '\x01'), rotated, false));
  EXPECT_TRUE(written_.empty());  // Not decrypted yet: nothing to acknowledge.
  QuicMcKey key;
  key.channel_id = kChannel;
  key.key_sequence = 2;
  key.from_packet_number = 1;
  key.secret = rotated;
  Feed(Frame(kMcKey, EncodeMcKey(key)));
  QuicMcAck want;
  want.channel_id = kChannel;
  want.largest_acknowledged = 1;
  ASSERT_EQ(written_.size(), 1u);
  EXPECT_EQ(written_[0], Ack(want));
}

// MC_LEAVE drops a packet still waiting for its key: the channel and its
// buffer go, and a key that arrives later acknowledges nothing.
TEST_F(QuicMulticastClientTest, LeaveDropsAPacketWaitingForItsKey) {
  JoinDemoChannel();
  const std::string rotated(32, '\x33');
  SendSealedOnChannel(1, Seal(1, std::string(1, '\x01'), rotated, false));
  ASSERT_NE(client_->channel_stats(kChannel), nullptr);
  QuicMcLeave leave;
  leave.channel_id = kChannel;
  EXPECT_CALL(delegate_, LeaveChannel(Eq(kChannel)));
  Feed(Frame(kMcLeave, EncodeMcLeave(leave)));
  EXPECT_EQ(client_->channel_stats(kChannel), nullptr);
  QuicMcKey key;
  key.channel_id = kChannel;
  key.key_sequence = 2;
  key.from_packet_number = 1;
  key.secret = rotated;
  Feed(Frame(kMcKey, EncodeMcKey(key)));
  ASSERT_EQ(written_.size(), 1u);  // MC_STATE LEFT, and no MC_ACK.
  EXPECT_EQ(written_[0].first, kMcState);
}

// -08 section 11: MC_RETIRE inside a channel packet reaches the control as a
// unicast copy would. With no data yet, After Packet Number does not hold it
// back, so the client leaves and sends MC_STATE RETIRED.
TEST_F(QuicMulticastClientTest, McRetireInChannelRetiresTheChannel) {
  JoinDemoChannel();
  QuicMcRetire retire;
  retire.channel_id = kChannel;
  retire.after_packet_number = 30;
  EXPECT_CALL(delegate_, LeaveChannel(Eq(kChannel)));
  SendOnChannel(4, Frame(kMcRetire, EncodeMcRetire(retire)));
  ASSERT_EQ(written_.size(), 1u);
  EXPECT_EQ(written_[0].first, kMcState);
  QuicDataReader reader(written_[0].second);
  QuicMcState state;
  ASSERT_TRUE(DecodeMcState(kMcState, &reader, &state));
  EXPECT_EQ(state.state, QuicMcChannelState::kRetired);
  // The channel is gone: a later packet is not read and not acknowledged.
  SendOnChannel(5, std::string(1, '\x01'));
  EXPECT_EQ(written_.size(), 1u);
}

// -08 section 11: a forbidden frame in a channel packet closes the
// connection (MC_EXTENSION_ERROR, mapped to QUIC_INVALID_FRAME_DATA).
TEST_F(QuicMulticastClientTest, ForbiddenFrameInChannelClosesTheConnection) {
  JoinDemoChannel();
  QuicMcAck ack;
  ack.channel_id = kChannel;
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_INVALID_FRAME_DATA, _,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET));
  SendOnChannel(0, Frame(kMcAck, EncodeMcAck(ack)));
  EXPECT_TRUE(written_.empty());  // The packet is not acknowledged.
}

// Lead decision 7: a shared stream ID that arrives on a channel counts as
// consumed on the unicast session, with every lower server unidirectional ID
// (here 15-3999, never sent to this session), and each stream that finishes
// gives one stream of credit back in MAX_STREAMS. Only the session's own
// stream accounting runs: the client hands it STREAM frames as frames.
TEST_F(QuicMulticastClientTest, ChannelStreamsUseAndReturnUniCredit) {
  QuicSessionPeer::SetMaxOpenIncomingUnidirectionalStreams(&session_, 1010);
  QuicSessionPeer::set_is_configured(&session_, true);  // MAX_STREAMS needs it.
  EXPECT_CALL(session_, CreateIncomingStream(_))
      .WillRepeatedly([this](QuicStreamId id) -> QuicStream* {
        auto stream = std::make_unique<ReadOnlyStream>(id, &session_);
        QuicStream* raw = stream.get();
        session_.ActivateStream(std::move(stream));
        return raw;
      });
  JoinDemoChannel();
  QuicStreamIdManager* uni =
      QuicSessionPeer::ietf_unidirectional_stream_id_manager(&session_);

  SendOnChannel(0, StreamFrame(4003, 0, "tick-0", /*fin=*/true));
  EXPECT_EQ(uni->largest_peer_created_stream_id(), 4003u);
  EXPECT_TRUE(uni->IsAvailableStream(15));  // Consumed, never opened.
  EXPECT_EQ(max_streams_, std::vector<QuicStreamCount>({1011}));

  SendOnChannel(1, StreamFrame(4007, 0, "tick-1", /*fin=*/false));
  EXPECT_EQ(uni->largest_peer_created_stream_id(), 4007u);
  EXPECT_EQ(max_streams_.size(), 1u);  // 4007 is still open.

  // Its end comes over unicast (recovery): the stream finishes and its
  // credit comes back.
  session_.OnStreamFrame(QuicStreamFrame(4007, /*fin=*/true, 6, ""));
  EXPECT_EQ(max_streams_, std::vector<QuicStreamCount>({1011, 1012}));
  // A late copy of a finished stream opens nothing and costs nothing.
  SendOnChannel(2, StreamFrame(4003, 0, "tick-0", /*fin=*/true));
  EXPECT_EQ(max_streams_.size(), 2u);
  EXPECT_EQ(uni->incoming_actual_max_streams(), 1012u);
}

// A17: a JOIN answered kPending sends nothing. CompleteJoin(kJoined) sends
// JOINED, and the channel kept since the JOIN reads and acknowledges data.
TEST_F(QuicMulticastClientTest, PendingThenJoinedDeliversPackets) {
  UseResultDelegate();
  AcceptMulticast();
  EXPECT_CALL(result_delegate_,
              JoinChannelWithResult(Eq(kChannel), Ip("192.0.2.1"),
                                    Ip("232.1.2.3"), 5002))
      .WillOnce(Return(JoinResult::kPending));
  FeedDemoJoin();
  ASSERT_EQ(written_.size(), 1u);  // MC_LIMITS only.
  EXPECT_EQ(written_[0].first, kMcLimits);
  written_.clear();

  client_->CompleteJoin(kChannel, JoinResult::kJoined);
  ASSERT_EQ(written_.size(), 1u);
  EXPECT_EQ(written_[0].first, kMcState);
  QuicDataReader reader(written_[0].second);
  QuicMcState state;
  ASSERT_TRUE(DecodeMcState(kMcState, &reader, &state));
  EXPECT_EQ(state.state, QuicMcChannelState::kJoined);
  written_.clear();

  SendOnChannel(0, std::string(1, '\x01'), ECN_ECT0);
  QuicMcAck want;
  want.channel_id = kChannel;
  want.ecn = QuicEcnCounts(1, 0, 0);
  ASSERT_EQ(written_.size(), 1u);
  EXPECT_EQ(written_[0], Ack(want));
}

// A17: OnChannelLost sends LEFT with the embedder's reason, never calls
// LeaveChannel (StrictMock), and drops the channel: a later packet is not
// read and not acknowledged.
TEST_F(QuicMulticastClientTest, ChannelLostDropsLaterPackets) {
  UseResultDelegate();
  AcceptMulticast();
  EXPECT_CALL(result_delegate_, JoinChannelWithResult(Eq(kChannel), _, _, _))
      .WillOnce(Return(JoinResult::kJoined));
  FeedDemoJoin();
  ASSERT_EQ(written_.size(), 2u);  // MC_LIMITS, MC_STATE JOINED.
  written_.clear();
  SendOnChannel(0, std::string(1, '\x01'));
  ASSERT_EQ(written_.size(), 1u);  // Its MC_ACK.
  written_.clear();

  client_->OnChannelLost(kChannel, kMcReasonMaxRateExceeded);
  EXPECT_EQ(client_->channel_stats(kChannel), nullptr);
  ASSERT_EQ(written_.size(), 1u);
  EXPECT_EQ(written_[0].first, kMcState);
  QuicDataReader reader(written_[0].second);
  QuicMcState state;
  ASSERT_TRUE(DecodeMcState(kMcState, &reader, &state));
  EXPECT_EQ(state.state, QuicMcChannelState::kLeft);
  EXPECT_EQ(state.reason_code, kMcReasonMaxRateExceeded);

  SendOnChannel(1, std::string(1, '\x01'));
  EXPECT_EQ(written_.size(), 1u);  // No MC_ACK.
}

}  // namespace
}  // namespace test
}  // namespace quic
