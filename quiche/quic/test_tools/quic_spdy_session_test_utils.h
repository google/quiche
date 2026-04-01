// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Shared test infrastructure for QuicSpdySession tests.
// Provides TestCryptoStream, TestStream, TestSession, and
// QuicSpdySessionTestBase — used by both quic_spdy_session_test.cc and
// the draft-15 WebTransport test suite.

#ifndef QUICHE_QUIC_TEST_TOOLS_QUIC_SPDY_SESSION_TEST_UTILS_H_
#define QUICHE_QUIC_TEST_TOOLS_QUIC_SPDY_SESSION_TEST_UTILS_H_

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>

#include "absl/memory/memory.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/crypto_protocol.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/quic_header_list.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/quic_spdy_stream.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_crypto_stream.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_session_peer.h"
#include "quiche/quic/test_tools/quic_spdy_session_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_endian.h"

namespace quic {
namespace test {

// ---------------------------------------------------------------------------
// TestCryptoStream — minimal crypto stream for unit tests.
// ---------------------------------------------------------------------------
class TestCryptoStream : public QuicCryptoStream, public QuicCryptoHandshaker {
 public:
  explicit TestCryptoStream(QuicSession* session)
      : QuicCryptoStream(session),
        QuicCryptoHandshaker(this, session),
        encryption_established_(false),
        one_rtt_keys_available_(false),
        params_(new QuicCryptoNegotiatedParameters) {
    // Simulate a negotiated cipher_suite with a fake value.
    params_->cipher_suite = 1;
  }

  void EstablishZeroRttEncryption() {
    encryption_established_ = true;
    session()->connection()->SetEncrypter(
        ENCRYPTION_ZERO_RTT,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_ZERO_RTT));
  }

  void OnHandshakeMessage(const CryptoHandshakeMessage& /*message*/) override {
    encryption_established_ = true;
    one_rtt_keys_available_ = true;
    QuicErrorCode error;
    std::string error_details;
    session()->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session()->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (session()->version().IsIetfQuic()) {
      if (session()->perspective() == Perspective::IS_CLIENT) {
        session()->config()->SetOriginalConnectionIdToSend(
            session()->connection()->connection_id());
        session()->config()->SetInitialSourceConnectionIdToSend(
            session()->connection()->connection_id());
      } else {
        session()->config()->SetInitialSourceConnectionIdToSend(
            session()->connection()->client_connection_id());
      }
      TransportParameters transport_parameters;
      EXPECT_TRUE(
          session()->config()->FillTransportParameters(&transport_parameters));
      error = session()->config()->ProcessTransportParameters(
          transport_parameters, /* is_resumption = */ false, &error_details);
    } else {
      CryptoHandshakeMessage msg;
      session()->config()->ToHandshakeMessage(&msg, transport_version());
      error =
          session()->config()->ProcessPeerHello(msg, CLIENT, &error_details);
    }
    EXPECT_THAT(error, IsQuicNoError());
    session()->OnNewEncryptionKeyAvailable(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
    session()->OnConfigNegotiated();
    if (session()->connection()->version().IsIetfQuic()) {
      session()->OnTlsHandshakeComplete();
    } else {
      session()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    session()->DiscardOldEncryptionKey(ENCRYPTION_INITIAL);
  }

  // QuicCryptoStream implementation
  ssl_early_data_reason_t EarlyDataReason() const override {
    return ssl_early_data_unknown;
  }
  bool encryption_established() const override {
    return encryption_established_;
  }
  bool one_rtt_keys_available() const override {
    return one_rtt_keys_available_;
  }
  HandshakeState GetHandshakeState() const override {
    return one_rtt_keys_available() ? HANDSHAKE_COMPLETE : HANDSHAKE_START;
  }
  void SetServerApplicationStateForResumption(
      std::unique_ptr<ApplicationState> /*application_state*/) override {}
  std::unique_ptr<QuicDecrypter> AdvanceKeysAndCreateCurrentOneRttDecrypter()
      override {
    return nullptr;
  }
  std::unique_ptr<QuicEncrypter> CreateCurrentOneRttEncrypter() override {
    return nullptr;
  }
  const QuicCryptoNegotiatedParameters& crypto_negotiated_params()
      const override {
    return *params_;
  }
  CryptoMessageParser* crypto_message_parser() override {
    return QuicCryptoHandshaker::crypto_message_parser();
  }
  void OnPacketDecrypted(EncryptionLevel /*level*/) override {}
  void OnOneRttPacketAcknowledged() override {}
  void OnHandshakePacketSent() override {}
  void OnHandshakeDoneReceived() override {}
  void OnNewTokenReceived(absl::string_view /*token*/) override {}
  std::string GetAddressToken(
      const CachedNetworkParameters* /*cached_network_params*/) const override {
    return "";
  }
  bool ValidateAddressToken(absl::string_view /*token*/) const override {
    return true;
  }
  const CachedNetworkParameters* PreviousCachedNetworkParams() const override {
    return nullptr;
  }
  void SetPreviousCachedNetworkParams(
      CachedNetworkParameters /*cached_network_params*/) override {}

  MOCK_METHOD(void, OnCanWrite, (), (override));

  bool HasPendingCryptoRetransmission() const override { return false; }

  MOCK_METHOD(bool, HasPendingRetransmission, (), (const, override));

  void OnConnectionClosed(const QuicConnectionCloseFrame& /*frame*/,
                          ConnectionCloseSource /*source*/) override {}
  SSL* GetSsl() const override { return nullptr; }
  bool IsCryptoFrameExpectedForEncryptionLevel(
      EncryptionLevel level) const override {
    return level != ENCRYPTION_ZERO_RTT;
  }
  EncryptionLevel GetEncryptionLevelToSendCryptoDataOfSpace(
      PacketNumberSpace space) const override {
    switch (space) {
      case INITIAL_DATA:
        return ENCRYPTION_INITIAL;
      case HANDSHAKE_DATA:
        return ENCRYPTION_HANDSHAKE;
      case APPLICATION_DATA:
        return ENCRYPTION_FORWARD_SECURE;
      default:
        QUICHE_DCHECK(false);
        return NUM_ENCRYPTION_LEVELS;
    }
  }

  bool ExportKeyingMaterial(absl::string_view /*label*/,
                            absl::string_view /*context*/,
                            size_t /*result_len*/, std::string*
                            /*result*/) override {
    return false;
  }

 private:
  using QuicCryptoStream::session;

  bool encryption_established_;
  bool one_rtt_keys_available_;
  quiche::QuicheReferenceCountedPointer<QuicCryptoNegotiatedParameters> params_;
};

// ---------------------------------------------------------------------------
// TestStream — minimal SPDY stream for unit tests.
// ---------------------------------------------------------------------------
class TestStream : public QuicSpdyStream {
 public:
  TestStream(QuicStreamId id, QuicSpdySession* session, StreamType type)
      : QuicSpdyStream(id, session, type) {}

  TestStream(PendingStream* pending, QuicSpdySession* session)
      : QuicSpdyStream(pending, session) {}

  using QuicStream::CloseWriteSide;

  void OnBodyAvailable() override {}

  MOCK_METHOD(void, OnCanWrite, (), (override));
  MOCK_METHOD(bool, RetransmitStreamData,
              (QuicStreamOffset, QuicByteCount, bool, TransmissionType),
              (override));

  MOCK_METHOD(bool, HasPendingRetransmission, (), (const, override));

 protected:
  bool ValidateReceivedHeaders(const QuicHeaderList& /*header_list*/) override {
    return true;
  }
};

// ---------------------------------------------------------------------------
// TestSession — QuicSpdySession subclass for unit tests.
// ---------------------------------------------------------------------------
class TestSession : public QuicSpdySession {
 public:
  explicit TestSession(QuicConnection* connection)
      : QuicSpdySession(connection, nullptr, DefaultQuicConfig(),
                        CurrentSupportedVersions()),
        crypto_stream_(this),
        writev_consumes_all_data_(false) {
    this->connection()->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<TaggingEncrypter>(ENCRYPTION_FORWARD_SECURE));
    if (this->connection()->version().IsIetfQuic()) {
      QuicConnectionPeer::SetAddressValidated(this->connection());
    }
  }

  ~TestSession() override { DeleteConnection(); }

  TestCryptoStream* GetMutableCryptoStream() override {
    return &crypto_stream_;
  }

  const TestCryptoStream* GetCryptoStream() const override {
    return &crypto_stream_;
  }

  TestStream* CreateOutgoingBidirectionalStream() override {
    TestStream* stream = new TestStream(GetNextOutgoingBidirectionalStreamId(),
                                        this, BIDIRECTIONAL);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  TestStream* CreateIncomingStream(QuicStreamId id) override {
    // Enforce the limit on the number of open streams.
    if (!VersionIsIetfQuic(connection()->transport_version()) &&
        stream_id_manager().num_open_incoming_streams() + 1 >
            max_open_incoming_bidirectional_streams()) {
      connection()->CloseConnection(
          QUIC_TOO_MANY_OPEN_STREAMS, "Too many streams!",
          ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET);
      return nullptr;
    } else {
      TestStream* stream = new TestStream(
          id, this,
          DetermineStreamType(id, connection()->version(), perspective(),
                              /*is_incoming=*/true, BIDIRECTIONAL));
      ActivateStream(absl::WrapUnique(stream));
      return stream;
    }
  }

  TestStream* CreateIncomingStream(PendingStream* pending) override {
    TestStream* stream = new TestStream(pending, this);
    ActivateStream(absl::WrapUnique(stream));
    return stream;
  }

  bool ShouldCreateIncomingStream(QuicStreamId /*id*/) override { return true; }

  bool ShouldCreateOutgoingBidirectionalStream() override { return true; }

  bool IsClosedStream(QuicStreamId id) {
    return QuicSession::IsClosedStream(id);
  }

  QuicStream* GetOrCreateStream(QuicStreamId stream_id) {
    return QuicSpdySession::GetOrCreateStream(stream_id);
  }

  QuicConsumedData WritevData(QuicStreamId id, size_t write_length,
                              QuicStreamOffset offset, StreamSendingState state,
                              TransmissionType type,
                              EncryptionLevel level) override {
    bool fin = state != NO_FIN;
    QuicConsumedData consumed(write_length, fin);
    if (!writev_consumes_all_data_) {
      consumed =
          QuicSession::WritevData(id, write_length, offset, state, type, level);
    }
    QuicSessionPeer::GetWriteBlockedStreams(this)->UpdateBytesForStream(
        id, consumed.bytes_consumed);
    return consumed;
  }

  void set_writev_consumes_all_data(bool val) {
    writev_consumes_all_data_ = val;
  }

  QuicConsumedData SendStreamData(QuicStream* stream) {
    if (!QuicUtils::IsCryptoStreamId(connection()->transport_version(),
                                     stream->id()) &&
        connection()->encryption_level() != ENCRYPTION_FORWARD_SECURE) {
      this->connection()->SetDefaultEncryptionLevel(ENCRYPTION_FORWARD_SECURE);
    }
    QuicStreamPeer::SendBuffer(stream).SaveStreamData("not empty");
    QuicConsumedData consumed =
        WritevData(stream->id(), 9, 0, FIN, NOT_RETRANSMISSION,
                   GetEncryptionLevelToSendApplicationData());
    QuicStreamPeer::SendBuffer(stream).OnStreamDataConsumed(
        consumed.bytes_consumed);
    return consumed;
  }

  QuicConsumedData SendLargeFakeData(QuicStream* stream, int bytes) {
    QUICHE_DCHECK(writev_consumes_all_data_);
    return WritevData(stream->id(), bytes, 0, FIN, NOT_RETRANSMISSION,
                      GetEncryptionLevelToSendApplicationData());
  }

  WebTransportHttp3VersionSet LocallySupportedWebTransportVersions()
      const override {
    return locally_supported_web_transport_versions_;
  }
  void set_supports_webtransport(bool value) {
    locally_supported_web_transport_versions_ =
        value ? kDefaultSupportedWebTransportVersions
              : WebTransportHttp3VersionSet();
  }
  void set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet versions) {
    locally_supported_web_transport_versions_ = std::move(versions);
  }

  HttpDatagramSupport LocalHttpDatagramSupport() override {
    return local_http_datagram_support_;
  }
  void set_local_http_datagram_support(HttpDatagramSupport value) {
    local_http_datagram_support_ = value;
  }

  MOCK_METHOD(void, OnAcceptChFrame, (const AcceptChFrame&), (override));

  using QuicSession::closed_streams;
  using QuicSession::pending_streams_size;
  using QuicSession::ShouldKeepConnectionAlive;
  using QuicSpdySession::settings;
  using QuicSpdySession::UsesPendingStreamForFrame;

 private:
  testing::StrictMock<TestCryptoStream> crypto_stream_;

  bool writev_consumes_all_data_;
  WebTransportHttp3VersionSet locally_supported_web_transport_versions_;
  HttpDatagramSupport local_http_datagram_support_ = HttpDatagramSupport::kNone;
};

// ---------------------------------------------------------------------------
// QuicSpdySessionTestBase — parameterized test fixture base class.
// ---------------------------------------------------------------------------
class QuicSpdySessionTestBase : public QuicTestWithParam<ParsedQuicVersion> {
 public:
  bool ClearMaxStreamsControlFrame(const QuicFrame& frame) {
    if (frame.type == MAX_STREAMS_FRAME) {
      DeleteFrame(&const_cast<QuicFrame&>(frame));
      return true;
    }
    return false;
  }

 protected:
  explicit QuicSpdySessionTestBase(Perspective perspective,
                                   bool allow_extended_connect = true)
      : connection_(new testing::StrictMock<MockQuicConnection>(
            &helper_, &alarm_factory_, perspective,
            SupportedVersions(GetParam()))),
        allow_extended_connect_(allow_extended_connect) {}

  void Initialize() {
    session_.emplace(connection_);
    if (qpack_maximum_dynamic_table_capacity_.has_value()) {
      session_->set_qpack_maximum_dynamic_table_capacity(
          *qpack_maximum_dynamic_table_capacity_);
    }
    if (connection_->perspective() == Perspective::IS_SERVER &&
        VersionIsIetfQuic(transport_version())) {
      session_->set_allow_extended_connect(allow_extended_connect_);
    }
    session_->Initialize();
    session_->config()->SetInitialStreamFlowControlWindowToSend(
        kInitialStreamFlowControlWindowForTest);
    session_->config()->SetInitialSessionFlowControlWindowToSend(
        kInitialSessionFlowControlWindowForTest);
    if (VersionIsIetfQuic(transport_version())) {
      QuicConfigPeer::SetReceivedMaxUnidirectionalStreams(
          session_->config(), kHttp3StaticUnidirectionalStreamCount);
    }
    QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesUnidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesOutgoingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    session_->OnConfigNegotiated();
    connection_->AdvanceTime(QuicTime::Delta::FromSeconds(1));
    TestCryptoStream* crypto_stream = session_->GetMutableCryptoStream();
    EXPECT_CALL(*crypto_stream, HasPendingRetransmission())
        .Times(testing::AnyNumber());
    writer_ = static_cast<MockPacketWriter*>(
        QuicConnectionPeer::GetWriter(session_->connection()));
  }

  void CheckClosedStreams() {
    QuicStreamId first_stream_id = QuicUtils::GetFirstBidirectionalStreamId(
        transport_version(), Perspective::IS_CLIENT);
    if (!VersionIsIetfQuic(transport_version())) {
      first_stream_id = QuicUtils::GetCryptoStreamId(transport_version());
    }
    for (QuicStreamId i = first_stream_id; i < 100; i++) {
      if (closed_streams_.find(i) == closed_streams_.end()) {
        EXPECT_FALSE(session_->IsClosedStream(i)) << " stream id: " << i;
      } else {
        EXPECT_TRUE(session_->IsClosedStream(i)) << " stream id: " << i;
      }
    }
  }

  void CloseStream(QuicStreamId id) {
    if (!VersionIsIetfQuic(transport_version())) {
      EXPECT_CALL(*connection_, SendControlFrame(testing::_))
          .WillOnce(&ClearControlFrame);
    } else {
      // IETF QUIC has two frames, RST_STREAM and STOP_SENDING
      EXPECT_CALL(*connection_, SendControlFrame(testing::_))
          .Times(2)
          .WillRepeatedly(&ClearControlFrame);
    }
    EXPECT_CALL(*connection_, OnStreamReset(id, testing::_));

    // QPACK streams might write data upon stream reset. Let the test session
    // handle the data.
    session_->set_writev_consumes_all_data(true);

    session_->ResetStream(id, QUIC_STREAM_CANCELLED);
    closed_streams_.insert(id);
  }

  ParsedQuicVersion version() const { return connection_->version(); }

  QuicTransportVersion transport_version() const {
    return connection_->transport_version();
  }

  QuicStreamId GetNthClientInitiatedBidirectionalId(int n) {
    return GetNthClientInitiatedBidirectionalStreamId(transport_version(), n);
  }

  QuicStreamId GetNthServerInitiatedBidirectionalId(int n) {
    return GetNthServerInitiatedBidirectionalStreamId(transport_version(), n);
  }

  QuicStreamId IdDelta() {
    return QuicUtils::StreamIdDelta(transport_version());
  }

  QuicStreamCount StreamCountToId(QuicStreamCount stream_count,
                                  Perspective perspective, bool bidirectional) {
    // Calculate and build up stream ID rather than use
    // GetFirst... because the test that relies on this method
    // needs to do the stream count where #1 is 0/1/2/3, and not
    // take into account that stream 0 is special.
    QuicStreamId id =
        ((stream_count - 1) * QuicUtils::StreamIdDelta(transport_version()));
    if (!bidirectional) {
      id |= 0x2;
    }
    if (perspective == Perspective::IS_SERVER) {
      id |= 0x1;
    }
    return id;
  }

  void CompleteHandshake() {
    if (VersionIsIetfQuic(transport_version())) {
      EXPECT_CALL(*writer_, WritePacket(testing::_, testing::_, testing::_,
                                        testing::_, testing::_, testing::_))
          .WillOnce(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));
    }
    if (connection_->version().IsIetfQuic() &&
        connection_->perspective() == Perspective::IS_SERVER) {
      // HANDSHAKE_DONE frame.
      EXPECT_CALL(*connection_, SendControlFrame(testing::_))
          .WillOnce(&ClearControlFrame);
    }

    CryptoHandshakeMessage message;
    session_->GetMutableCryptoStream()->OnHandshakeMessage(message);
    testing::Mock::VerifyAndClearExpectations(writer_);
    testing::Mock::VerifyAndClearExpectations(connection_);
  }

  void ReceiveWebTransportSettings(WebTransportHttp3VersionSet versions =
                                       kDefaultSupportedWebTransportVersions) {
    SettingsFrame settings;
    settings.values[SETTINGS_H3_DATAGRAM] = 1;
    if (versions.IsSet(WebTransportHttp3Version::kDraft02)) {
      settings.values[SETTINGS_WEBTRANS_DRAFT00] = 1;
    }
    if (versions.IsSet(WebTransportHttp3Version::kDraft07)) {
      settings.values[SETTINGS_WEBTRANS_MAX_SESSIONS_DRAFT07] = 16;
    }
    settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
    std::string data = std::string(1, kControlStream) +
                       HttpEncoder::SerializeSettingsFrame(settings);
    QuicStreamId control_stream_id =
        session_->perspective() == Perspective::IS_SERVER
            ? GetNthClientInitiatedUnidirectionalStreamId(transport_version(),
                                                          3)
            : GetNthServerInitiatedUnidirectionalStreamId(transport_version(),
                                                          3);
    QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
    session_->OnStreamFrame(frame);
  }

  void ReceiveWebTransportSession(WebTransportSessionId session_id) {
    QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
    session_->OnStreamFrame(frame);
    QuicSpdyStream* stream =
        static_cast<QuicSpdyStream*>(session_->GetOrCreateStream(session_id));
    QuicHeaderList headers;
    headers.OnHeader(":method", "CONNECT");
    headers.OnHeader(":protocol", "webtransport");
    stream->OnStreamHeaderList(/*fin=*/true, 0, headers);
    WebTransportHttp3* web_transport =
        session_->GetWebTransportSession(session_id);
    ASSERT_TRUE(web_transport != nullptr);
    quiche::HttpHeaderBlock header_block;
    web_transport->HeadersReceived(header_block);
  }

  void ReceiveWebTransportUnidirectionalStream(
      WebTransportSessionId session_id, QuicStreamId stream_id,
      absl::string_view payload = "test data") {
    std::string data;
    // Encode the stream type as a QUIC varint.
    char type_buf[8];
    QuicDataWriter type_writer(sizeof(type_buf), type_buf);
    ASSERT_TRUE(type_writer.WriteVarInt62(kWebTransportUnidirectionalStream));
    data.append(type_buf, type_writer.length());
    // Encode session_id as varint.
    char varint_buf[8];
    QuicDataWriter varint_writer(sizeof(varint_buf), varint_buf);
    ASSERT_TRUE(varint_writer.WriteVarInt62(session_id));
    data.append(varint_buf, varint_writer.length());
    data.append(payload);
    QuicStreamFrame frame(stream_id, /*fin=*/false, /*offset=*/0, data);
    session_->OnStreamFrame(frame);
  }

  void TestHttpDatagramSetting(HttpDatagramSupport local_support,
                               HttpDatagramSupport remote_support,
                               HttpDatagramSupport expected_support,
                               bool expected_datagram_supported);

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  testing::StrictMock<MockQuicConnection>* connection_;
  bool allow_extended_connect_;
  std::optional<TestSession> session_;
  std::set<QuicStreamId> closed_streams_;
  std::optional<uint64_t> qpack_maximum_dynamic_table_capacity_;
  MockPacketWriter* writer_;
};

}  // namespace test
}  // namespace quic

#endif  // QUICHE_QUIC_TEST_TOOLS_QUIC_SPDY_SESSION_TEST_UTILS_H_
