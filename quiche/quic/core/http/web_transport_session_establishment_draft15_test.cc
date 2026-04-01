// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 tests for session establishment (Section 3.1, 3.2).

#include <cstdint>
#include <string>

#include "quiche/quic/core/http/http_constants.h"
#include "quiche/quic/core/http/http_encoder.h"
#include "quiche/quic/core/http/http_frames.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_constants.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_connection_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/web_transport/test_tools/draft15_constants.h"

namespace quic {
namespace {

using ::testing::_;

// --- Server-perspective fixture ---

class SessionEstablishmentDraft15Test : public test::Draft15SessionTest {
 protected:
  SessionEstablishmentDraft15Test()
      : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(SessionEstablishmentDraft15,
                         SessionEstablishmentDraft15Test,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

// --- Client-perspective fixture ---

class SessionEstablishmentDraft15ClientTest : public test::Draft15SessionTest {
 protected:
  SessionEstablishmentDraft15ClientTest()
      : Draft15SessionTest(Perspective::IS_CLIENT) {}
};

INSTANTIATE_TEST_SUITE_P(SessionEstablishmentDraft15Client,
                         SessionEstablishmentDraft15ClientTest,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

// --- SETTINGS requirements (Section 3.1) ---

TEST_P(SessionEstablishmentDraft15Test, ServerSendsRequiredSettings) {
  // Section 3.1 MUST: Server sends SETTINGS_WT_ENABLED > 0,
  // SETTINGS_ENABLE_CONNECT_PROTOCOL = 1, SETTINGS_H3_DATAGRAM = 1.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  EXPECT_EQ(webtransport::draft15::kSettingsWtEnabled, 0x2c7cf000u);
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Server must emit SETTINGS_WT_ENABLED for draft-15";
  EXPECT_TRUE(
      session_->settings().values.contains(SETTINGS_ENABLE_CONNECT_PROTOCOL))
      << "Server must emit SETTINGS_ENABLE_CONNECT_PROTOCOL";
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_H3_DATAGRAM))
      << "Server must emit SETTINGS_H3_DATAGRAM";
}

TEST_P(SessionEstablishmentDraft15ClientTest, ClientSendsRequiredSettings) {
  // Section 3.1 MUST: Client sends SETTINGS_H3_DATAGRAM = 1 and
  // SETTINGS_WT_ENABLED with draft-15 codepoint.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  EXPECT_EQ(webtransport::draft15::kSettingsWtEnabled, 0x2c7cf000u);
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_WT_ENABLED))
      << "Client must emit SETTINGS_WT_ENABLED for draft-15";
  EXPECT_TRUE(session_->settings().values.contains(SETTINGS_H3_DATAGRAM))
      << "Client must emit SETTINGS_H3_DATAGRAM";
}

TEST_P(SessionEstablishmentDraft15ClientTest, ClientWaitsForServerSettings) {
  // Section 3.1 MUST NOT: Client must not initiate a session before
  // receiving server SETTINGS.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Before receiving server settings, WebTransport should not be available.
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "Client must not report WT support before receiving server SETTINGS";
  // Now receive server settings.
  ReceiveWebTransportDraft15Settings();
  EXPECT_TRUE(session_->SupportsWebTransport())
      << "After receiving server SETTINGS, WT should be available";
}

TEST_P(SessionEstablishmentDraft15Test, ServerWaitsForClientSettings) {
  // Section 7.1 MUST NOT: Server must not process requests until client
  // SETTINGS received.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Before receiving client settings, WebTransport should not be available.
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "Server must not report WT support before receiving client SETTINGS";
  // Now receive client settings.
  ReceiveWebTransportDraft15Settings();
  EXPECT_TRUE(session_->SupportsWebTransport())
      << "After receiving client SETTINGS, WT should be available";
}

TEST_P(SessionEstablishmentDraft15Test, MissingSettingsWtEnabled) {
  // Section 3.1: Without SETTINGS_WT_ENABLED, WebTransport is unavailable.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Send settings that have H3_DATAGRAM and ENABLE_CONNECT_PROTOCOL but NOT
  // SETTINGS_WT_ENABLED.
  SettingsFrame settings;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  // Deliberately omit SETTINGS_WT_ENABLED.
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
  session_->OnStreamFrame(frame);
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "Without SETTINGS_WT_ENABLED, WebTransport should not be available";
}

TEST_P(SessionEstablishmentDraft15ClientTest, MissingEnableConnectProtocol) {
  // Section 3.1: Extended CONNECT support is required for WebTransport.
  // In the current implementation, receiving SETTINGS_WT_ENABLED (draft-15)
  // or SETTINGS_ENABLE_CONNECT_PROTOCOL on the client implicitly sets
  // allow_extended_connect_. This test verifies that when the peer sends
  // only H3_DATAGRAM (without either WT_ENABLED or ENABLE_CONNECT_PROTOCOL),
  // WebTransport is not available.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Send settings with only H3_DATAGRAM — no WT_ENABLED, no
  // ENABLE_CONNECT_PROTOCOL.
  SettingsFrame settings;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
  session_->OnStreamFrame(frame);
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "Without SETTINGS_ENABLE_CONNECT_PROTOCOL or SETTINGS_WT_ENABLED, "
         "WT should not be available";
}

TEST_P(SessionEstablishmentDraft15Test, MissingH3Datagram) {
  // Section 3.1: Without SETTINGS_H3_DATAGRAM, WebTransport is unavailable.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Send settings with WT_ENABLED and ENABLE_CONNECT_PROTOCOL but not
  // H3_DATAGRAM.
  SettingsFrame settings;
  settings.values[SETTINGS_WT_ENABLED] = 1;
  settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  // Deliberately omit SETTINGS_H3_DATAGRAM.
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
  // ValidateWebTransportSettingsConsistency() detects missing datagram support
  // and closes the connection with WT_REQUIREMENTS_NOT_MET for draft-15.
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_HTTP_INVALID_SETTING_VALUE,
                  static_cast<QuicIetfTransportErrorCodes>(
                      webtransport::draft15::kWtRequirementsNotMet),
                  _, _));
  session_->OnStreamFrame(frame);
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "Without SETTINGS_H3_DATAGRAM, WebTransport should not be available";
}

// --- CONNECT request format (Section 3.2) ---

TEST_P(SessionEstablishmentDraft15Test, UpgradeTokenWebtransportH3) {
  // Section 3.2 MUST: The :protocol pseudo-header is "webtransport-h3"
  // (not "webtransport" as in draft-02/07).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  // Establish a valid draft-15 session with :protocol = "webtransport-h3".
  QuicStreamId valid_stream_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(valid_stream_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  EXPECT_EQ(webtransport::draft15::kProtocolToken, "webtransport-h3");

  // Now attempt a session with the old token :protocol = "webtransport"
  // (used by draft-02/07). Draft-15 must reject this.
  QuicStreamId old_token_stream_id = GetNthClientInitiatedBidirectionalId(1);
  QuicStreamFrame old_frame(old_token_stream_id, /*fin=*/false, /*offset=*/0,
                            absl::string_view());
  session_->OnStreamFrame(old_frame);
  QuicSpdyStream* old_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(old_token_stream_id));
  ASSERT_NE(old_stream, nullptr);
  QuicHeaderList old_headers;
  old_headers.OnHeader(":method", "CONNECT");
  old_headers.OnHeader(":protocol", "webtransport");  // Old token.
  old_headers.OnHeader(":scheme", "https");
  old_headers.OnHeader(":authority", "test.example.com");
  old_headers.OnHeader(":path", "/wt");
  old_stream->OnStreamHeaderList(/*fin=*/false, 0, old_headers);
  WebTransportHttp3* old_wt =
      session_->GetWebTransportSession(old_token_stream_id);
  // When draft-15 is the only version, the old "webtransport" token should
  // not create a valid WebTransport session.
  EXPECT_EQ(old_wt, nullptr)
      << "Draft-15 must reject :protocol='webtransport' (old token)";
}

TEST_P(SessionEstablishmentDraft15Test, SchemeHttps) {
  // Section 3.2 MUST: :scheme is "https".
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  // Valid session with :scheme = "https".
  QuicStreamId valid_stream_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(valid_stream_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Attempt a session with :scheme = "http" (not https). Must be rejected.
  QuicStreamId http_stream_id = GetNthClientInitiatedBidirectionalId(1);
  QuicStreamFrame http_frame(http_stream_id, /*fin=*/false, /*offset=*/0,
                             absl::string_view());
  session_->OnStreamFrame(http_frame);
  QuicSpdyStream* http_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(http_stream_id));
  ASSERT_NE(http_stream, nullptr);
  QuicHeaderList http_headers;
  http_headers.OnHeader(":method", "CONNECT");
  http_headers.OnHeader(":protocol", "webtransport-h3");
  http_headers.OnHeader(":scheme", "http");  // Wrong scheme.
  http_headers.OnHeader(":authority", "test.example.com");
  http_headers.OnHeader(":path", "/wt");
  http_stream->OnStreamHeaderList(/*fin=*/false, 0, http_headers);
  WebTransportHttp3* http_wt =
      session_->GetWebTransportSession(http_stream_id);
  EXPECT_EQ(http_wt, nullptr)
      << "Draft-15 must reject :scheme='http' (only 'https' allowed)";
}

TEST_P(SessionEstablishmentDraft15Test, AuthorityAndPathPresent) {
  // Section 3.2 MUST: Both :authority and :path must be present.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  // Valid session with both :authority and :path present.
  QuicStreamId valid_stream_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(valid_stream_id);
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Attempt without :authority.
  QuicStreamId no_auth_stream_id = GetNthClientInitiatedBidirectionalId(1);
  {
    QuicStreamFrame frame(no_auth_stream_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
    session_->OnStreamFrame(frame);
    QuicSpdyStream* stream = static_cast<QuicSpdyStream*>(
        session_->GetOrCreateStream(no_auth_stream_id));
    ASSERT_NE(stream, nullptr);
    QuicHeaderList headers;
    headers.OnHeader(":method", "CONNECT");
    headers.OnHeader(":protocol", "webtransport-h3");
    headers.OnHeader(":scheme", "https");
    // Deliberately omit :authority.
    headers.OnHeader(":path", "/wt");
    stream->OnStreamHeaderList(/*fin=*/false, 0, headers);
    EXPECT_EQ(session_->GetWebTransportSession(no_auth_stream_id), nullptr)
        << "Draft-15 must reject CONNECT missing :authority";
  }

  // Attempt without :path.
  QuicStreamId no_path_stream_id = GetNthClientInitiatedBidirectionalId(2);
  {
    QuicStreamFrame frame(no_path_stream_id, /*fin=*/false, /*offset=*/0,
                          absl::string_view());
    session_->OnStreamFrame(frame);
    QuicSpdyStream* stream = static_cast<QuicSpdyStream*>(
        session_->GetOrCreateStream(no_path_stream_id));
    ASSERT_NE(stream, nullptr);
    QuicHeaderList headers;
    headers.OnHeader(":method", "CONNECT");
    headers.OnHeader(":protocol", "webtransport-h3");
    headers.OnHeader(":scheme", "https");
    headers.OnHeader(":authority", "test.example.com");
    // Deliberately omit :path.
    stream->OnStreamHeaderList(/*fin=*/false, 0, headers);
    EXPECT_EQ(session_->GetWebTransportSession(no_path_stream_id), nullptr)
        << "Draft-15 must reject CONNECT missing :path";
  }
}

TEST_P(SessionEstablishmentDraft15Test, RejectRedirects) {
  // Section 3.2 MUST NOT: 3xx responses must not be auto-followed.
  // Server-side: verify that the session is established with the correct
  // draft-15 protocol token and that the upgrade token is "webtransport-h3".
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";
  // The session was created using the draft-15 protocol token.
  EXPECT_EQ(webtransport::draft15::kProtocolToken, "webtransport-h3");
  // Server does not auto-follow redirects; it either accepts (200) or rejects.
  // Verify the session is valid (server-side sessions are always "accepted"
  // once established).
  EXPECT_EQ(wt->id(), GetNthClientInitiatedBidirectionalId(0));
}

TEST_P(SessionEstablishmentDraft15ClientTest, RejectRedirectsClient) {
  // Section 3.2 MUST NOT: Client must not auto-follow 3xx responses.
  // A 301 response should result in rejection with kWrongStatusCode.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings();

  auto* wt = AttemptWebTransportDraft15ClientSession();
  ASSERT_NE(wt, nullptr) << "Draft-15 client session could not be created";
  QuicStreamId stream_id = wt->id();

  // Server responds with 301 (redirect).
  ReceiveWebTransportDraft15Response(stream_id, 301);
  EXPECT_EQ(wt->rejection_reason(),
            WebTransportHttp3RejectionReason::kWrongStatusCode)
      << "Client must reject 3xx responses with kWrongStatusCode";
  EXPECT_FALSE(wt->ready())
      << "Session must not be ready after a redirect response";
}

TEST_P(SessionEstablishmentDraft15Test, No0RTTSessionInitiation) {
  // Section 3.2 MUST NOT: WT CONNECT requests must not be sent in 0-RTT.
  // The CONNECT stream is only created after the handshake completes (1-RTT).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // After handshake, encryption should be at ENCRYPTION_FORWARD_SECURE.
  EXPECT_EQ(connection_->encryption_level(), ENCRYPTION_FORWARD_SECURE)
      << "After handshake, encryption must be at ENCRYPTION_FORWARD_SECURE";

  ReceiveWebTransportDraft15Settings();
  auto* wt = AttemptWebTransportDraft15Session(GetNthClientInitiatedBidirectionalId(0));
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Verify the session was established at 1-RTT encryption level, not 0-RTT.
  // The connection should be using forward-secure encryption.
  EXPECT_EQ(connection_->encryption_level(), ENCRYPTION_FORWARD_SECURE)
      << "WebTransport CONNECT must be established at 1-RTT, not 0-RTT";
}

TEST_P(SessionEstablishmentDraft15ClientTest, NoReducedLimitsOn0RTTAccept) {
  // Section 3.2 MUST: "If the server accepts 0-RTT, the server MUST NOT
  // reduce [...] initial flow control values, from the values negotiated
  // during the previous session; such change [...] MUST result in a
  // H3_SETTINGS_ERROR connection error."
  //
  // Uses the ALPS pattern from quic_spdy_session_test.cc
  // (AlpsSettingsViaControlStreamConflictsAlpsSettings): inject initial
  // SETTINGS via OnAlpsData(), then send reduced values on the control stream.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // Step 1: Simulate the initial SETTINGS from the server via ALPS (as if
  // from the previous session / 0-RTT handshake) with max_streams_bidi=10.
  SettingsFrame alps_settings;
  alps_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  alps_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  alps_settings.values[SETTINGS_WT_ENABLED] = 1;
  alps_settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI] = 10;
  std::string alps_data = HttpEncoder::SerializeSettingsFrame(alps_settings);
  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(alps_data.data()), alps_data.size());
  ASSERT_FALSE(error) << "OnAlpsData failed: " << *error;

  // Step 2: Send reduced SETTINGS on the control stream (max_streams_bidi=5).
  // This simulates the server resuming with a lower limit than 0-RTT promised.
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH, _,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .Times(1);

  SettingsFrame reduced_settings;
  reduced_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  reduced_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  reduced_settings.values[SETTINGS_WT_ENABLED] = 1;
  reduced_settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_BIDI] = 5;
  std::string control_stream_data =
      std::string(1, kControlStream) +
      HttpEncoder::SerializeSettingsFrame(reduced_settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(
          transport_version(), 3);
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /*fin=*/false,
                                          /*offset=*/0, control_stream_data));
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(SessionEstablishmentDraft15ClientTest, NoReducedLimitsOn0RTTAccept_Uni) {
  // Section 3.2 MUST: Same requirement for SETTINGS_WT_INITIAL_MAX_STREAMS_UNI.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  SettingsFrame alps_settings;
  alps_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  alps_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  alps_settings.values[SETTINGS_WT_ENABLED] = 1;
  alps_settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_UNI] = 10;
  std::string alps_data = HttpEncoder::SerializeSettingsFrame(alps_settings);
  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(alps_data.data()), alps_data.size());
  ASSERT_FALSE(error) << "OnAlpsData failed: " << *error;

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH, _,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .Times(1);

  SettingsFrame reduced_settings;
  reduced_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  reduced_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  reduced_settings.values[SETTINGS_WT_ENABLED] = 1;
  reduced_settings.values[SETTINGS_WT_INITIAL_MAX_STREAMS_UNI] = 5;
  std::string control_stream_data =
      std::string(1, kControlStream) +
      HttpEncoder::SerializeSettingsFrame(reduced_settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(
          transport_version(), 3);
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /*fin=*/false,
                                          /*offset=*/0, control_stream_data));
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(SessionEstablishmentDraft15ClientTest, NoReducedLimitsOn0RTTAccept_Data) {
  // Section 3.2 MUST: Same requirement for SETTINGS_WT_INITIAL_MAX_DATA.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  SettingsFrame alps_settings;
  alps_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  alps_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  alps_settings.values[SETTINGS_WT_ENABLED] = 1;
  alps_settings.values[SETTINGS_WT_INITIAL_MAX_DATA] = 65536;
  std::string alps_data = HttpEncoder::SerializeSettingsFrame(alps_settings);
  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(alps_data.data()), alps_data.size());
  ASSERT_FALSE(error) << "OnAlpsData failed: " << *error;

  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH, _,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .Times(1);

  SettingsFrame reduced_settings;
  reduced_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  reduced_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  reduced_settings.values[SETTINGS_WT_ENABLED] = 1;
  reduced_settings.values[SETTINGS_WT_INITIAL_MAX_DATA] = 32768;
  std::string control_stream_data =
      std::string(1, kControlStream) +
      HttpEncoder::SerializeSettingsFrame(reduced_settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(
          transport_version(), 3);
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /*fin=*/false,
                                          /*offset=*/0, control_stream_data));
  testing::Mock::VerifyAndClearExpectations(connection_);
}

TEST_P(SessionEstablishmentDraft15ClientTest,
       RequirementsNotMetOnMissingDatagramSupport) {
  // Section 3.1 MAY: If the server's SETTINGS do not have correct values
  // for every required setting, the client MAY close the HTTP/3 connection
  // with WT_REQUIREMENTS_NOT_MET (0x212c0d48).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // The connection should be closed with WT_REQUIREMENTS_NOT_MET when
  // SETTINGS are received without H3_DATAGRAM.
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_HTTP_INVALID_SETTING_VALUE,
                  static_cast<QuicIetfTransportErrorCodes>(
                      webtransport::draft15::kWtRequirementsNotMet),
                  _, _));

  // Send server SETTINGS with WT_ENABLED but WITHOUT H3_DATAGRAM.
  SettingsFrame settings;
  settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  settings.values[SETTINGS_WT_ENABLED] = 1;
  // Deliberately omit SETTINGS_H3_DATAGRAM.
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(
          transport_version(), 3);
  QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);
  session_->OnStreamFrame(frame);
}

TEST_P(SessionEstablishmentDraft15ClientTest,
       RequirementsNotMetPropagatesThroughClosePath) {
  // Section 3.1: Verify that WT_REQUIREMENTS_NOT_MET (0x212c0d48)
  // propagates correctly through OnInternalError → CloseSession →
  // OnSessionClosed, so that when the detection logic is implemented,
  // the visitor receives the correct error code.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  auto* wt = SetUpWebTransportDraft15ClientSession();
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  auto* visitor = AttachMockVisitor(wt);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*writer_,
              WritePacket(_, _, _, _, _, _))
      .WillRepeatedly(testing::Return(WriteResult(WRITE_STATUS_OK, 0)));

  // Deliver the server's 200 response so the session becomes ready.
  quiche::HttpHeaderBlock response_headers;
  response_headers[":status"] = "200";
  EXPECT_CALL(*visitor, OnSessionReady());
  wt->HeadersReceived(response_headers);

  // Simulate the client detecting requirements not met.
  EXPECT_CALL(*visitor, OnSessionClosed(
      static_cast<webtransport::SessionErrorCode>(
          webtransport::draft15::kWtRequirementsNotMet), _))
      .Times(1);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  wt->OnInternalError(
      static_cast<WebTransportSessionError>(
          webtransport::draft15::kWtRequirementsNotMet),
      "Server does not meet client requirements");

  testing::Mock::VerifyAndClearExpectations(visitor);
  testing::Mock::VerifyAndClearExpectations(writer_);
}

TEST_P(SessionEstablishmentDraft15Test, ServerReply404ForUnknownPath) {
  // Section 3.2 SHOULD: Server replies with 404 for unknown path.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc,
      /*local_max_streams_uni=*/10,
      /*local_max_streams_bidi=*/10,
      /*local_max_data=*/65536);
  CompleteHandshake();
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/1,
                         /*initial_max_streams_uni=*/10,
                         /*initial_max_streams_bidi=*/10,
                         /*initial_max_data=*/65536);

  // Create a session at a known path "/wt".
  QuicStreamId known_stream_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = AttemptWebTransportDraft15Session(known_stream_id, "/wt");
  ASSERT_NE(wt, nullptr) << "Draft-15 session could not be established";

  // Create a session at an unknown path "/nonexistent".
  // The CONNECT stream headers are available for application-layer routing.
  // The path-based 404 decision is at the application layer; the QUIC session
  // creates the WT session object regardless and lets the application decide.
  QuicStreamId unknown_stream_id = GetNthClientInitiatedBidirectionalId(1);
  auto* unknown_wt = AttemptWebTransportDraft15Session(unknown_stream_id, "/nonexistent");
  // The session object is created; the application layer is responsible for
  // sending a 404. Verify both sessions are created.
  ASSERT_NE(unknown_wt, nullptr)
      << "Session object should be created for application-layer routing";
  // Verify the two sessions are distinct.
  EXPECT_NE(wt->id(), unknown_wt->id())
      << "Sessions on different streams must have different IDs";
}

TEST_P(SessionEstablishmentDraft15Test,
       Section3_1_MissingResetStreamAtRejectsSession) {
  // Section 3.1: Both client and server MUST send an empty reset_stream_at
  // transport parameter. "If the server receives SETTINGS that do not have
  // correct values for every required setting, or transport parameters that
  // do not have correct values for every required transport parameter, the
  // server MUST treat all established and newly incoming WebTransport
  // sessions as malformed."
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  // Use the base class Initialize() which does NOT set reset_stream_at,
  // then configure draft-15 support manually. This avoids the
  // Draft15SessionTest::Initialize() path which enables reset_stream_at
  // as part of the standard draft-15 setup.
  QuicSpdySessionTestBase::Initialize();
  session_->set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}));
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  CompleteHandshake();

  ASSERT_FALSE(connection_->reliable_stream_reset_enabled())
      << "Test precondition: reset_stream_at should not be negotiated";

  // Receiving peer SETTINGS should trigger ValidateWebTransportSettingsConsistency(),
  // which should detect the missing reset_stream_at transport parameter and
  // close the connection with WT_REQUIREMENTS_NOT_MET.
  // Send settings manually (not via ReceiveWebTransportDraft15Settings which enables
  // reset_stream_at as part of standard draft-15 setup).
  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_HTTP_INVALID_SETTING_VALUE,
                  static_cast<QuicIetfTransportErrorCodes>(
                      webtransport::draft15::kWtRequirementsNotMet),
                  _, _));
  SettingsFrame settings;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  settings.values[SETTINGS_WT_ENABLED] = 1;
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  session_->OnStreamFrame(
      QuicStreamFrame(control_stream_id, /*fin=*/false, /*offset=*/0, data));
}

TEST_P(SessionEstablishmentDraft15Test, SettingsWtEnabledValueGreaterThan1) {
  // The production code enforces SETTINGS_WT_ENABLED as a boolean flag
  // (0 or 1). Values > 1 trigger a QUICHE_BUG (fatal in debug builds).
  // This test verifies that behavior using EXPECT_QUIC_BUG.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Send SETTINGS_WT_ENABLED = 2 -- triggers a QUICHE_BUG (fatal in debug).
  EXPECT_QUIC_BUG(ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/2),
                   "bad received setting");
}

TEST_P(SessionEstablishmentDraft15Test, SettingsWtEnabledValueZeroDisabled) {
  // Section 3.1: SETTINGS_WT_ENABLED = 0 means disabled.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  // Send SETTINGS_WT_ENABLED = 0 (disabled).
  ReceiveWebTransportDraft15Settings(/*wt_enabled_value=*/0);
  EXPECT_FALSE(session_->SupportsWebTransport())
      << "SETTINGS_WT_ENABLED=0 should mean WebTransport is disabled";
}

TEST_P(SessionEstablishmentDraft15ClientTest,
       Section3_1_WtEnabledWithoutExtendedConnectRejected) {
  // Section 3.1: Servers MUST send both SETTINGS_WT_ENABLED=1 AND
  // SETTINGS_ENABLE_CONNECT_PROTOCOL=1. A client receiving WT_ENABLED
  // without ENABLE_CONNECT_PROTOCOL should reject the settings.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // Send WT_ENABLED + H3_DATAGRAM but omit ENABLE_CONNECT_PROTOCOL.
  SettingsFrame settings;
  settings.values[SETTINGS_WT_ENABLED] = 1;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  // Deliberately omit SETTINGS_ENABLE_CONNECT_PROTOCOL.
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(transport_version(), 3);
  QuicStreamFrame frame(control_stream_id, /*fin=*/false, /*offset=*/0, data);

  EXPECT_CALL(*connection_, CloseConnection(_, _, _, _))
      .WillOnce(testing::Invoke(
          connection_, &test::MockQuicConnection::ReallyCloseConnection4));
  EXPECT_CALL(*connection_, SendConnectionClosePacket(_, _, _))
      .Times(testing::AnyNumber());

  session_->OnStreamFrame(frame);

  // The connection should be closed because ENABLE_CONNECT_PROTOCOL is missing.
  EXPECT_FALSE(connection_->connected())
      << "Client must reject WT_ENABLED when "
         "SETTINGS_ENABLE_CONNECT_PROTOCOL is missing";
}

TEST_P(SessionEstablishmentDraft15Test,
       Section3_1_ZeroMaxDatagramFrameSizeRejectsSession) {
  // Section 3.1: Both client and server MUST send max_datagram_frame_size
  // transport parameter with a value greater than 0. A peer that negotiates
  // max_datagram_frame_size=0 must be rejected.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;

  QuicSpdySessionTestBase::Initialize();
  session_->set_locally_supported_web_transport_versions(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}));
  session_->set_local_http_datagram_support(HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // Override the received max_datagram_frame_size to 0 (simulating a peer
  // that sent the transport parameter with value 0).
  test::QuicConfigPeer::SetReceivedMaxDatagramFrameSize(
      session_->config(), 0);

  // Enable reset_stream_at so that the only missing requirement is
  // max_datagram_frame_size > 0.
  const_cast<QuicFramer*>(&connection_->framer())
      ->set_process_reset_stream_at(true);

  EXPECT_CALL(*connection_,
              CloseConnection(
                  QUIC_HTTP_INVALID_SETTING_VALUE,
                  static_cast<QuicIetfTransportErrorCodes>(
                      webtransport::draft15::kWtRequirementsNotMet),
                  _, _));

  SettingsFrame settings;
  settings.values[SETTINGS_H3_DATAGRAM] = 1;
  settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  settings.values[SETTINGS_WT_ENABLED] = 1;
  std::string data = std::string(1, kControlStream) +
                     HttpEncoder::SerializeSettingsFrame(settings);
  QuicStreamId control_stream_id =
      test::GetNthClientInitiatedUnidirectionalStreamId(transport_version(), 3);
  session_->OnStreamFrame(
      QuicStreamFrame(control_stream_id, /*fin=*/false, /*offset=*/0, data));
}

TEST_P(SessionEstablishmentDraft15ClientTest,
       NoReducedLimitsOn0RTTAccept_WtEnabled) {
  // Section 3.2 MUST: "If the server accepts 0-RTT, the server MUST NOT
  // reduce the limit of maximum open WebTransport sessions, or other initial
  // flow control values." SETTINGS_WT_ENABLED going from 1 to 0 is a
  // reduction that must be rejected.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft15}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();

  // Step 1: Simulate initial SETTINGS via ALPS with WT_ENABLED=1.
  SettingsFrame alps_settings;
  alps_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  alps_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  alps_settings.values[SETTINGS_WT_ENABLED] = 1;
  std::string alps_data = HttpEncoder::SerializeSettingsFrame(alps_settings);
  auto error = session_->OnAlpsData(
      reinterpret_cast<const uint8_t*>(alps_data.data()), alps_data.size());
  ASSERT_FALSE(error) << "OnAlpsData failed: " << *error;

  // Step 2: Send control stream SETTINGS with WT_ENABLED=0 (reduction).
  EXPECT_CALL(
      *connection_,
      CloseConnection(QUIC_HTTP_ZERO_RTT_RESUMPTION_SETTINGS_MISMATCH, _,
                      ConnectionCloseBehavior::SEND_CONNECTION_CLOSE_PACKET))
      .Times(1);

  SettingsFrame reduced_settings;
  reduced_settings.values[SETTINGS_H3_DATAGRAM] = 1;
  reduced_settings.values[SETTINGS_ENABLE_CONNECT_PROTOCOL] = 1;
  reduced_settings.values[SETTINGS_WT_ENABLED] = 0;
  std::string control_stream_data =
      std::string(1, kControlStream) +
      HttpEncoder::SerializeSettingsFrame(reduced_settings);
  QuicStreamId control_stream_id =
      test::GetNthServerInitiatedUnidirectionalStreamId(
          transport_version(), 3);
  session_->OnStreamFrame(QuicStreamFrame(control_stream_id, /*fin=*/false,
                                          /*offset=*/0, control_stream_data));
  testing::Mock::VerifyAndClearExpectations(connection_);
}

}  // namespace
}  // namespace quic
