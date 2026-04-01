// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Draft-15 acceptance tests for keying material exporters (Section 4.8).

#include <cstddef>
#include <cstdint>
#include <string>

#include "absl/status/statusor.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/web_transport_draft15_test_utils.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/quic_data_writer.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_test_utils.h"

namespace quic {
namespace {

using ::testing::_;

// Helper: builds the expected "WebTransport Exporter Context" struct
// (Section 4.8) for a given session ID, app label, and app context.
std::string BuildExpectedExporterContext(uint64_t session_id,
                                        absl::string_view label,
                                        absl::string_view context) {
  std::string buf;
  buf.resize(8 + 1 + label.size() + 1 + context.size());
  QuicDataWriter writer(buf.size(), buf.data());
  writer.WriteUInt64(session_id);
  writer.WriteUInt8(static_cast<uint8_t>(label.size()));
  if (!label.empty()) {
    writer.WriteStringPiece(label);
  }
  writer.WriteUInt8(static_cast<uint8_t>(context.size()));
  if (!context.empty()) {
    writer.WriteStringPiece(context);
  }
  return buf;
}

// ===================================================================
// Context struct serialization tests (no session needed)
// ===================================================================

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_EmptyLabelEmptyContext) {
  // Section 4.8: session_id=0, label="", context="" ->
  // 8 bytes (session ID) + 1 byte (label len=0) + 1 byte (ctx len=0) = 10 bytes
  std::string ctx = BuildExpectedExporterContext(0, "", "");
  EXPECT_EQ(ctx.size(), 10u);
  // All zero session ID + two zero length bytes.
  EXPECT_EQ(ctx, std::string(8, '\0') + std::string(1, '\0') + std::string(1, '\0'));
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_NonEmptyLabel) {
  // label="my-label", context="" -> session_id(8) + len(1) + "my-label"(8) + len(1) = 18
  std::string ctx = BuildExpectedExporterContext(0, "my-label", "");
  EXPECT_EQ(ctx.size(), 18u);
  EXPECT_EQ(ctx[8], 8);  // label length
  EXPECT_EQ(ctx.substr(9, 8), "my-label");
  EXPECT_EQ(ctx[17], 0);  // context length
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_NonEmptyContext) {
  // label="", context="ctx" -> session_id(8) + len(1) + len(1) + "ctx"(3) = 13
  std::string ctx = BuildExpectedExporterContext(0, "", "ctx");
  EXPECT_EQ(ctx.size(), 13u);
  EXPECT_EQ(ctx[8], 0);   // label length
  EXPECT_EQ(ctx[9], 3);   // context length
  EXPECT_EQ(ctx.substr(10, 3), "ctx");
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_BothNonEmpty) {
  // label="lbl", context="ctx" ->
  // session_id(8) + len(1) + "lbl"(3) + len(1) + "ctx"(3) = 16
  std::string ctx = BuildExpectedExporterContext(0, "lbl", "ctx");
  EXPECT_EQ(ctx.size(), 16u);
  EXPECT_EQ(ctx[8], 3);  // label length
  EXPECT_EQ(ctx.substr(9, 3), "lbl");
  EXPECT_EQ(ctx[12], 3);  // context length
  EXPECT_EQ(ctx.substr(13, 3), "ctx");
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_SessionIdEndianness) {
  // Section 4.8: Session ID is 64-bit. Verify big-endian encoding.
  // session_id=0x0102030405060708 -> bytes 01 02 03 04 05 06 07 08
  std::string ctx = BuildExpectedExporterContext(0x0102030405060708ULL, "", "");
  EXPECT_EQ(ctx.size(), 10u);
  EXPECT_EQ(static_cast<uint8_t>(ctx[0]), 0x01);
  EXPECT_EQ(static_cast<uint8_t>(ctx[1]), 0x02);
  EXPECT_EQ(static_cast<uint8_t>(ctx[2]), 0x03);
  EXPECT_EQ(static_cast<uint8_t>(ctx[3]), 0x04);
  EXPECT_EQ(static_cast<uint8_t>(ctx[4]), 0x05);
  EXPECT_EQ(static_cast<uint8_t>(ctx[5]), 0x06);
  EXPECT_EQ(static_cast<uint8_t>(ctx[6]), 0x07);
  EXPECT_EQ(static_cast<uint8_t>(ctx[7]), 0x08);
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_MaxLabelLength) {
  // Label length field is 8 bits -> max 255 bytes. 255-byte label must work.
  std::string label(255, 'L');
  std::string ctx = BuildExpectedExporterContext(0, label, "");
  EXPECT_EQ(ctx.size(), 8u + 1u + 255u + 1u);
  EXPECT_EQ(static_cast<uint8_t>(ctx[8]), 0xFF);
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_MaxContextLength) {
  // Context length field is 8 bits -> max 255 bytes. 255-byte context must work.
  std::string context(255, 'C');
  std::string ctx = BuildExpectedExporterContext(0, "", context);
  EXPECT_EQ(ctx.size(), 8u + 1u + 1u + 255u);
  EXPECT_EQ(static_cast<uint8_t>(ctx[9]), 0xFF);
}

TEST(WebTransportKeyingMaterialDraft15, ContextSerialization_OmittedContextIsZeroLength) {
  // Section 4.8: "the WebTransport Application-Supplied Exporter Context
  // becomes zero-length if omitted" -- empty context produces len=0, not absent.
  std::string ctx = BuildExpectedExporterContext(42, "label", "");
  // The context length byte must be present and zero.
  size_t context_len_offset = 8 + 1 + 5;  // session_id + label_len + "label"
  EXPECT_EQ(static_cast<uint8_t>(ctx[context_len_offset]), 0x00);
  // Total size includes the zero-length context field.
  EXPECT_EQ(ctx.size(), 8u + 1u + 5u + 1u);
}

// ===================================================================
// Session-level tests
// ===================================================================

class KeyingMaterialDraft15Test : public test::Draft15SessionTest {
 protected:
  KeyingMaterialDraft15Test() : Draft15SessionTest(Perspective::IS_SERVER) {}
};

INSTANTIATE_TEST_SUITE_P(KeyingMaterialDraft15, KeyingMaterialDraft15Test,
                         ::testing::ValuesIn(CurrentSupportedVersions()));

// --- Basic API contract ---

TEST_P(KeyingMaterialDraft15Test, BasicExport) {
  // Section 4.8 SHALL: GetKeyingMaterial returns keying material of
  // the requested length. Verify result.size() == requested length.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "context", 32);
  ASSERT_TRUE(result.ok()) << result.status();
  EXPECT_EQ(result->size(), 32u);
}

TEST_P(KeyingMaterialDraft15Test, ExportWithLabel) {
  // App-supplied label is included in the context struct.
  // Different labels must produce different keying material.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result_a = wt->GetKeyingMaterial("label-a", "", 32);
  auto result_b = wt->GetKeyingMaterial("label-b", "", 32);
  ASSERT_TRUE(result_a.ok()) << result_a.status();
  ASSERT_TRUE(result_b.ok()) << result_b.status();
  EXPECT_NE(*result_a, *result_b)
      << "Different app labels must produce different keying material";
}

TEST_P(KeyingMaterialDraft15Test, ExportWithContext) {
  // App-supplied context is included in the context struct.
  // Different contexts must produce different keying material.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result_a = wt->GetKeyingMaterial("", "context-a", 32);
  auto result_b = wt->GetKeyingMaterial("", "context-b", 32);
  ASSERT_TRUE(result_a.ok()) << result_a.status();
  ASSERT_TRUE(result_b.ok()) << result_b.status();
  EXPECT_NE(*result_a, *result_b)
      << "Different app contexts must produce different keying material";
}

TEST_P(KeyingMaterialDraft15Test, ExportWithLabelAndContext) {
  // Both label and context non-empty -> both included in struct.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("my-label", "my-context", 32);
  ASSERT_TRUE(result.ok()) << result.status();
  EXPECT_EQ(result->size(), 32u);
}

TEST_P(KeyingMaterialDraft15Test, OmittedContextProducesZeroLengthField) {
  // Section 4.8: empty context string -> zero-length field in struct,
  // not "no context". Must still produce valid output.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "", 32);
  ASSERT_TRUE(result.ok()) << result.status();
  EXPECT_EQ(result->size(), 32u);
}

// --- Length edge cases ---

TEST_P(KeyingMaterialDraft15Test, LengthZero) {
  // Requesting 0 bytes of keying material. Should succeed with empty string.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "context", 0);
  ASSERT_TRUE(result.ok()) << result.status();
  EXPECT_EQ(result->size(), 0u);
}

TEST_P(KeyingMaterialDraft15Test, LengthOne) {
  // Requesting 1 byte. Minimal non-trivial case.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "context", 1);
  ASSERT_TRUE(result.ok()) << result.status();
  EXPECT_EQ(result->size(), 1u);
}

TEST_P(KeyingMaterialDraft15Test, LengthLarge) {
  // Requesting a large amount (1024 bytes). Must succeed.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "context", 1024);
  ASSERT_TRUE(result.ok()) << result.status();
  EXPECT_EQ(result->size(), 1024u);
}

TEST_P(KeyingMaterialDraft15Test, LengthMaxReasonable) {
  // Requesting 64KB. Implementation should handle or return a
  // clear error, not crash or OOM.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "context", 65536);
  // Either succeeds with the right size or returns a clear error.
  if (result.ok()) {
    EXPECT_EQ(result->size(), 65536u);
  }
  // If !ok(), that's acceptable — just must not crash.
}

// --- Session isolation ---

TEST_P(KeyingMaterialDraft15Test, DifferentSessionsDifferentMaterial) {
  // Section 4.8: "separates keying material for different sessions"
  // Two sessions on the same connection with the same label/context
  // must produce different keying material (session ID differs).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  // Need FC to allow multiple sessions.
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

  QuicStreamId session_id_0 = GetNthClientInitiatedBidirectionalId(0);
  QuicStreamId session_id_1 = GetNthClientInitiatedBidirectionalId(1);
  auto* wt0 = AttemptWebTransportDraft15Session(session_id_0);
  auto* wt1 = AttemptWebTransportDraft15Session(session_id_1);
  ASSERT_NE(wt0, nullptr);
  ASSERT_NE(wt1, nullptr);

  auto result0 = wt0->GetKeyingMaterial("label", "context", 32);
  auto result1 = wt1->GetKeyingMaterial("label", "context", 32);
  ASSERT_TRUE(result0.ok()) << result0.status();
  ASSERT_TRUE(result1.ok()) << result1.status();
  EXPECT_NE(*result0, *result1)
      << "Different sessions must produce different keying material "
         "(session IDs " << session_id_0 << " vs " << session_id_1 << ")";
}

TEST_P(KeyingMaterialDraft15Test, SameSessionSameMaterial) {
  // Same session, same label, same context, same length -> must be
  // deterministic (same result every time).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result1 = wt->GetKeyingMaterial("label", "context", 32);
  auto result2 = wt->GetKeyingMaterial("label", "context", 32);
  ASSERT_TRUE(result1.ok()) << result1.status();
  ASSERT_TRUE(result2.ok()) << result2.status();
  EXPECT_EQ(*result1, *result2);
}

// --- TLS exporter arguments (wire-level correctness) ---
// These tests capture the actual arguments passed to
// QuicCryptoStream::ExportKeyingMaterial and verify them byte-for-byte.
// This is the core of the SHALL -- if the context struct is wrong
// (wrong endianness, swapped fields, missing length bytes), the output
// will be incompatible with other implementations.

TEST_P(KeyingMaterialDraft15Test, UsesFixedTlsLabel) {
  // Section 4.8 SHALL: The TLS exporter label is always
  // "EXPORTER-WebTransport", regardless of the app-supplied label.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("my-app-label", "my-context", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  EXPECT_EQ(crypto->last_export_label(), "EXPORTER-WebTransport")
      << "To implement Section 4.8, the TLS label must be "
         "'EXPORTER-WebTransport', not the app-supplied label";
}

TEST_P(KeyingMaterialDraft15Test, ContextStructEncoding_EmptyLabelEmptyContext) {
  // Capture the context arg passed to ExportKeyingMaterial.
  // session_id=N, label="", context="" ->
  // Expected bytes: [N as 8 big-endian bytes] [0x00] [0x00]
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("", "", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  std::string expected = BuildExpectedExporterContext(session_id, "", "");
  auto* crypto = session_->GetMutableCryptoStream();
  EXPECT_EQ(crypto->last_export_context(), expected)
      << "Context struct encoding mismatch for empty label and context";
}

TEST_P(KeyingMaterialDraft15Test, ContextStructEncoding_WithLabelAndContext) {
  // session_id=N, label="abc", context="xy" ->
  // Expected: [N BE 8 bytes] [0x03] [0x61 0x62 0x63] [0x02] [0x78 0x79]
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("abc", "xy", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  std::string expected = BuildExpectedExporterContext(session_id, "abc", "xy");
  auto* crypto = session_->GetMutableCryptoStream();
  EXPECT_EQ(crypto->last_export_context(), expected)
      << "Context struct encoding mismatch for label='abc', context='xy'";
}

TEST_P(KeyingMaterialDraft15Test, ContextStructEncoding_SessionIdIsBigEndian) {
  // Use a session ID with distinct bytes. Capture the context arg.
  // First 8 bytes must be big-endian, NOT host byte order.
  // This catches endianness bugs that would silently pass
  // "different sessions -> different output" tests on any single machine.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("", "", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  const std::string& ctx = crypto->last_export_context();
  ASSERT_GE(ctx.size(), 8u);
  // Verify the session ID is encoded big-endian by comparing against
  // the expected struct built with QuicDataWriter (which writes BE).
  std::string expected = BuildExpectedExporterContext(session_id, "", "");
  EXPECT_EQ(ctx.substr(0, 8), expected.substr(0, 8))
      << "Session ID must be encoded big-endian in the exporter context";
}

TEST_P(KeyingMaterialDraft15Test, ContextStructEncoding_MaxLabelMaxContext) {
  // 255-byte label + 255-byte context. Verify the length bytes are 0xFF
  // and the full struct is 8 + 1 + 255 + 1 + 255 = 520 bytes.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string label(255, 'L');
  std::string context(255, 'C');
  auto result = wt->GetKeyingMaterial(label, context, 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  const std::string& ctx = crypto->last_export_context();
  EXPECT_EQ(ctx.size(), 520u);
  EXPECT_EQ(static_cast<uint8_t>(ctx[8]), 0xFF)
      << "Label length byte should be 0xFF for 255-byte label";
  EXPECT_EQ(static_cast<uint8_t>(ctx[8 + 1 + 255]), 0xFF)
      << "Context length byte should be 0xFF for 255-byte context";
}

// --- Error conditions ---

// FailsBeforeHandshakeComplete: not testable here because TestCryptoStream's
// ExportKeyingMaterial always returns true regardless of handshake state.
// With a real TLS stack (covered by e2e tests), ExportKeyingMaterial returns
// false before handshake completion, causing GetKeyingMaterial to return
// InternalError.

TEST_P(KeyingMaterialDraft15Test, FailsAfterSessionClosed) {
  // After CloseSession(), GetKeyingMaterial should return an error.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  session_->set_writev_consumes_all_data(true);
  EXPECT_CALL(*connection_, SendControlFrame(_))
      .WillRepeatedly(&test::ClearControlFrame);
  EXPECT_CALL(*connection_, OnStreamReset(_, _))
      .Times(testing::AnyNumber());

  wt->CloseSession(0, "done");

  auto result = wt->GetKeyingMaterial("label", "context", 32);
  EXPECT_FALSE(result.ok())
      << "GetKeyingMaterial should fail after session is closed";
}

// FailsWhenCryptoStreamReturnsFailure: not testable with TestCryptoStream
// (always returns true). The implementation propagates failures: if
// ExportKeyingMaterial returns false, GetKeyingMaterial returns
// absl::InternalError("TLS exporter failed").

// --- Label/context boundary values ---

TEST_P(KeyingMaterialDraft15Test, EmptyLabel) {
  // App label="" -> label length byte = 0, no label bytes in context struct.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("", "context", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  std::string expected = BuildExpectedExporterContext(session_id, "", "context");
  EXPECT_EQ(crypto->last_export_context(), expected);
}

TEST_P(KeyingMaterialDraft15Test, MaxLengthLabel) {
  // 255-byte app label -> label length byte = 0xFF, 255 label bytes.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string label(255, 'X');
  auto result = wt->GetKeyingMaterial(label, "", 32);
  ASSERT_TRUE(result.ok()) << result.status();
}

TEST_P(KeyingMaterialDraft15Test, LabelExceeds255Bytes) {
  // 256-byte app label -> must return error (8-bit length field overflow).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string label(256, 'X');
  auto result = wt->GetKeyingMaterial(label, "", 32);
  EXPECT_FALSE(result.ok())
      << "256-byte label exceeds 8-bit length field and must be rejected";
}

TEST_P(KeyingMaterialDraft15Test, EmptyContext) {
  // App context="" -> context length byte = 0.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  std::string expected = BuildExpectedExporterContext(session_id, "label", "");
  EXPECT_EQ(crypto->last_export_context(), expected);
}

TEST_P(KeyingMaterialDraft15Test, MaxLengthContext) {
  // 255-byte app context -> context length byte = 0xFF.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string context(255, 'Y');
  auto result = wt->GetKeyingMaterial("", context, 32);
  ASSERT_TRUE(result.ok()) << result.status();
}

TEST_P(KeyingMaterialDraft15Test, ContextExceeds255Bytes) {
  // 256-byte app context -> must return error (8-bit length field overflow).
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string context(256, 'Y');
  auto result = wt->GetKeyingMaterial("", context, 32);
  EXPECT_FALSE(result.ok())
      << "256-byte context exceeds 8-bit length field and must be rejected";
}

TEST_P(KeyingMaterialDraft15Test, LabelWithNullBytes) {
  // App label containing \0 bytes. The TLS exporter label
  // "EXPORTER-WebTransport" is fixed and has no nulls, but the app
  // label goes into the context struct, not the TLS label. Must work.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string label("ab\0cd", 5);
  auto result = wt->GetKeyingMaterial(label, "", 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  std::string expected = BuildExpectedExporterContext(session_id, label, "");
  EXPECT_EQ(crypto->last_export_context(), expected);
}

TEST_P(KeyingMaterialDraft15Test, ContextWithNullBytes) {
  // App context containing \0 bytes. Binary data in context is valid.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  auto* wt = SetUpWebTransportDraft15ServerSession(session_id);
  ASSERT_NE(wt, nullptr);

  std::string context("xy\0z", 4);
  auto result = wt->GetKeyingMaterial("", context, 32);
  ASSERT_TRUE(result.ok()) << result.status();

  auto* crypto = session_->GetMutableCryptoStream();
  std::string expected = BuildExpectedExporterContext(session_id, "", context);
  EXPECT_EQ(crypto->last_export_context(), expected);
}

// --- Draft-07 behavior ---

TEST_P(KeyingMaterialDraft15Test, NotAvailableOnDraft07) {
  // Section 4.8 is a draft-15 feature. On a draft-07 session,
  // GetKeyingMaterial should return an error or not-implemented.
  if (!VersionIsIetfQuic(GetParam().transport_version)) return;
  Initialize(
      WebTransportHttp3VersionSet({WebTransportHttp3Version::kDraft07}),
      HttpDatagramSupport::kRfc);
  CompleteHandshake();
  ReceiveWebTransportDraft07Settings();

  QuicStreamId session_id = GetNthClientInitiatedBidirectionalId(0);
  // Create a draft-07 session.
  QuicStreamFrame frame(session_id, /*fin=*/false, /*offset=*/0,
                        absl::string_view());
  session_->OnStreamFrame(frame);
  auto* connect_stream = static_cast<QuicSpdyStream*>(
      session_->GetOrCreateStream(session_id));
  ASSERT_NE(connect_stream, nullptr);
  QuicHeaderList headers;
  headers.OnHeader(":method", "CONNECT");
  headers.OnHeader(":protocol", "webtransport");
  connect_stream->OnStreamHeaderList(/*fin=*/false, 0, headers);
  auto* wt = session_->GetWebTransportSession(session_id);
  ASSERT_NE(wt, nullptr);

  auto result = wt->GetKeyingMaterial("label", "context", 32);
  EXPECT_FALSE(result.ok())
      << "Keying material export should not be available on "
         "draft-07 sessions (only supported in draft-15)";
}

}  // namespace
}  // namespace quic
