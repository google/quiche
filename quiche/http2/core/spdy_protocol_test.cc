// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/http2/core/spdy_protocol.h"

#include <iostream>
#include <string>
#include <type_traits>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/http2/core/spdy_frame_builder.h"
#include "quiche/http2/core/spdy_framer.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace spdy {

std::ostream& operator<<(std::ostream& os,
                         const SpdyStreamPrecedence precedence) {
  if (precedence.is_spdy3_priority()) {
    os << "SpdyStreamPrecedence[spdy3_priority=" << precedence.spdy3_priority()
       << "]";
  } else {
    os << "SpdyStreamPrecedence[parent_id=" << precedence.parent_id()
       << ", weight=" << precedence.weight()
       << ", is_exclusive=" << precedence.is_exclusive() << "]";
  }
  return os;
}

namespace test {

TEST(SpdyProtocolTest, ClampSpdy3Priority) {
  EXPECT_QUICHE_BUG(EXPECT_EQ(7, ClampSpdy3Priority(8)), "Invalid priority: 8");
  EXPECT_EQ(kV3LowestPriority, ClampSpdy3Priority(kV3LowestPriority));
  EXPECT_EQ(kV3HighestPriority, ClampSpdy3Priority(kV3HighestPriority));
}

TEST(SpdyProtocolTest, ClampHttp2Weight) {
  EXPECT_QUICHE_BUG(EXPECT_EQ(kHttp2MinStreamWeight, ClampHttp2Weight(0)),
                    "Invalid weight: 0");
  EXPECT_QUICHE_BUG(EXPECT_EQ(kHttp2MaxStreamWeight, ClampHttp2Weight(300)),
                    "Invalid weight: 300");
  EXPECT_EQ(kHttp2MinStreamWeight, ClampHttp2Weight(kHttp2MinStreamWeight));
  EXPECT_EQ(kHttp2MaxStreamWeight, ClampHttp2Weight(kHttp2MaxStreamWeight));
}

TEST(SpdyProtocolTest, Spdy3PriorityToHttp2Weight) {
  EXPECT_EQ(256, Spdy3PriorityToHttp2Weight(0));
  EXPECT_EQ(220, Spdy3PriorityToHttp2Weight(1));
  EXPECT_EQ(183, Spdy3PriorityToHttp2Weight(2));
  EXPECT_EQ(147, Spdy3PriorityToHttp2Weight(3));
  EXPECT_EQ(110, Spdy3PriorityToHttp2Weight(4));
  EXPECT_EQ(74, Spdy3PriorityToHttp2Weight(5));
  EXPECT_EQ(37, Spdy3PriorityToHttp2Weight(6));
  EXPECT_EQ(1, Spdy3PriorityToHttp2Weight(7));
}

TEST(SpdyProtocolTest, Http2WeightToSpdy3Priority) {
  EXPECT_EQ(0u, Http2WeightToSpdy3Priority(256));
  EXPECT_EQ(0u, Http2WeightToSpdy3Priority(221));
  EXPECT_EQ(1u, Http2WeightToSpdy3Priority(220));
  EXPECT_EQ(1u, Http2WeightToSpdy3Priority(184));
  EXPECT_EQ(2u, Http2WeightToSpdy3Priority(183));
  EXPECT_EQ(2u, Http2WeightToSpdy3Priority(148));
  EXPECT_EQ(3u, Http2WeightToSpdy3Priority(147));
  EXPECT_EQ(3u, Http2WeightToSpdy3Priority(111));
  EXPECT_EQ(4u, Http2WeightToSpdy3Priority(110));
  EXPECT_EQ(4u, Http2WeightToSpdy3Priority(75));
  EXPECT_EQ(5u, Http2WeightToSpdy3Priority(74));
  EXPECT_EQ(5u, Http2WeightToSpdy3Priority(38));
  EXPECT_EQ(6u, Http2WeightToSpdy3Priority(37));
  EXPECT_EQ(6u, Http2WeightToSpdy3Priority(2));
  EXPECT_EQ(7u, Http2WeightToSpdy3Priority(1));
}

TEST(SpdyProtocolTest, IsValidHTTP2FrameStreamId) {
  // Stream-specific frames must have non-zero stream ids
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::DATA));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::DATA));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::HEADERS));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::HEADERS));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::PRIORITY));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::PRIORITY));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::RST_STREAM));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::RST_STREAM));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::CONTINUATION));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::CONTINUATION));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::PUSH_PROMISE));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::PUSH_PROMISE));

  // Connection-level frames must have zero stream ids
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::GOAWAY));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::GOAWAY));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::SETTINGS));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::SETTINGS));
  EXPECT_FALSE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::PING));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::PING));

  // Frames that are neither stream-specific nor connection-level
  // should not have their stream id declared invalid
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(1, SpdyFrameType::WINDOW_UPDATE));
  EXPECT_TRUE(IsValidHTTP2FrameStreamId(0, SpdyFrameType::WINDOW_UPDATE));
}

TEST(SpdyProtocolTest, ParseSettingsId) {
  SpdyKnownSettingsId setting_id;
  EXPECT_FALSE(ParseSettingsId(0, &setting_id));
  EXPECT_TRUE(ParseSettingsId(1, &setting_id));
  EXPECT_EQ(SETTINGS_HEADER_TABLE_SIZE, setting_id);
  EXPECT_TRUE(ParseSettingsId(2, &setting_id));
  EXPECT_EQ(SETTINGS_ENABLE_PUSH, setting_id);
  EXPECT_TRUE(ParseSettingsId(3, &setting_id));
  EXPECT_EQ(SETTINGS_MAX_CONCURRENT_STREAMS, setting_id);
  EXPECT_TRUE(ParseSettingsId(4, &setting_id));
  EXPECT_EQ(SETTINGS_INITIAL_WINDOW_SIZE, setting_id);
  EXPECT_TRUE(ParseSettingsId(5, &setting_id));
  EXPECT_EQ(SETTINGS_MAX_FRAME_SIZE, setting_id);
  EXPECT_TRUE(ParseSettingsId(6, &setting_id));
  EXPECT_EQ(SETTINGS_MAX_HEADER_LIST_SIZE, setting_id);
  EXPECT_FALSE(ParseSettingsId(7, &setting_id));
  EXPECT_TRUE(ParseSettingsId(8, &setting_id));
  EXPECT_EQ(SETTINGS_ENABLE_CONNECT_PROTOCOL, setting_id);
  EXPECT_TRUE(ParseSettingsId(9, &setting_id));
  EXPECT_EQ(SETTINGS_DEPRECATE_HTTP2_PRIORITIES, setting_id);
  EXPECT_FALSE(ParseSettingsId(10, &setting_id));
  EXPECT_FALSE(ParseSettingsId(0xFF44, &setting_id));
  EXPECT_TRUE(ParseSettingsId(0xFF45, &setting_id));
  EXPECT_EQ(SETTINGS_EXPERIMENT_SCHEDULER, setting_id);
  EXPECT_FALSE(ParseSettingsId(0xFF46, &setting_id));
}

TEST(SpdyProtocolTest, SettingsIdToString) {
  struct {
    SpdySettingsId setting_id;
    const std::string expected_string;
  } test_cases[] = {
      {0, "SETTINGS_UNKNOWN_0"},
      {SETTINGS_HEADER_TABLE_SIZE, "SETTINGS_HEADER_TABLE_SIZE"},
      {SETTINGS_ENABLE_PUSH, "SETTINGS_ENABLE_PUSH"},
      {SETTINGS_MAX_CONCURRENT_STREAMS, "SETTINGS_MAX_CONCURRENT_STREAMS"},
      {SETTINGS_INITIAL_WINDOW_SIZE, "SETTINGS_INITIAL_WINDOW_SIZE"},
      {SETTINGS_MAX_FRAME_SIZE, "SETTINGS_MAX_FRAME_SIZE"},
      {SETTINGS_MAX_HEADER_LIST_SIZE, "SETTINGS_MAX_HEADER_LIST_SIZE"},
      {7, "SETTINGS_UNKNOWN_7"},
      {SETTINGS_ENABLE_CONNECT_PROTOCOL, "SETTINGS_ENABLE_CONNECT_PROTOCOL"},
      {SETTINGS_DEPRECATE_HTTP2_PRIORITIES,
       "SETTINGS_DEPRECATE_HTTP2_PRIORITIES"},
      {0xa, "SETTINGS_UNKNOWN_a"},
      {0xFF44, "SETTINGS_UNKNOWN_ff44"},
      {0xFF45, "SETTINGS_EXPERIMENT_SCHEDULER"},
      {0xFF46, "SETTINGS_UNKNOWN_ff46"}};
  for (auto test_case : test_cases) {
    EXPECT_EQ(test_case.expected_string,
              SettingsIdToString(test_case.setting_id));
  }
}

TEST(SpdyStreamPrecedenceTest, Basic) {
  SpdyStreamPrecedence spdy3_prec(2);
  EXPECT_TRUE(spdy3_prec.is_spdy3_priority());
  EXPECT_EQ(2, spdy3_prec.spdy3_priority());
  EXPECT_EQ(kHttp2RootStreamId, spdy3_prec.parent_id());
  EXPECT_EQ(Spdy3PriorityToHttp2Weight(2), spdy3_prec.weight());
  EXPECT_FALSE(spdy3_prec.is_exclusive());

  for (bool is_exclusive : {true, false}) {
    SpdyStreamPrecedence h2_prec(7, 123, is_exclusive);
    EXPECT_FALSE(h2_prec.is_spdy3_priority());
    EXPECT_EQ(Http2WeightToSpdy3Priority(123), h2_prec.spdy3_priority());
    EXPECT_EQ(7u, h2_prec.parent_id());
    EXPECT_EQ(123, h2_prec.weight());
    EXPECT_EQ(is_exclusive, h2_prec.is_exclusive());
  }
}

TEST(SpdyStreamPrecedenceTest, Clamping) {
  EXPECT_QUICHE_BUG(EXPECT_EQ(7, SpdyStreamPrecedence(8).spdy3_priority()),
                    "Invalid priority: 8");
  EXPECT_QUICHE_BUG(EXPECT_EQ(kHttp2MinStreamWeight,
                              SpdyStreamPrecedence(3, 0, false).weight()),
                    "Invalid weight: 0");
  EXPECT_QUICHE_BUG(EXPECT_EQ(kHttp2MaxStreamWeight,
                              SpdyStreamPrecedence(3, 300, false).weight()),
                    "Invalid weight: 300");
}

TEST(SpdyStreamPrecedenceTest, Copying) {
  SpdyStreamPrecedence prec1(3);
  SpdyStreamPrecedence copy1(prec1);
  EXPECT_TRUE(copy1.is_spdy3_priority());
  EXPECT_EQ(3, copy1.spdy3_priority());

  SpdyStreamPrecedence prec2(4, 5, true);
  SpdyStreamPrecedence copy2(prec2);
  EXPECT_FALSE(copy2.is_spdy3_priority());
  EXPECT_EQ(4u, copy2.parent_id());
  EXPECT_EQ(5, copy2.weight());
  EXPECT_TRUE(copy2.is_exclusive());

  copy1 = prec2;
  EXPECT_FALSE(copy1.is_spdy3_priority());
  EXPECT_EQ(4u, copy1.parent_id());
  EXPECT_EQ(5, copy1.weight());
  EXPECT_TRUE(copy1.is_exclusive());

  copy2 = prec1;
  EXPECT_TRUE(copy2.is_spdy3_priority());
  EXPECT_EQ(3, copy2.spdy3_priority());
}

TEST(SpdyStreamPrecedenceTest, Equals) {
  EXPECT_EQ(SpdyStreamPrecedence(3), SpdyStreamPrecedence(3));
  EXPECT_NE(SpdyStreamPrecedence(3), SpdyStreamPrecedence(4));

  EXPECT_EQ(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(1, 2, false));
  EXPECT_NE(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(2, 2, false));
  EXPECT_NE(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(1, 3, false));
  EXPECT_NE(SpdyStreamPrecedence(1, 2, false),
            SpdyStreamPrecedence(1, 2, true));

  SpdyStreamPrecedence spdy3_prec(3);
  SpdyStreamPrecedence h2_prec(spdy3_prec.parent_id(), spdy3_prec.weight(),
                               spdy3_prec.is_exclusive());
  EXPECT_NE(spdy3_prec, h2_prec);
}

TEST(SpdyDataIRTest, Construct) {
  // Confirm that it makes a string of zero length from a
  // absl::string_view(nullptr).
  absl::string_view s1;
  SpdyDataIR d1(/* stream_id = */ 1, s1);
  EXPECT_EQ(0u, d1.data_len());
  EXPECT_NE(nullptr, d1.data());

  // Confirms makes a copy of char array.
  const char s2[] = "something";
  SpdyDataIR d2(/* stream_id = */ 2, s2);
  EXPECT_EQ(absl::string_view(d2.data(), d2.data_len()), s2);
  EXPECT_NE(absl::string_view(d1.data(), d1.data_len()), s2);
  EXPECT_EQ((int)d1.data_len(), d1.flow_control_window_consumed());

  // Confirm copies a const string.
  const std::string foo = "foo";
  SpdyDataIR d3(/* stream_id = */ 3, foo);
  EXPECT_EQ(foo, d3.data());
  EXPECT_EQ((int)d3.data_len(), d3.flow_control_window_consumed());

  // Confirm copies a non-const string.
  std::string bar = "bar";
  SpdyDataIR d4(/* stream_id = */ 4, bar);
  EXPECT_EQ("bar", bar);
  EXPECT_EQ("bar", absl::string_view(d4.data(), d4.data_len()));

  // Confirm moves an rvalue reference. Note that the test string "baz" is too
  // short to trigger the move optimization, and instead a copy occurs.
  std::string baz = "the quick brown fox";
  SpdyDataIR d5(/* stream_id = */ 5, std::move(baz));
  EXPECT_EQ("", baz);  // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(absl::string_view(d5.data(), d5.data_len()), "the quick brown fox");

  // Confirms makes a copy of string literal.
  SpdyDataIR d7(/* stream_id = */ 7, "something else");
  EXPECT_EQ(absl::string_view(d7.data(), d7.data_len()), "something else");

  SpdyDataIR d8(/* stream_id = */ 8, "shawarma");
  d8.set_padding_len(20);
  EXPECT_EQ(28, d8.flow_control_window_consumed());
}

TEST(SpdySerializedFrameTest, Basic) {
  const std::string data = "0123456789";
  auto buffer = std::make_unique<char[]>(data.length());
  memcpy(buffer.get(), &data[0], data.length());

  SpdySerializedFrame frame(std::move(buffer), data.length());
  EXPECT_EQ(data.length(), frame.size());
  EXPECT_EQ(data, std::string(frame.data(), frame.size()));
  EXPECT_EQ(frame.begin(), frame.data());
  EXPECT_EQ(frame.end(), frame.data() + frame.size());
}

// =============================================================================
// Modern HTTP/2 Frame Representations Tests
// =============================================================================

TEST(ModernFrameTest, StandardLayoutAndTriviallyCopyable) {
  static_assert(std::is_standard_layout_v<PriorityFields>);
  static_assert(std::is_trivially_copyable_v<PriorityFields>);

  static_assert(std::is_standard_layout_v<SettingParameter>);
  static_assert(std::is_trivially_copyable_v<SettingParameter>);

  static_assert(std::is_standard_layout_v<AcceptChEntryView>);
  static_assert(std::is_trivially_copyable_v<AcceptChEntryView>);

  static_assert(std::is_standard_layout_v<DataFrame>);
  static_assert(std::is_trivially_copyable_v<DataFrame>);

  static_assert(std::is_standard_layout_v<HeadersFrame>);
  static_assert(std::is_trivially_copyable_v<HeadersFrame>);

  static_assert(std::is_standard_layout_v<PriorityFrame>);
  static_assert(std::is_trivially_copyable_v<PriorityFrame>);

  static_assert(std::is_standard_layout_v<RstStreamFrame>);
  static_assert(std::is_trivially_copyable_v<RstStreamFrame>);

  static_assert(std::is_standard_layout_v<SettingsFrame>);

  static_assert(std::is_standard_layout_v<PushPromiseFrame>);
  static_assert(std::is_trivially_copyable_v<PushPromiseFrame>);

  static_assert(std::is_standard_layout_v<PingFrame>);
  static_assert(std::is_trivially_copyable_v<PingFrame>);

  static_assert(std::is_standard_layout_v<GoAwayFrame>);
  static_assert(std::is_trivially_copyable_v<GoAwayFrame>);

  static_assert(std::is_standard_layout_v<WindowUpdateFrame>);
  static_assert(std::is_trivially_copyable_v<WindowUpdateFrame>);

  static_assert(std::is_standard_layout_v<ContinuationFrame>);
  static_assert(std::is_trivially_copyable_v<ContinuationFrame>);

  static_assert(std::is_standard_layout_v<AltSvcFrame>);
  static_assert(std::is_trivially_copyable_v<AltSvcFrame>);

  static_assert(std::is_standard_layout_v<PriorityUpdateFrame>);
  static_assert(std::is_trivially_copyable_v<PriorityUpdateFrame>);

  static_assert(std::is_standard_layout_v<AcceptChFrame>);
  static_assert(std::is_trivially_copyable_v<AcceptChFrame>);

  static_assert(std::is_standard_layout_v<UnknownFrame>);
  static_assert(std::is_trivially_copyable_v<UnknownFrame>);

  static_assert(sizeof(SpdyFrame) <= 64,
                "SpdyFrame must fit in a 64-byte cache line");
}

TEST(ModernFrameTest, Http2FrameConcept) {
  static_assert(Http2FrameConcept<DataFrame>);
  static_assert(Http2FrameConcept<HeadersFrame>);
  static_assert(Http2FrameConcept<PriorityFrame>);
  static_assert(Http2FrameConcept<RstStreamFrame>);
  static_assert(Http2FrameConcept<SettingsFrame>);
  static_assert(Http2FrameConcept<PushPromiseFrame>);
  static_assert(Http2FrameConcept<PingFrame>);
  static_assert(Http2FrameConcept<GoAwayFrame>);
  static_assert(Http2FrameConcept<WindowUpdateFrame>);
  static_assert(Http2FrameConcept<ContinuationFrame>);
  static_assert(Http2FrameConcept<AltSvcFrame>);
  static_assert(Http2FrameConcept<PriorityUpdateFrame>);
  static_assert(Http2FrameConcept<AcceptChFrame>);
  static_assert(Http2FrameConcept<UnknownFrame>);

  // Non-frame types should not satisfy the concept.
  static_assert(!Http2FrameConcept<int>);
  static_assert(!Http2FrameConcept<std::string>);
  static_assert(!Http2FrameConcept<PriorityFields>);
  static_assert(!Http2FrameConcept<SpdyDataIR>);
}

TEST(ModernFrameTest, FrameTraits) {
  EXPECT_EQ(SpdyFrameType::DATA, frame_type_v<DataFrame>);
  EXPECT_EQ(SpdyFrameType::HEADERS, frame_type_v<HeadersFrame>);
  EXPECT_EQ(SpdyFrameType::PRIORITY, frame_type_v<PriorityFrame>);
  EXPECT_EQ(SpdyFrameType::RST_STREAM, frame_type_v<RstStreamFrame>);
  EXPECT_EQ(SpdyFrameType::SETTINGS, frame_type_v<SettingsFrame>);
  EXPECT_EQ(SpdyFrameType::PUSH_PROMISE, frame_type_v<PushPromiseFrame>);
  EXPECT_EQ(SpdyFrameType::PING, frame_type_v<PingFrame>);
  EXPECT_EQ(SpdyFrameType::GOAWAY, frame_type_v<GoAwayFrame>);
  EXPECT_EQ(SpdyFrameType::WINDOW_UPDATE, frame_type_v<WindowUpdateFrame>);
  EXPECT_EQ(SpdyFrameType::CONTINUATION, frame_type_v<ContinuationFrame>);
  EXPECT_EQ(SpdyFrameType::ALTSVC, frame_type_v<AltSvcFrame>);
  EXPECT_EQ(SpdyFrameType::PRIORITY_UPDATE, frame_type_v<PriorityUpdateFrame>);
  EXPECT_EQ(SpdyFrameType::ACCEPT_CH, frame_type_v<AcceptChFrame>);

  // Fixed size checks
  EXPECT_TRUE(is_fixed_size_v<PriorityFrame>);
  EXPECT_TRUE(is_fixed_size_v<RstStreamFrame>);
  EXPECT_TRUE(is_fixed_size_v<PingFrame>);
  EXPECT_TRUE(is_fixed_size_v<WindowUpdateFrame>);
  EXPECT_FALSE(is_fixed_size_v<DataFrame>);
  EXPECT_FALSE(is_fixed_size_v<HeadersFrame>);
  EXPECT_FALSE(is_fixed_size_v<SettingsFrame>);

  // Stream ID presence
  EXPECT_TRUE(has_stream_id_v<DataFrame>);
  EXPECT_TRUE(has_stream_id_v<HeadersFrame>);
  EXPECT_TRUE(has_stream_id_v<PriorityFrame>);
  EXPECT_TRUE(has_stream_id_v<RstStreamFrame>);
  EXPECT_TRUE(has_stream_id_v<PushPromiseFrame>);
  EXPECT_TRUE(has_stream_id_v<WindowUpdateFrame>);
  EXPECT_FALSE(has_stream_id_v<SettingsFrame>);
  EXPECT_FALSE(has_stream_id_v<PingFrame>);
  EXPECT_FALSE(has_stream_id_v<GoAwayFrame>);

  // Fin flag presence
  EXPECT_TRUE(has_fin_v<DataFrame>);
  EXPECT_TRUE(has_fin_v<HeadersFrame>);
  EXPECT_FALSE(has_fin_v<RstStreamFrame>);
  EXPECT_FALSE(has_fin_v<SettingsFrame>);

  // Padding presence
  EXPECT_TRUE(has_padding_v<DataFrame>);
  EXPECT_TRUE(has_padding_v<HeadersFrame>);
  EXPECT_TRUE(has_padding_v<PushPromiseFrame>);
  EXPECT_FALSE(has_padding_v<PingFrame>);

  // Flow control consumption
  EXPECT_TRUE(consumes_flow_control_v<DataFrame>);
  EXPECT_FALSE(consumes_flow_control_v<HeadersFrame>);
  EXPECT_FALSE(consumes_flow_control_v<SettingsFrame>);
}

TEST(ModernFrameTest, FrameSizeCalculation) {
  DataFrame data{.stream_id = 1, .data = "hello"};
  EXPECT_EQ(14u, FrameSize(data));
  data.flags = DATA_FLAG_PADDED;
  data.padding_payload_len = 3;
  EXPECT_EQ(18u, FrameSize(data));

  HeadersFrame headers{.stream_id = 1, .hpack_block = "0123456789"};
  EXPECT_EQ(19u, FrameSize(headers));
  headers.has_priority = true;
  EXPECT_EQ(24u, FrameSize(headers));

  PriorityFrame priority{.stream_id = 1};
  EXPECT_EQ(14u, FrameSize(priority));

  RstStreamFrame rst{.stream_id = 1};
  EXPECT_EQ(13u, FrameSize(rst));

  SettingsFrame settings_ack{.is_ack = true, .values = {}};
  EXPECT_EQ(9u, FrameSize(settings_ack));
  SettingsFrame settings_data{
      .is_ack = false,
      .values = {{SETTINGS_HEADER_TABLE_SIZE, 4096},
                 {SETTINGS_MAX_CONCURRENT_STREAMS, 100}}};
  EXPECT_EQ(21u, FrameSize(settings_data));

  PushPromiseFrame push{
      .stream_id = 1, .promised_stream_id = 2, .hpack_block = "12345678"};
  EXPECT_EQ(21u, FrameSize(push));

  PingFrame ping{};
  EXPECT_EQ(17u, FrameSize(ping));

  GoAwayFrame goaway{.debug_data = "abcd"};
  EXPECT_EQ(21u, FrameSize(goaway));

  WindowUpdateFrame win{.stream_id = 1, .delta = 100};
  EXPECT_EQ(13u, FrameSize(win));

  ContinuationFrame cont{.stream_id = 1, .hpack_block = "abcdef"};
  EXPECT_EQ(15u, FrameSize(cont));

  AltSvcFrame altsvc{.stream_id = 1, .origin = "foo", .value = "h2=\":443\""};
  EXPECT_EQ(9u + 2u + 3u + 9u, FrameSize(altsvc));

  PriorityUpdateFrame prio_up{.prioritized_stream_id = 3,
                              .priority_field_value = "u=3,i"};
  EXPECT_EQ(9u + 4u + 5u, FrameSize(prio_up));

  AcceptChFrame accept_ch{.num_entries = 1,
                          .entries = {{{.origin = "foo", .value = "bar"}}}};
  EXPECT_EQ(9u + 4u + 3u + 3u, FrameSize(accept_ch));

  UnknownFrame unknown{.type = 0x99, .payload = "payload"};
  EXPECT_EQ(16u, FrameSize(unknown));
}

TEST(ModernFrameTest, SerializeDataFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  DataFrame df{.stream_id = 3, .flags = DATA_FLAG_FIN, .data = "hello world"};
  SpdyFrameBuilder builder(FrameSize(df));
  EXPECT_TRUE(SerializeFrame(df, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyDataIR data_ir(3, "hello world");
  data_ir.set_fin(true);
  SpdySerializedFrame expected = framer.SerializeData(data_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializePriorityFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  PriorityFrame pf{
      .stream_id = 5,
      .priority = {.parent_stream_id = 1, .weight = 32, .exclusive = true}};
  SpdyFrameBuilder builder(FrameSize(pf));
  EXPECT_TRUE(SerializeFrame(pf, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyPriorityIR prio_ir(5, 1, 32, true);
  SpdySerializedFrame expected = framer.SerializePriority(prio_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeRstStreamFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  // 3. RST_STREAM frame
  RstStreamFrame rf{.stream_id = 7, .error_code = ERROR_CODE_CANCEL};
  SpdyFrameBuilder builder(FrameSize(rf));
  EXPECT_TRUE(SerializeFrame(rf, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyRstStreamIR rst_ir(7, ERROR_CODE_CANCEL);
  SpdySerializedFrame expected = framer.SerializeRstStream(rst_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeSettingsFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  // SETTINGS ack.
  {
    SettingsFrame sf_ack{.is_ack = true, .values = {}};
    SpdyFrameBuilder builder(FrameSize(sf_ack));
    EXPECT_TRUE(SerializeFrame(sf_ack, builder));
    SpdySerializedFrame serialized = builder.take();

    SpdySettingsIR settings_ack_ir;
    settings_ack_ir.set_is_ack(true);
    SpdySerializedFrame expected = framer.SerializeSettings(settings_ack_ir);

    EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
  }
  // SETTINGS with values.
  {
    SettingsFrame sf_vals{.is_ack = false,
                          .values = {{SETTINGS_HEADER_TABLE_SIZE, 4096},
                                     {SETTINGS_MAX_CONCURRENT_STREAMS, 100}}};
    SpdyFrameBuilder builder(FrameSize(sf_vals));
    EXPECT_TRUE(SerializeFrame(sf_vals, builder));
    SpdySerializedFrame serialized = builder.take();

    SpdySettingsIR settings_ir;
    settings_ir.AddSetting(SETTINGS_HEADER_TABLE_SIZE, 4096);
    settings_ir.AddSetting(SETTINGS_MAX_CONCURRENT_STREAMS, 100);
    SpdySerializedFrame expected = framer.SerializeSettings(settings_ir);

    EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
  }
}

TEST(ModernFrameTest, SerializePingFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  PingFrame ping{.opaque_data = 0x0102030405060708ULL, .is_ack = true};
  SpdyFrameBuilder builder(FrameSize(ping));
  EXPECT_TRUE(SerializeFrame(ping, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyPingIR ping_ir(0x0102030405060708ULL);
  ping_ir.set_is_ack(true);
  SpdySerializedFrame expected = framer.SerializePing(ping_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeGoAwayFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  GoAwayFrame goaway{.last_good_stream_id = 9,
                     .error_code = ERROR_CODE_PROTOCOL_ERROR,
                     .debug_data = "protocol error occurred"};
  SpdyFrameBuilder builder(FrameSize(goaway));
  EXPECT_TRUE(SerializeFrame(goaway, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyGoAwayIR goaway_ir(9, ERROR_CODE_PROTOCOL_ERROR,
                         "protocol error occurred");
  SpdySerializedFrame expected = framer.SerializeGoAway(goaway_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeWindowUpdateFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  WindowUpdateFrame win{.stream_id = 11, .delta = 65535};
  SpdyFrameBuilder builder(FrameSize(win));
  EXPECT_TRUE(SerializeFrame(win, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyWindowUpdateIR win_ir(11, 65535);
  SpdySerializedFrame expected = framer.SerializeWindowUpdate(win_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeContinuationFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  ContinuationFrame cont{.stream_id = 13,
                         .flags = HEADERS_FLAG_END_HEADERS,
                         .hpack_block = "continuation_block"};
  SpdyFrameBuilder builder(FrameSize(cont));
  EXPECT_TRUE(SerializeFrame(cont, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyContinuationIR cont_ir(13);
  cont_ir.set_end_headers(true);
  cont_ir.take_encoding("continuation_block");
  SpdySerializedFrame expected = framer.SerializeContinuation(cont_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializePriorityUpdateFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  PriorityUpdateFrame prio_up{.prioritized_stream_id = 5,
                              .priority_field_value = "u=1,i"};
  SpdyFrameBuilder builder(FrameSize(prio_up));
  EXPECT_TRUE(SerializeFrame(prio_up, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyPriorityUpdateIR prio_up_ir(0, 5, "u=1,i");
  SpdySerializedFrame expected = framer.SerializePriorityUpdate(prio_up_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeAcceptChFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  AcceptChFrame accept_ch{
      .num_entries = 1,
      .entries = {{{.origin = "example.com", .value = "sec-ch-ua"}}}};
  SpdyFrameBuilder builder(FrameSize(accept_ch));
  EXPECT_TRUE(SerializeFrame(accept_ch, builder));
  SpdySerializedFrame serialized = builder.take();

  SpdyAcceptChIR accept_ch_ir(
      {AcceptChOriginValuePair{.origin = "example.com", .value = "sec-ch-ua"}});
  SpdySerializedFrame expected = framer.SerializeAcceptCh(accept_ch_ir);

  EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
}

TEST(ModernFrameTest, SerializeUnknownFrame) {
  SpdyFramer framer(SpdyFramer::ENABLE_COMPRESSION);

  // 11. UNKNOWN frame
  {
    UnknownFrame unknown{.stream_id = 1,
                         .type = 0xfe,
                         .flags = 0x05,
                         .payload = "custom_payload"};
    SpdyFrameBuilder builder(FrameSize(unknown));
    EXPECT_TRUE(SerializeFrame(unknown, builder));
    SpdySerializedFrame serialized = builder.take();

    SpdyUnknownIR unknown_ir(1, 0xfe, 0x05, "custom_payload");
    SpdySerializedFrame expected = framer.SerializeUnknown(unknown_ir);

    EXPECT_EQ(absl::string_view(expected), absl::string_view(serialized));
  }
}

TEST(ModernFrameTest, SpdyFrameVariant) {
  SpdyFrame frame = DataFrame{.stream_id = 42, .data = "payload"};
  EXPECT_EQ(42u, GetFrameStreamId(frame));
  EXPECT_EQ(SpdyFrameType::DATA, GetFrameType(frame));
  EXPECT_EQ(16u, GetFrameSize(frame));

  frame = PingFrame{.opaque_data = 123};
  EXPECT_EQ(0u, GetFrameStreamId(frame));
  EXPECT_EQ(SpdyFrameType::PING, GetFrameType(frame));
  EXPECT_EQ(17u, GetFrameSize(frame));

  SpdyFrameBuilder builder(GetFrameSize(frame));
  EXPECT_TRUE(SerializeSpdyFrame(frame, builder));
  EXPECT_EQ(17u, builder.length());
}

}  // namespace test
}  // namespace spdy
