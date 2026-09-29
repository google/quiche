// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/web_transport_stream_adapter.h"

#include <array>
#include <memory>
#include <optional>

#include "absl/status/status.h"
#include "absl/types/span.h"
#include "quiche/quic/core/crypto/null_encrypter.h"
#include "quiche/quic/core/quic_stream.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/quic_config_peer.h"
#include "quiche/quic/test_tools/quic_flow_controller_peer.h"
#include "quiche/quic/test_tools/quic_stream_peer.h"
#include "quiche/quic/test_tools/quic_test_utils.h"
#include "quiche/common/quiche_mem_slice.h"

using testing::_;
using testing::AnyNumber;
using testing::Return;
using testing::StrictMock;

namespace quic {
namespace test {
namespace {

class TestStream : public QuicStream {
 public:
  TestStream(QuicStreamId id, QuicSession* session)
      : QuicStream(id, session, /*is_static=*/false, BIDIRECTIONAL) {
    sequencer()->set_level_triggered(true);
  }

  MOCK_METHOD(void, OnDataAvailable, (), (override));
  MOCK_METHOD(void, OnCanWriteNewData, (), (override));
  MOCK_METHOD(void, OnWriteSideInDataRecvdState, (), (override));

  using QuicStream::WriteOrBufferData;
};

class WebTransportStreamAdapterTest
    : public QuicTestWithParam<ParsedQuicVersion> {
 protected:
  void Initialize() {
    connection_ = new StrictMock<MockQuicConnection>(
        &helper_, &alarm_factory_, Perspective::IS_SERVER,
        ParsedQuicVersionVector{GetParam()});
    session_ = std::make_unique<MockQuicSession>(connection_);
    session_->Initialize();
    connection_->SetEncrypter(
        ENCRYPTION_FORWARD_SECURE,
        std::make_unique<NullEncrypter>(connection_->perspective()));
    QuicConfigPeer::SetReceivedInitialSessionFlowControlWindow(
        session_->config(), kMinimumFlowControlSendWindow);
    QuicConfigPeer::SetReceivedInitialMaxStreamDataBytesIncomingBidirectional(
        session_->config(), kMinimumFlowControlSendWindow);
    session_->OnConfigNegotiated();

    stream_ = new StrictMock<TestStream>(kTestStreamId, session_.get());
    session_->ActivateStream(absl::WrapUnique(stream_));
    EXPECT_CALL(*session_, ShouldKeepConnectionAlive())
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*session_, MaybeSendStopSendingFrame(kTestStreamId, _))
        .Times(AnyNumber());
    EXPECT_CALL(*session_, MaybeSendRstStreamFrame(kTestStreamId, _, _))
        .Times(AnyNumber());
    adapter_ = std::make_unique<WebTransportStreamAdapter>(
        session_.get(), stream_, QuicStreamPeer::sequencer(stream_),
        std::nullopt);
  }

  MockQuicConnectionHelper helper_;
  MockAlarmFactory alarm_factory_;
  MockQuicConnection* connection_ = nullptr;
  std::unique_ptr<MockQuicSession> session_;
  StrictMock<TestStream>* stream_ = nullptr;
  std::unique_ptr<WebTransportStreamAdapter> adapter_;
  const QuicStreamId kTestStreamId = GetNthClientInitiatedBidirectionalStreamId(
      GetParam().transport_version, 1);
};

INSTANTIATE_TEST_SUITE_P(WebTransportStreamAdapterTests,
                         WebTransportStreamAdapterTest,
                         ::testing::ValuesIn(CurrentSupportedHttp3Versions()),
                         ::testing::PrintToStringParamName());

TEST_P(WebTransportStreamAdapterTest, AtomicWriteRequiresStreamCredit) {
  Initialize();
  QuicStreamPeer::SetSendWindowOffset(stream_, 4);
  std::array slices = {quiche::QuicheMemSlice::Copy("12345")};
  webtransport::StreamWriteOptions options;
  options.set_atomic_write(true);

  EXPECT_EQ(absl::StatusCode::kResourceExhausted,
            adapter_->Writev(absl::MakeSpan(slices), options).code());
  EXPECT_EQ(0u, stream_->BufferedDataBytes());
}

TEST_P(WebTransportStreamAdapterTest, AtomicWriteAcceptsExactStreamCredit) {
  Initialize();
  QuicStreamPeer::SetSendWindowOffset(stream_, 4);
  std::array slices = {quiche::QuicheMemSlice::Copy("1234")};
  EXPECT_CALL(*session_, WritevData(kTestStreamId, 4, 0, _, _, _))
      .WillOnce(Return(QuicConsumedData(4, false)));
  EXPECT_CALL(*session_, SendBlocked(_, 4));
  webtransport::StreamWriteOptions options;
  options.set_atomic_write(true);

  EXPECT_TRUE(adapter_->Writev(absl::MakeSpan(slices), options).ok());
  EXPECT_EQ(0u, stream_->BufferedDataBytes());
}

TEST_P(WebTransportStreamAdapterTest, AtomicWriteAccountsForBufferedData) {
  Initialize();
  EXPECT_CALL(*session_, WritevData(kTestStreamId, _, _, _, _, _))
      .WillOnce(Return(QuicConsumedData(0, false)));
  stream_->WriteOrBufferData("12", false, nullptr);
  ASSERT_EQ(2u, stream_->BufferedDataBytes());
  QuicStreamPeer::SetSendWindowOffset(stream_, 4);
  std::array slices = {quiche::QuicheMemSlice::Copy("345")};
  webtransport::StreamWriteOptions options;
  options.set_atomic_write(true);

  EXPECT_EQ(absl::StatusCode::kResourceExhausted,
            adapter_->Writev(absl::MakeSpan(slices), options).code());
  EXPECT_EQ(2u, stream_->BufferedDataBytes());
}

TEST_P(WebTransportStreamAdapterTest, AtomicWriteRequiresConnectionCredit) {
  Initialize();
  QuicStreamPeer::SetSendWindowOffset(stream_, 10);
  QuicFlowControllerPeer::SetSendWindowOffset(session_->flow_controller(), 3);
  std::array slices = {quiche::QuicheMemSlice::Copy("1234")};
  webtransport::StreamWriteOptions options;
  options.set_atomic_write(true);

  EXPECT_EQ(absl::StatusCode::kResourceExhausted,
            adapter_->Writev(absl::MakeSpan(slices), options).code());
  EXPECT_EQ(0u, stream_->BufferedDataBytes());
}

TEST_P(WebTransportStreamAdapterTest, AtomicWriteCanSendFin) {
  Initialize();
  QuicStreamPeer::SetSendWindowOffset(stream_, 4);
  std::array slices = {quiche::QuicheMemSlice::Copy("1234")};
  EXPECT_CALL(*session_, WritevData(kTestStreamId, 4, 0, _, _, _))
      .WillOnce(Return(QuicConsumedData(4, true)));
  EXPECT_CALL(*session_, SendBlocked(_, 4));
  webtransport::StreamWriteOptions options;
  options.set_atomic_write(true);
  options.set_send_fin(true);

  EXPECT_TRUE(adapter_->Writev(absl::MakeSpan(slices), options).ok());
  EXPECT_TRUE(stream_->fin_sent());
}

}  // namespace
}  // namespace test
}  // namespace quic
