// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/web_transport/encapsulated/encapsulated_web_transport.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "quiche/common/capsule.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_stream.h"
#include "quiche/common/simple_buffer_allocator.h"
#include "quiche/common/test_tools/mock_streams.h"
#include "quiche/web_transport/test_tools/mock_web_transport.h"
#include "quiche/web_transport/web_transport.h"

namespace webtransport::test {
namespace {

using ::quiche::Capsule;
using ::quiche::CapsuleType;
using ::testing::_;
using ::testing::HasSubstr;
using ::testing::IsEmpty;
using ::testing::Return;
using ::testing::StrEq;

class EncapsulatedWebTransportTest : public quiche::test::QuicheTest,
                                     public quiche::CapsuleParser::Visitor {
 public:
  EncapsulatedWebTransportTest() : parser_(this), reader_(&read_buffer_) {
    ON_CALL(fatal_error_callback_, Call(_))
        .WillByDefault([](absl::string_view error) {
          ADD_FAILURE() << "Fatal session error: " << error;
        });
    ON_CALL(writer_, Writev(_, _))
        .WillByDefault([&](absl::Span<const absl::string_view> data,
                           const quiche::StreamWriteOptions& options) {
          for (absl::string_view fragment : data) {
            parser_.IngestCapsuleFragment(fragment);
          }
          writer_.ProcessOptions(options);
          return absl::OkStatus();
        });
  }

  std::unique_ptr<EncapsulatedSession> CreateTransport(
      Perspective perspective) {
    auto transport = std::make_unique<EncapsulatedSession>(
        perspective, fatal_error_callback_.AsStdFunction());
    session_ = transport.get();
    return transport;
  }

  std::unique_ptr<SessionVisitor> CreateAndStoreVisitor() {
    auto visitor = std::make_unique<testing::StrictMock<MockSessionVisitor>>();
    visitor_ = visitor.get();
    return visitor;
  }

  MOCK_METHOD(bool, OnCapsule, (const Capsule&), (override));

  void OnCapsuleParseFailure(absl::string_view error_message) override {
    ADD_FAILURE() << "Written an invalid capsule: " << error_message;
  }

  void ProcessIncomingCapsule(const Capsule& capsule) {
    quiche::QuicheBuffer buffer =
        quiche::SerializeCapsule(capsule, quiche::SimpleBufferAllocator::Get());
    read_buffer_.append(buffer.data(), buffer.size());
    session_->OnCanRead();
  }

  void DefaultHandshakeForClient(EncapsulatedSession& session) {
    quiche::HttpHeaderBlock outgoing_headers, incoming_headers;
    session.InitializeClient(CreateAndStoreVisitor(), outgoing_headers,
                             &writer_, &reader_);
    EXPECT_CALL(*visitor_, OnSessionReady());
    session.ProcessIncomingServerHeaders(incoming_headers);
  }

 protected:
  quiche::CapsuleParser parser_;
  quiche::test::MockWriteStream writer_;
  std::string read_buffer_;
  quiche::test::ReadStreamFromString reader_;
  MockSessionVisitor* visitor_ = nullptr;
  EncapsulatedSession* session_ = nullptr;
  testing::MockFunction<void(absl::string_view)> fatal_error_callback_;
};

TEST_F(EncapsulatedWebTransportTest, SetupClientSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  quiche::HttpHeaderBlock outgoing_headers, incoming_headers;
  EXPECT_EQ(session->state(), EncapsulatedSession::kUninitialized);
  session->InitializeClient(CreateAndStoreVisitor(), outgoing_headers, &writer_,
                            &reader_);
  EXPECT_EQ(session->state(), EncapsulatedSession::kWaitingForHeaders);
  EXPECT_CALL(*visitor_, OnSessionReady());
  session->ProcessIncomingServerHeaders(incoming_headers);
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
}

TEST_F(EncapsulatedWebTransportTest, SetupServerSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kServer);
  quiche::HttpHeaderBlock outgoing_headers, incoming_headers;
  EXPECT_EQ(session->state(), EncapsulatedSession::kUninitialized);
  std::unique_ptr<SessionVisitor> visitor = CreateAndStoreVisitor();
  EXPECT_CALL(*visitor_, OnSessionReady());
  session->InitializeServer(std::move(visitor), outgoing_headers,
                            incoming_headers, &writer_, &reader_);
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
}

TEST_F(EncapsulatedWebTransportTest, CloseSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::CLOSE_WEBTRANSPORT_SESSION);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_code, 0x1234);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_message,
              "test close");
    return true;
  });
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
  EXPECT_CALL(*visitor_, OnSessionClosed(0x1234, StrEq("test close")));
  session->CloseSession(0x1234, "test close");
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionClosed);
  EXPECT_TRUE(writer_.fin_written());

  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("close a session that is already closed"));
      });
  session->CloseSession(0x1234, "test close");
}

TEST_F(EncapsulatedWebTransportTest, CloseSessionWriteBlocked) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(writer_, CanWrite()).WillOnce(Return(false));
  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionOpen);
  session->CloseSession(0x1234, "test close");
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionClosing);

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::CLOSE_WEBTRANSPORT_SESSION);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_code, 0x1234);
    EXPECT_EQ(capsule.close_web_transport_session_capsule().error_message,
              "test close");
    return true;
  });
  EXPECT_CALL(writer_, CanWrite()).WillOnce(Return(true));
  EXPECT_CALL(*visitor_, OnSessionClosed(0x1234, StrEq("test close")));
  session->OnCanWrite();
  EXPECT_EQ(session->state(), EncapsulatedSession::kSessionClosed);
  EXPECT_TRUE(writer_.fin_written());
}

TEST_F(EncapsulatedWebTransportTest, ReceiveFin) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  EXPECT_CALL(*visitor_, OnSessionClosed(0, IsEmpty()));
  reader_.set_fin();
  session->OnCanRead();
  EXPECT_TRUE(writer_.fin_written());
}

TEST_F(EncapsulatedWebTransportTest, ReceiveCloseSession) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  EXPECT_CALL(*visitor_, OnSessionClosed(0x1234, StrEq("test")));
  ProcessIncomingCapsule(Capsule::CloseWebTransportSession(0x1234, "test"));
  EXPECT_TRUE(writer_.fin_written());
  reader_.set_fin();
  session->OnCanRead();
}

TEST_F(EncapsulatedWebTransportTest, ReceiveMalformedData) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);

  EXPECT_CALL(fatal_error_callback_, Call(HasSubstr("too much capsule data")))
      .WillOnce([] {});
  read_buffer_ = std::string(2 * 1024 * 1024, '\xff');
  session->OnCanRead();
}

TEST_F(EncapsulatedWebTransportTest, SendDatagrams) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), quiche::CapsuleType::DATAGRAM);
    EXPECT_EQ(capsule.datagram_capsule().http_datagram_payload, "test");
    return true;
  });
  DatagramStatus status = session->SendOrQueueDatagram("test");
  EXPECT_EQ(status.code, DatagramStatusCode::kSuccess);
}

TEST_F(EncapsulatedWebTransportTest, SendDatagramsEarly) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  quiche::HttpHeaderBlock outgoing_headers;
  session->InitializeClient(CreateAndStoreVisitor(), outgoing_headers, &writer_,
                            &reader_);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), quiche::CapsuleType::DATAGRAM);
    EXPECT_EQ(capsule.datagram_capsule().http_datagram_payload, "test");
    return true;
  });
  ASSERT_EQ(session->state(), EncapsulatedSession::kWaitingForHeaders);
  session->SendOrQueueDatagram("test");
}

TEST_F(EncapsulatedWebTransportTest, SendDatagramsBeforeInitialization) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  quiche::HttpHeaderBlock outgoing_headers;
  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  ASSERT_EQ(session->state(), EncapsulatedSession::kUninitialized);
  session->SendOrQueueDatagram("test");

  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::DATAGRAM);
    EXPECT_EQ(capsule.datagram_capsule().http_datagram_payload, "test");
    return true;
  });
  DefaultHandshakeForClient(*session);
}

TEST_F(EncapsulatedWebTransportTest, SendDatagramsTooBig) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).Times(0);
  std::string long_string(16 * 1024, 'a');
  DatagramStatus status = session->SendOrQueueDatagram(long_string);
  EXPECT_EQ(status.code, DatagramStatusCode::kTooBig);
}

TEST_F(EncapsulatedWebTransportTest, ReceiveDatagrams) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*visitor_, OnDatagramReceived(_))
      .WillOnce([](absl::string_view data) { EXPECT_EQ(data, "test"); });
  ProcessIncomingCapsule(Capsule::Datagram("test"));
}

TEST_F(EncapsulatedWebTransportTest, SendDraining) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(*this, OnCapsule(_)).WillOnce([](const Capsule& capsule) {
    EXPECT_EQ(capsule.capsule_type(), CapsuleType::DRAIN_WEBTRANSPORT_SESSION);
    return true;
  });
  session->NotifySessionDraining();
}

TEST_F(EncapsulatedWebTransportTest, ReceiveDraining) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  testing::MockFunction<void()> callback;
  session->SetOnDraining(callback.AsStdFunction());
  EXPECT_CALL(callback, Call());
  ProcessIncomingCapsule(Capsule(quiche::DrainWebTransportSessionCapsule()));
}

TEST_F(EncapsulatedWebTransportTest, WriteErrorDatagram) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(writer_, Writev(_, _))
      .WillOnce(Return(absl::InternalError("Test write error")));
  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("Test write error"));
      });
  DatagramStatus status = session->SendOrQueueDatagram("test");
  EXPECT_EQ(status.code, DatagramStatusCode::kInternalError);
}

TEST_F(EncapsulatedWebTransportTest, WriteErrorControlCapsule) {
  std::unique_ptr<EncapsulatedSession> session =
      CreateTransport(Perspective::kClient);
  DefaultHandshakeForClient(*session);
  EXPECT_CALL(writer_, Writev(_, _))
      .WillOnce(Return(absl::InternalError("Test write error")));
  EXPECT_CALL(fatal_error_callback_, Call(_))
      .WillOnce([](absl::string_view error) {
        EXPECT_THAT(error, HasSubstr("Test write error"));
      });
  session->NotifySessionDraining();
}

}  // namespace
}  // namespace webtransport::test
