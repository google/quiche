// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/quartc/quartc_endpoint.h"

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/quartc/simulated_packet_transport.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/simulator.h"

namespace quic {
namespace {

static QuicByteCount kDefaultMaxPacketSize = 1200;

class FakeEndpointDelegate : public QuartcEndpoint::Delegate {
 public:
  void OnSessionCreated(QuartcSession* session) override {
    last_session_ = session;
  }

  void OnConnectError(QuicErrorCode /*error*/,
                      const QuicString& /*error_details*/) override {}

  QuartcSession* last_session() { return last_session_; }

 private:
  QuartcSession* last_session_ = nullptr;
};

class QuartcEndpointTest : public QuicTest {
 protected:
  QuartcEndpointTest()
      : transport_(&simulator_,
                   "client_transport",
                   "server_transport",
                   10 * kDefaultMaxPacketSize) {}

  simulator::Simulator simulator_;
  simulator::SimulatedQuartcPacketTransport transport_;
  FakeEndpointDelegate delegate_;
};

// After calling Connect, the client endpoint must wait for an async callback.
// The callback occurs after a finite amount of time and produces a session.
TEST_F(QuartcEndpointTest, ClientCreatesSessionAsynchronously) {
  QuartcClientEndpoint endpoint_(simulator_.GetAlarmFactory(),
                                 simulator_.GetClock(), &delegate_,
                                 /*serialized_server_config=*/"");
  QuartcSessionConfig config;
  config.packet_transport = &transport_;
  config.max_packet_size = kDefaultMaxPacketSize;
  endpoint_.Connect(config);

  EXPECT_EQ(delegate_.last_session(), nullptr);

  EXPECT_TRUE(simulator_.RunUntil(
      [this] { return delegate_.last_session() != nullptr; }));
}

}  // namespace
}  // namespace quic
