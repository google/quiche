// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "net/third_party/quiche/src/quic/core/quic_bandwidth.h"
#include "net/third_party/quiche/src/quic/core/quic_time.h"
#include "net/third_party/quiche/src/quic/core/quic_types.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/quartc/simulated_packet_transport.h"
#include "net/third_party/quiche/src/quic/quartc/test/bidi_test_runner.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/link.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/simulator.h"

namespace quic {
namespace test {
namespace {

class QuartcBidiTest : public QuicTest {
 protected:
  QuartcBidiTest() {}

  void CreateTransports(QuicBandwidth bandwidth,
                        QuicTime::Delta propagation_delay,
                        QuicByteCount queue_length) {
    client_transport_ =
        QuicMakeUnique<simulator::SimulatedQuartcPacketTransport>(
            &simulator_, "client_transport", "server_transport", queue_length);
    server_transport_ =
        QuicMakeUnique<simulator::SimulatedQuartcPacketTransport>(
            &simulator_, "server_transport", "client_transport", queue_length);
    client_server_link_ = QuicMakeUnique<simulator::SymmetricLink>(
        client_transport_.get(), server_transport_.get(), bandwidth,
        propagation_delay);
  }

  simulator::Simulator simulator_;

  std::unique_ptr<simulator::SimulatedQuartcPacketTransport> client_transport_;
  std::unique_ptr<simulator::SimulatedQuartcPacketTransport> server_transport_;
  std::unique_ptr<simulator::SymmetricLink> client_server_link_;
};

TEST_F(QuartcBidiTest, Basic300kbps200ms) {
  CreateTransports(QuicBandwidth::FromKBitsPerSecond(300),
                   QuicTime::Delta::FromMilliseconds(200),
                   10 * kDefaultMaxPacketSize);
  BidiTestRunner runner(&simulator_, client_transport_.get(),
                        server_transport_.get());
  EXPECT_TRUE(runner.RunTest(QuicTime::Delta::FromSeconds(30)));
}

}  // namespace
}  // namespace test
}  // namespace quic
