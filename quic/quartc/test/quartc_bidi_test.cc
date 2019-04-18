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
#include "net/third_party/quiche/src/quic/quartc/test/random_delay_link.h"
#include "net/third_party/quiche/src/quic/quartc/test/random_packet_filter.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"
#include "net/third_party/quiche/src/quic/test_tools/simulator/simulator.h"

namespace quic {
namespace test {
namespace {

class QuartcBidiTest : public QuicTest {
 protected:
  QuartcBidiTest() {
    uint64_t seed = QuicRandom::GetInstance()->RandUint64();
    QUIC_LOG(INFO) << "Setting random seed to " << seed;
    random_.set_seed(seed);
    simulator_.set_random_generator(&random_);
  }

  void CreateTransports(QuicBandwidth bandwidth,
                        QuicTime::Delta propagation_delay,
                        QuicByteCount queue_length,
                        int loss_percent) {
    client_transport_ =
        QuicMakeUnique<simulator::SimulatedQuartcPacketTransport>(
            &simulator_, "client_transport", "server_transport", queue_length);
    server_transport_ =
        QuicMakeUnique<simulator::SimulatedQuartcPacketTransport>(
            &simulator_, "server_transport", "client_transport", queue_length);
    client_filter_ = QuicMakeUnique<simulator::RandomPacketFilter>(
        &simulator_, "client_filter", client_transport_.get());
    server_filter_ = QuicMakeUnique<simulator::RandomPacketFilter>(
        &simulator_, "server_filter", server_transport_.get());
    client_server_link_ = QuicMakeUnique<simulator::SymmetricRandomDelayLink>(
        client_filter_.get(), server_filter_.get(), bandwidth,
        propagation_delay);
    client_filter_->set_loss_percent(loss_percent);
    server_filter_->set_loss_percent(loss_percent);
  }

  simulator::Simulator simulator_;
  SimpleRandom random_;

  std::unique_ptr<simulator::SimulatedQuartcPacketTransport> client_transport_;
  std::unique_ptr<simulator::SimulatedQuartcPacketTransport> server_transport_;
  std::unique_ptr<simulator::RandomPacketFilter> client_filter_;
  std::unique_ptr<simulator::RandomPacketFilter> server_filter_;
  std::unique_ptr<simulator::SymmetricRandomDelayLink> client_server_link_;
};

TEST_F(QuartcBidiTest, Basic300kbps200ms) {
  CreateTransports(QuicBandwidth::FromKBitsPerSecond(300),
                   QuicTime::Delta::FromMilliseconds(200),
                   10 * kDefaultMaxPacketSize, /*loss_percent=*/0);
  BidiTestRunner runner(&simulator_, client_transport_.get(),
                        server_transport_.get());
  EXPECT_TRUE(runner.RunTest(QuicTime::Delta::FromSeconds(30)));
}

TEST_F(QuartcBidiTest, 300kbps200ms2PercentLoss) {
  CreateTransports(QuicBandwidth::FromKBitsPerSecond(300),
                   QuicTime::Delta::FromMilliseconds(200),
                   10 * kDefaultMaxPacketSize, /*loss_percent=*/2);
  BidiTestRunner runner(&simulator_, client_transport_.get(),
                        server_transport_.get());
  EXPECT_TRUE(runner.RunTest(QuicTime::Delta::FromSeconds(30)));
}

TEST_F(QuartcBidiTest, 300kbps200ms25msRandom2PercentLoss) {
  CreateTransports(QuicBandwidth::FromKBitsPerSecond(300),
                   QuicTime::Delta::FromMilliseconds(200),
                   10 * kDefaultMaxPacketSize, /*loss_percent=*/2);
  client_server_link_->set_median_random_delay(
      QuicTime::Delta::FromMilliseconds(25));
  BidiTestRunner runner(&simulator_, client_transport_.get(),
                        server_transport_.get());
  EXPECT_TRUE(runner.RunTest(QuicTime::Delta::FromSeconds(30)));
}

}  // namespace
}  // namespace test
}  // namespace quic
