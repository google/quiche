// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/test_tools/moqt_simulator.h"

#include "quiche/quic/core/quic_bandwidth.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/common/platform/api/quiche_test.h"

namespace moqt::test {
namespace {

class MoqtSimulatorTest : public quiche::test::QuicheTest {};

// Ensure the simulation works with default parameters.
TEST_F(MoqtSimulatorTest, DefaultSettings) {
  MoqtSimulator simulator(SimulationParameters{});
  simulator.Run();
  EXPECT_NEAR(simulator.received_on_time_fraction(), 1.0f, 0.001f);
}

// Ensure that the bitrate adaptation down works.
TEST_F(MoqtSimulatorTest, BandwidthTooLow) {
  SimulationParameters parameters;
  parameters.bandwidth = quic::QuicBandwidth::FromKBitsPerSecond(900);
  parameters.delivery_timeout = quic::QuicTimeDelta::FromSeconds(1);

  MoqtSimulator simulator(parameters);
  simulator.Run();
  EXPECT_GE(simulator.received_on_time_fraction(), 0.8f);
  EXPECT_LT(simulator.received_on_time_fraction(), 0.99f);
}

}  // namespace
}  // namespace moqt::test
