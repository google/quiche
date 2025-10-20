// Copyright 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/test_tools/moqt_simulator.h"

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

}  // namespace
}  // namespace moqt::test
