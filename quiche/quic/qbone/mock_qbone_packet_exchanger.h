// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QBONE_MOCK_QBONE_PACKET_EXCHANGER_H_
#define QUICHE_QUIC_QBONE_MOCK_QBONE_PACKET_EXCHANGER_H_

#include <cstddef>
#include <memory>
#include <string>

#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/qbone_packet_exchanger.h"

namespace quic::test {

class MockQbonePacketExchanger : public QbonePacketExchanger {
 public:
  MockQbonePacketExchanger() : QbonePacketExchanger(/*visitor=*/nullptr) {}

  MOCK_METHOD(std::unique_ptr<QuicData>, ReadPacket, (std::string * error),
              (override));
  MOCK_METHOD(bool, WritePacket,
              (const char* packet, size_t size, std::string* error),
              (override));
};

}  // namespace quic::test

#endif  // QUICHE_QUIC_QBONE_MOCK_QBONE_PACKET_EXCHANGER_H_
