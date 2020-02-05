// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/core/quic_types.h"

#include <cstdint>

#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_str_cat.h"

namespace quic {
namespace test {
namespace {

class QuicTypesTest : public QuicTest {};

TEST_F(QuicTypesTest, QuicIetfTransportErrorCodeString) {
  // QuicIetfTransportErrorCode out of bound.
  for (quic::QuicErrorCode error = quic::QUIC_PACKET_TOO_LARGE;
       error < quic::QUIC_LAST_ERROR;
       error = static_cast<quic::QuicErrorCode>(error + 1)) {
    QuicErrorCodeToIetfMapping mapping =
        QuicErrorCodeToTransportErrorCode(error);
    if (mapping.is_transport_close_) {
      EXPECT_EQ(QuicIetfTransportErrorCodeString(mapping.transport_error_code_),
                quiche::QuicheStrCat(
                    "Unknown(",
                    static_cast<uint64_t>(mapping.transport_error_code_), ")"))
          << " " << static_cast<uint64_t>(error) << " "
          << QuicErrorCodeToString(error);
    }
  }
}

}  // namespace
}  // namespace test
}  // namespace quic
