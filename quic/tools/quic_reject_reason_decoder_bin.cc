// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Decodes the packet HandshakeFailureReason from the chromium histogram
// Net.QuicClientHelloRejectReasons

#include <iostream>

#include "base/commandlineflags.h"
#include "base/init_google.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_handshake.h"
#include "net/third_party/quiche/src/quic/core/crypto/crypto_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_text_utils.h"

using quic::CryptoUtils;
using quic::HandshakeFailureReason;
using quic::MAX_FAILURE_REASON;
using std::cerr;
using std::cout;

int main(int argc, char* argv[]) {
  InitGoogle(argv[0], &argc, &argv, true);

  if (argc != 2) {
    std::cerr << "Missing argument (Usage: " << argv[0] << " <packed_reason>\n";
    return 1;
  }

  uint32_t packed_error = 0;
  if (!quic::QuicTextUtils::StringToUint32(argv[1], &packed_error)) {
    std::cerr << "Unable to parse: " << argv[1] << "\n";
    return 2;
  }

  for (int i = 1; i < MAX_FAILURE_REASON; ++i) {
    if ((packed_error & (1 << (i - 1))) == 0) {
      continue;
    }
    HandshakeFailureReason reason = static_cast<HandshakeFailureReason>(i);
    std::cout << CryptoUtils::HandshakeFailureReasonToString(reason) << "\n";
  }
  return 0;
}
