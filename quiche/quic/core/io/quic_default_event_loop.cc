// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/quic_default_event_loop.h"

#include <memory>

#include "quiche/quic/core/io/quic_poll_event_loop.h"
#include "quiche/common/platform/api/quiche_event_loop.h"

namespace quic {

QuicEventLoopFactory* GetDefaultEventLoop() {
  if (QuicEventLoopFactory* factory =
          quiche::GetOverrideForDefaultEventLoop()) {
    return factory;
  }
  return QuicPollEventLoopFactory::Get();
}

std::vector<QuicEventLoopFactory*> GetAllSupportedEventLoops() {
  std::vector<QuicEventLoopFactory*> loops = {QuicPollEventLoopFactory::Get()};
  std::vector<QuicEventLoopFactory*> extra =
      quiche::GetExtraEventLoopImplementations();
  loops.insert(loops.end(), extra.begin(), extra.end());
  return loops;
}

}  // namespace quic
