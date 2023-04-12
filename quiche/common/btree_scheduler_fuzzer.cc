// Copyright 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/btree_scheduler.h"
#include "quiche/common/quiche_data_reader.h"

namespace {
uint8_t ReadUint8(quiche::QuicheDataReader& reader) {
  uint8_t result;
  if (!reader.ReadUInt8(&result)) {
    exit(0);
  }
  return result;
}
}  // namespace

// Simple fuzzer that attempts to drive the scheduler into an invalid state that
// would cause a QUICHE_BUG or a crash.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data_ptr, size_t size) {
  quiche::BTreeScheduler<uint8_t, uint8_t> scheduler;
  quiche::QuicheDataReader reader(reinterpret_cast<const char*>(data_ptr),
                                  size);
  while (!reader.IsDoneReading()) {
    switch (ReadUint8(reader)) {
      case 0:
        (void)scheduler.Register(ReadUint8(reader), ReadUint8(reader));
        break;
      case 1:
        (void)scheduler.Unregister(ReadUint8(reader));
        break;
      case 2:
        (void)scheduler.UpdatePriority(ReadUint8(reader), ReadUint8(reader));
        break;
      case 3:
        (void)scheduler.Schedule(ReadUint8(reader));
        break;
      case 4:
        (void)scheduler.PopFront();
        break;
      default:
        return 0;
    }
  }
  return 0;
}
