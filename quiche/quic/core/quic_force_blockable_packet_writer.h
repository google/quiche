// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_FORCE_BLOCKABLE_PACKET_WRITER_H_
#define QUICHE_QUIC_CORE_QUIC_FORCE_BLOCKABLE_PACKET_WRITER_H_

#include "quiche/quic/core/quic_packet_writer.h"

namespace quic {

// A extended interface of QuicPacketWriter that can be forced to be write
// blocked.
class QUICHE_EXPORT QuicForceBlockablePacketWriter : public QuicPacketWriter {
 public:
  // If `enforce_write_block` is true, IsWriteBlocked() will always return true
  // regardless of whether SetWritable() is called or not until
  // this method is called again with |enforce_write_block| false.
  // If |enforce_write_block| is false, SetWritable() may still be needed to
  // make IsWriteBlocked() to return true.
  virtual void ForceWriteBlocked(bool enforce_write_block) = 0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_FORCE_BLOCKABLE_PACKET_WRITER_H_
