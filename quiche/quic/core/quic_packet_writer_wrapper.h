// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_QUIC_PACKET_WRITER_WRAPPER_H_
#define QUICHE_QUIC_CORE_QUIC_PACKET_WRITER_WRAPPER_H_

#include <cstddef>
#include <memory>
#include <utility>

#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/common/quiche_callbacks.h"

namespace quic {

// Wraps a writer object to allow dynamically extending functionality. Use
// cases: replace writer while dispatcher and connections hold on to the
// wrapper; mix in monitoring; mix in mocks in unit tests.
class QUICHE_EXPORT QuicPacketWriterWrapper : public QuicPacketWriter {
 public:
  QuicPacketWriterWrapper();
  QuicPacketWriterWrapper(const QuicPacketWriterWrapper&) = delete;
  QuicPacketWriterWrapper& operator=(const QuicPacketWriterWrapper&) = delete;
  ~QuicPacketWriterWrapper() override;

  // Default implementation of the QuicPacketWriter interface. Passes everything
  // to |writer_|.
  WriteResult WritePacket(const char* buffer, size_t buf_len,
                          const QuicIpAddress& self_address,
                          const QuicSocketAddress& peer_address,
                          PerPacketOptions* options,
                          const QuicPacketWriterParams& params) override;
  bool IsWriteBlocked() const override;
  void SetWritable() override;
  std::optional<int> MessageTooBigErrorCode() const override;
  QuicByteCount GetMaxPacketSize(
      const QuicSocketAddress& peer_address) const override;
  bool SupportsReleaseTime() const override;
  bool IsBatchMode() const override;
  bool SupportsEcn() const override { return writer_->SupportsEcn(); }
  QuicPacketBuffer GetNextWriteLocation(
      const QuicIpAddress& self_address,
      const QuicSocketAddress& peer_address) override;
  WriteResult Flush() override;

  // Takes ownership of |writer|.
  void set_writer(QuicPacketWriter* writer);

  // Does not take ownership of |writer|.
  void set_non_owning_writer(QuicPacketWriter* writer);

  virtual void set_peer_address(const QuicSocketAddress& /*peer_address*/) {}

  QuicPacketWriter* writer() { return writer_; }

  // First argument is the packet size. Second argument is the result of the
  // write.
  using OnWriteDoneCallback =
      quiche::MultiUseCallback<void(size_t, const WriteResult&)>;

  // If set, |on_write_done| will be called after each write.
  void set_on_write_done(OnWriteDoneCallback on_write_done) {
    on_write_done_ = std::move(on_write_done);
  }

 private:
  void unset_writer();

  QuicPacketWriter* writer_ = nullptr;
  bool owns_writer_ = false;
  // If not null, called after each write.
  OnWriteDoneCallback on_write_done_;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QUIC_PACKET_WRITER_WRAPPER_H_
