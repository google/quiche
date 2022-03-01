#ifndef QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_MEM_SLICE_IMPL_H_
#define QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_MEM_SLICE_IMPL_H_

#include "quic/core/quic_buffer_allocator.h"
#include "quic/core/quic_simple_buffer_allocator.h"
#include "common/platform/api/quiche_export.h"

namespace quiche {

class QUICHE_EXPORT_PRIVATE QuicheMemSliceImpl {
 public:
  QuicheMemSliceImpl() = default;

  explicit QuicheMemSliceImpl(quic::QuicBuffer buffer)
      : buffer_(std::move(buffer)) {}

  QuicheMemSliceImpl(std::unique_ptr<char[]> buffer, size_t length)
      : buffer_(quic::QuicBuffer(
            quic::QuicUniqueBufferPtr(
                buffer.release(),
                quic::QuicBufferDeleter(quic::SimpleBufferAllocator::Get())),
            length)) {}

  QuicheMemSliceImpl(const QuicheMemSliceImpl& other) = delete;
  QuicheMemSliceImpl& operator=(const QuicheMemSliceImpl& other) = delete;

  // Move constructors. |other| will not hold a reference to the data buffer
  // after this call completes.
  QuicheMemSliceImpl(QuicheMemSliceImpl&& other) = default;
  QuicheMemSliceImpl& operator=(QuicheMemSliceImpl&& other) = default;

  ~QuicheMemSliceImpl() = default;

  void Reset() { buffer_ = quic::QuicBuffer(); }

  const char* data() const { return buffer_.data(); }
  size_t length() const { return buffer_.size(); }
  bool empty() const { return buffer_.empty(); }

 private:
  quic::QuicBuffer buffer_;
};

}  // namespace quiche

#endif  // QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_MEM_SLICE_IMPL_H_
