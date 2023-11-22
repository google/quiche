#ifndef QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_MEM_SLICE_IMPL_H_
#define QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_MEM_SLICE_IMPL_H_

#include <cstdlib>
#include <optional>
#include <utility>

#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quiche {

class QUICHE_EXPORT QuicheMemSliceImpl {
 public:
  QuicheMemSliceImpl() = default;

  explicit QuicheMemSliceImpl(QuicheBuffer buffer)
      : buffer_(std::move(buffer)) {}

  QuicheMemSliceImpl(std::unique_ptr<char[]> buffer, size_t length)
      : buffer_(
            QuicheBuffer(QuicheUniqueBufferPtr(
                             buffer.release(),
                             QuicheBufferDeleter(SimpleBufferAllocator::Get())),
                         length)) {}

  QuicheMemSliceImpl(char buffer[], size_t length,
                     quiche::SingleUseCallback<void(const char*)> done_callback)
      : allocator_(std::in_place, std::move(done_callback)),
        buffer_(QuicheBuffer(
            QuicheUniqueBufferPtr(buffer, QuicheBufferDeleter(&*allocator_)),
            length)) {}

  QuicheMemSliceImpl(const QuicheMemSliceImpl& other) = delete;
  QuicheMemSliceImpl& operator=(const QuicheMemSliceImpl& other) = delete;

  // Move constructors. |other| will not hold a reference to the data buffer
  // after this call completes.
  QuicheMemSliceImpl(QuicheMemSliceImpl&& other) = default;
  QuicheMemSliceImpl& operator=(QuicheMemSliceImpl&& other) = default;

  ~QuicheMemSliceImpl() = default;

  void Reset() { buffer_ = QuicheBuffer(); }

  const char* data() const { return buffer_.data(); }
  size_t length() const { return buffer_.size(); }
  bool empty() const { return buffer_.empty(); }

 private:
  // Allocator that is only used for a special `done` callback.
  class LambdaAllocator : public QuicheBufferAllocator {
   public:
    LambdaAllocator(quiche::SingleUseCallback<void(const char*)> done_callback)
        : done_callback_(std::move(done_callback)) {}

    // Noncompliant. Will cause program termination.
    char* New(size_t) override {
      std::exit(-1);
      return nullptr;
    }
    char* New(size_t, bool) override {
      std::exit(-1);
      return nullptr;
    }

    void Delete(char* buffer) override {
      if (done_callback_ != nullptr) {
        std::move(done_callback_)(buffer);
      }
    }

   private:
    quiche::SingleUseCallback<void(const char*)> done_callback_;
  };
  std::optional<LambdaAllocator> allocator_;
  QuicheBuffer buffer_;
};

}  // namespace quiche

#endif  // QUICHE_COMMON_PLATFORM_DEFAULT_QUICHE_PLATFORM_IMPL_QUICHE_MEM_SLICE_IMPL_H_
