#include "net/third_party/quiche/src/spdy/core/spdy_header_storage.h"

#include "net/third_party/quiche/src/spdy/platform/api/spdy_logging.h"

namespace spdy {
namespace {

// SpdyHeaderStorage allocates blocks of this size by default.
const size_t kDefaultStorageBlockSize = 2048;

}  // namespace

SpdyHeaderStorage::SpdyHeaderStorage() : arena_(kDefaultStorageBlockSize) {}

SpdyStringPiece SpdyHeaderStorage::Write(const SpdyStringPiece s) {
  return SpdyStringPiece(arena_.Memdup(s.data(), s.size()), s.size());
}

void SpdyHeaderStorage::Rewind(const SpdyStringPiece s) {
  arena_.Free(const_cast<char*>(s.data()), s.size());
}

SpdyStringPiece SpdyHeaderStorage::WriteFragments(
    const std::vector<SpdyStringPiece>& fragments,
    SpdyStringPiece separator) {
  if (fragments.empty()) {
    return SpdyStringPiece();
  }
  size_t total_size = separator.size() * (fragments.size() - 1);
  for (const auto fragment : fragments) {
    total_size += fragment.size();
  }
  char* dst = arena_.Alloc(total_size);
  size_t written = Join(dst, fragments, separator);
  DCHECK_EQ(written, total_size);
  return SpdyStringPiece(dst, total_size);
}

size_t Join(char* dst,
            const std::vector<SpdyStringPiece>& fragments,
            SpdyStringPiece separator) {
  if (fragments.empty()) {
    return 0;
  }
  auto* original_dst = dst;
  auto it = fragments.begin();
  memcpy(dst, it->data(), it->size());
  dst += it->size();
  for (++it; it != fragments.end(); ++it) {
    memcpy(dst, separator.data(), separator.size());
    dst += separator.size();
    memcpy(dst, it->data(), it->size());
    dst += it->size();
  }
  return dst - original_dst;
}

}  // namespace spdy
