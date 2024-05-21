// Copyright 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/common/platform/api/quiche_mem_slice.h"

#include <cstring>
#include <memory>
#include <utility>

#include "absl/strings/string_view.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace quiche {
namespace test {
namespace {

class QuicheMemSliceTest : public QuicheTest {
 public:
  QuicheMemSliceTest() {
    size_t length = 1024;
    slice_ = QuicheMemSlice(QuicheBuffer(&allocator_, length));
    orig_data_ = slice_.data();
    orig_length_ = slice_.length();
  }

  SimpleBufferAllocator allocator_;
  QuicheMemSlice slice_;
  const char* orig_data_;
  size_t orig_length_;
};

TEST_F(QuicheMemSliceTest, MoveConstruct) {
  QuicheMemSlice moved(std::move(slice_));
  EXPECT_EQ(moved.data(), orig_data_);
  EXPECT_EQ(moved.length(), orig_length_);
  EXPECT_EQ(nullptr, slice_.data());
  EXPECT_EQ(0u, slice_.length());
  EXPECT_TRUE(slice_.empty());
}

TEST_F(QuicheMemSliceTest, MoveAssign) {
  QuicheMemSlice moved;
  moved = std::move(slice_);
  EXPECT_EQ(moved.data(), orig_data_);
  EXPECT_EQ(moved.length(), orig_length_);
  EXPECT_EQ(nullptr, slice_.data());
  EXPECT_EQ(0u, slice_.length());
  EXPECT_TRUE(slice_.empty());
}

TEST_F(QuicheMemSliceTest, MoveAssignNonEmpty) {
  const absl::string_view data("foo");
  auto buffer = std::make_unique<char[]>(data.length());
  std::memcpy(buffer.get(), data.data(), data.length());

  QuicheMemSlice moved(std::move(buffer), data.length());
  EXPECT_EQ(data, moved.AsStringView());

  moved = std::move(slice_);
  EXPECT_EQ(moved.data(), orig_data_);
  EXPECT_EQ(moved.length(), orig_length_);
  EXPECT_EQ(nullptr, slice_.data());
  EXPECT_EQ(0u, slice_.length());
  EXPECT_TRUE(slice_.empty());
}

TEST_F(QuicheMemSliceTest, SliceCustomDoneCallback) {
  const absl::string_view data("foo");
  bool deleted = false;

  char* buffer = new char[data.length()];
  std::memcpy(buffer, data.data(), data.length());

  {
    QuicheMemSlice slice(buffer, data.length(), [&deleted](const char* data) {
      deleted = true;
      delete[] data;
    });
    EXPECT_EQ(data, slice.AsStringView());
  }
  EXPECT_TRUE(deleted);
}

TEST_F(QuicheMemSliceTest, Reset) {
  EXPECT_EQ(slice_.data(), orig_data_);
  EXPECT_EQ(slice_.length(), orig_length_);
  EXPECT_FALSE(slice_.empty());

  slice_.Reset();

  EXPECT_EQ(slice_.length(), 0u);
  EXPECT_TRUE(slice_.empty());
}

TEST_F(QuicheMemSliceTest, SliceAllocatedOnHeap) {
  auto buffer = std::make_unique<char[]>(128);
  char* orig_data = buffer.get();
  size_t used_length = 105;
  QuicheMemSlice slice = QuicheMemSlice(std::move(buffer), used_length);
  QuicheMemSlice moved = std::move(slice);
  EXPECT_EQ(moved.data(), orig_data);
  EXPECT_EQ(moved.length(), used_length);
}

TEST_F(QuicheMemSliceTest, SliceFromBuffer) {
  const absl::string_view kTestString =
      "RFC 9000 Release Celebration Memorial Test String";
  auto buffer = QuicheBuffer::Copy(&allocator_, kTestString);
  QuicheMemSlice slice(std::move(buffer));

  EXPECT_EQ(buffer.data(), nullptr);  // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(buffer.size(), 0u);
  EXPECT_EQ(slice.AsStringView(), kTestString);
  EXPECT_EQ(slice.length(), kTestString.length());
}

}  // namespace
}  // namespace test
}  // namespace quiche
