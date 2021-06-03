// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/quic_simple_buffer_allocator.h"

#include "quic/core/quic_packets.h"
#include "quic/platform/api/quic_test.h"

namespace quic {
namespace {

class SimpleBufferAllocatorTest : public QuicTest {};

TEST_F(SimpleBufferAllocatorTest, NewDelete) {
  SimpleBufferAllocator alloc;
  char* buf = alloc.New(4);
  EXPECT_NE(nullptr, buf);
  alloc.Delete(buf);
}

TEST_F(SimpleBufferAllocatorTest, DeleteNull) {
  SimpleBufferAllocator alloc;
  alloc.Delete(nullptr);
}

TEST_F(SimpleBufferAllocatorTest, MoveBuffersConstructor) {
  SimpleBufferAllocator alloc;
  QuicBuffer buffer1(&alloc, 16);

  EXPECT_NE(buffer1.data(), nullptr);
  EXPECT_EQ(buffer1.size(), 16u);

  QuicBuffer buffer2(std::move(buffer1));
  EXPECT_EQ(buffer1.data(), nullptr);  // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(buffer1.size(), 0u);
  EXPECT_NE(buffer2.data(), nullptr);
  EXPECT_EQ(buffer2.size(), 16u);
}

TEST_F(SimpleBufferAllocatorTest, MoveBuffersAssignment) {
  SimpleBufferAllocator alloc;
  QuicBuffer buffer1(&alloc, 16);
  QuicBuffer buffer2;

  EXPECT_NE(buffer1.data(), nullptr);
  EXPECT_EQ(buffer1.size(), 16u);
  EXPECT_EQ(buffer2.data(), nullptr);
  EXPECT_EQ(buffer2.size(), 0u);

  buffer2 = std::move(buffer1);
  EXPECT_EQ(buffer1.data(), nullptr);  // NOLINT(bugprone-use-after-move)
  EXPECT_EQ(buffer1.size(), 0u);
  EXPECT_NE(buffer2.data(), nullptr);
  EXPECT_EQ(buffer2.size(), 16u);
}

TEST_F(SimpleBufferAllocatorTest, CopyBuffer) {
  SimpleBufferAllocator alloc;
  const absl::string_view original = "Test string";
  QuicBuffer copy = QuicBuffer::Copy(&alloc, original);
  EXPECT_EQ(copy.AsStringView(), original);
}

}  // namespace
}  // namespace quic
