// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_object.h"

#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_types.h"
#include "quiche/common/platform/api/quiche_expect_bug.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_mem_slice.h"

namespace moqt {
namespace test {
namespace {

class CachedObjectTest : public quiche::test::QuicheTest {
 public:
  PublishedObjectMetadata DefaultMetadata() {
    PublishedObjectMetadata metadata;
    metadata.location = Location(1, 2);
    metadata.subgroup = 3;
    metadata.status = MoqtObjectStatus::kNormal;
    metadata.publisher_priority = 4;
    metadata.payload_length = 10;
    return metadata;
  }

  std::string Reassemble(const PublishedObject& published) {
    std::string result;
    for (const auto& slice : published.payload) {
      result += std::string(slice.AsStringView());
    }
    return result;
  }
};

TEST_F(CachedObjectTest, Constructor) {
  CachedObject object(DefaultMetadata(), quiche::QuicheMemSlice::Copy("abc"),
                      false);
  PublishedObject published = object.ToPublishedObject();
  EXPECT_EQ(published.metadata.location, Location(1, 2));
  EXPECT_EQ(published.payload.size(), 1);
  EXPECT_EQ(published.payload[0].AsStringView(), "abc");
  EXPECT_FALSE(published.fin_after_this);
}

TEST(PublishedObjectMetadataTest, IsMalformed) {
  PublishedObjectMetadata metadata;
  metadata.location = Location(1, 2);
  metadata.subgroup = 3;
  metadata.status = MoqtObjectStatus::kNormal;
  metadata.publisher_priority = 4;
  metadata.payload_length = 10;

  PublishedObjectMetadata other = metadata;
  EXPECT_FALSE(metadata.IsMalformed(other));

  other.location = Location(1, 3);
  EXPECT_TRUE(metadata.IsMalformed(other));
  other = metadata;

  other.subgroup = 4;
  EXPECT_TRUE(metadata.IsMalformed(other));
  other = metadata;

  other.status = MoqtObjectStatus::kObjectDoesNotExist;
  EXPECT_TRUE(metadata.IsMalformed(other));
  other = metadata;

  other.publisher_priority = 5;
  EXPECT_TRUE(metadata.IsMalformed(other));

  // arrival_time, payload_length, and extensions being different should NOT
  // make it malformed.
  other = metadata;
  other.arrival_time =
      quic::QuicTime::Zero() + quic::QuicTimeDelta::FromSeconds(1);
  EXPECT_FALSE(metadata.IsMalformed(other));
  other.payload_length = 20;
  EXPECT_FALSE(metadata.IsMalformed(other));
  other.extensions = "ext";
  EXPECT_FALSE(metadata.IsMalformed(other));
}

TEST(PublishedObjectMetadataTest, Equality) {
  PublishedObjectMetadata metadata;
  metadata.location = Location(1, 2);
  metadata.subgroup = 3;
  metadata.status = MoqtObjectStatus::kNormal;
  metadata.publisher_priority = 4;
  metadata.payload_length = 10;
  metadata.extensions = "ext";
  metadata.arrival_time =
      quic::QuicTime::Zero() + quic::QuicTimeDelta::FromSeconds(1);

  PublishedObjectMetadata other = metadata;
  EXPECT_EQ(metadata, other);

  other.location = Location(1, 3);
  EXPECT_NE(metadata, other);
  other = metadata;

  other.subgroup = 4;
  EXPECT_NE(metadata, other);
  other = metadata;

  other.status = MoqtObjectStatus::kObjectDoesNotExist;
  EXPECT_NE(metadata, other);
  other = metadata;

  other.publisher_priority = 5;
  EXPECT_NE(metadata, other);
  other = metadata;

  other.payload_length = 20;
  EXPECT_NE(metadata, other);
  other = metadata;

  other.extensions = "something else";
  EXPECT_NE(metadata, other);
  other = metadata;

  other.arrival_time =
      quic::QuicTime::Zero() + quic::QuicTimeDelta::FromSeconds(2);
  EXPECT_NE(metadata, other);
}

TEST_F(CachedObjectTest, SetFinAfterThis) {
  CachedObject object(DefaultMetadata(), quiche::QuicheMemSlice::Copy("abc"),
                      false);
  EXPECT_FALSE(object.fin_after_this());
  object.set_fin_after_this(true);
  EXPECT_TRUE(object.fin_after_this());
}

TEST_F(CachedObjectTest, Append) {
  PublishedObjectMetadata metadata = DefaultMetadata();
  metadata.payload_length = 10;
  CachedObject object(metadata, quiche::QuicheMemSlice::Copy("abc"), false);

  // Success: append at the end.
  EXPECT_TRUE(object.Append(3, "def"));

  // Success: partial overlap, should append remaining.
  EXPECT_TRUE(object.Append(5, "fghi"));  // length 4. 5+4 = 9.

  // Failure: gap.
  EXPECT_QUICHE_BUG(object.Append(10, "k"),
                    "Gap in bytes in CachedObject::Append");

  // Failure: beyond payload_length.
  EXPECT_QUICHE_BUG(
      object.Append(9, "abc"),
      "Object is larger than the declared size");  // 9+3 = 12 > 10.

  // Failure: already received.
  EXPECT_FALSE(object.Append(0, "abc"));

  PublishedObject published = object.ToPublishedObject();
  std::string full_payload;
  for (const auto& slice : published.payload) {
    full_payload += std::string(slice.AsStringView());
  }
  EXPECT_EQ(full_payload, "abcdefghi");
}

TEST_F(CachedObjectTest, GetPayload) {
  PublishedObjectMetadata metadata = DefaultMetadata();
  // We have to use large object fragments to avoid absl::Cord optimizing them
  // into a single slice.
  const size_t kBlockSize = 1000;
  metadata.payload_length = kBlockSize * 3;
  std::string object_data(metadata.payload_length, 'a');
  absl::string_view payload = absl::string_view(object_data);
  CachedObject object(
      metadata, quiche::QuicheMemSlice::Copy(payload.substr(0, kBlockSize)),
      false);
  object.Append(kBlockSize, payload.substr(kBlockSize, kBlockSize));
  object.Append(2 * kBlockSize, payload.substr(2 * kBlockSize, kBlockSize));

  // Offset 0: get full payload.
  std::string received = Reassemble(object.ToPublishedObject(0));
  EXPECT_EQ(received, payload);
  // Offset at slice boundary.
  received = Reassemble(object.ToPublishedObject(kBlockSize));
  EXPECT_EQ(received, payload.substr(kBlockSize));
  // Offset in the middle of a slice.
  received = Reassemble(object.ToPublishedObject(kBlockSize + 1));
  EXPECT_EQ(received, payload.substr(kBlockSize + 1));
  // Offset beyond the last slice but within payload_length.
  received = Reassemble(object.ToPublishedObject(3 * kBlockSize));
  EXPECT_EQ(received, "");
  // Offset way beyond.
  received = Reassemble(object.ToPublishedObject(4 * kBlockSize));
  EXPECT_EQ(object.payload_received(), 3 * kBlockSize);
}

TEST_F(CachedObjectTest, ToPublishedObjectReferenceCounting) {
  CachedObject object(DefaultMetadata(), quiche::QuicheMemSlice::Copy("abc"),
                      false);
  PublishedObject published = object.ToPublishedObject();
  EXPECT_EQ(published.payload[0].AsStringView(), "abc");

  // Even if we append more, the old published object's slices should remain
  // valid.
  object.Append(3, "def");
  EXPECT_EQ(published.payload[0].AsStringView(), "abc");
  EXPECT_EQ(published.payload.size(), 1);
}

TEST_F(CachedObjectTest, OverlapIsEqual) {
  PublishedObjectMetadata metadata = DefaultMetadata();
  metadata.payload_length = 20;
  CachedObject object(metadata, quiche::QuicheMemSlice::Copy("abcdefghij"),
                      false);
  // payload_ covers [0, 10).

  // No overlap.
  EXPECT_TRUE(object.OverlapIsEqual(10, "klm"));
  EXPECT_TRUE(object.OverlapIsEqual(15, "xyz"));

  // Exact match.
  EXPECT_TRUE(object.OverlapIsEqual(0, "abcdefghij"));
  EXPECT_TRUE(object.OverlapIsEqual(5, "fghij"));

  // Partial overlap, matches.
  EXPECT_TRUE(object.OverlapIsEqual(0, "abcde"));
  EXPECT_TRUE(object.OverlapIsEqual(8, "ijmnop"));  // Overlap is "ij", matches.

  // Partial overlap, mismatch.
  EXPECT_FALSE(object.OverlapIsEqual(0, "axcde"));
  EXPECT_FALSE(
      object.OverlapIsEqual(8, "ixmnop"));  // Overlap is "ij" vs "ix", mismatch

  // Overlap beyond end of payload_, matches.
  EXPECT_TRUE(
      object.OverlapIsEqual(5, "fghijXXXXX"));  // Overlap is "fghij", matches.

  // Empty payload argument.
  EXPECT_TRUE(object.OverlapIsEqual(5, ""));
}

TEST_F(CachedObjectTest, OverlapIsEqualMultiSlice) {
  PublishedObjectMetadata metadata = DefaultMetadata();
  metadata.payload_length = 20;
  CachedObject object(metadata, quiche::QuicheMemSlice::Copy("abc"), false);
  object.Append(3, "def");
  object.Append(6, "ghi");

  // Overlap across two slices: "bcde" (indices 1 to 5)
  EXPECT_TRUE(object.OverlapIsEqual(1, "bcde"));
  EXPECT_FALSE(object.OverlapIsEqual(1, "bcxe"));

  // Overlap across three slices: "bcdefgh"
  EXPECT_TRUE(object.OverlapIsEqual(1, "bcdefgh"));
  EXPECT_FALSE(object.OverlapIsEqual(1, "bcdefgx"));

  // Overlap starting exactly at boundary
  EXPECT_TRUE(object.OverlapIsEqual(3, "defg"));
}

}  // namespace
}  // namespace test
}  // namespace moqt
