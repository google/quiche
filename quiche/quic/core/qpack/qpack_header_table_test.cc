// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/qpack/qpack_header_table.h"

#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/qpack/qpack_static_table.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/spdy/core/hpack/hpack_entry.h"

using ::testing::Mock;
using ::testing::StrictMock;

namespace quic {
namespace test {
namespace {

const uint64_t kMaximumDynamicTableCapacityForTesting = 1024 * 1024;

template <typename T>
class QpackHeaderTableTest : public QuicTest {
 protected:
  ~QpackHeaderTableTest() override = default;

  void SetUp() override {
    ASSERT_TRUE(table_.SetMaximumDynamicTableCapacity(
        kMaximumDynamicTableCapacityForTesting));
    ASSERT_TRUE(
        table_.SetDynamicTableCapacity(kMaximumDynamicTableCapacityForTesting));
  }

  bool EntryFitsDynamicTableCapacity(absl::string_view name,
                                     absl::string_view value) const {
    return table_.EntryFitsDynamicTableCapacity(name, value);
  }

  void InsertEntry(absl::string_view name, absl::string_view value) {
    table_.InsertEntry(name, value);
  }

  bool SetDynamicTableCapacity(uint64_t capacity) {
    return table_.SetDynamicTableCapacity(capacity);
  }

  uint64_t max_entries() const { return table_.max_entries(); }
  uint64_t inserted_entry_count() const {
    return table_.inserted_entry_count();
  }
  uint64_t dropped_entry_count() const { return table_.dropped_entry_count(); }

  T table_;
};

using MyTypes =
    ::testing::Types<QpackEncoderHeaderTable, QpackDecoderHeaderTable>;
TYPED_TEST_SUITE(QpackHeaderTableTest, MyTypes);

// MaxEntries is determined by maximum dynamic table capacity,
// which is set at construction time.
TYPED_TEST(QpackHeaderTableTest, MaxEntries) {
  TypeParam table1;
  table1.SetMaximumDynamicTableCapacity(1024);
  EXPECT_EQ(32u, table1.max_entries());

  TypeParam table2;
  table2.SetMaximumDynamicTableCapacity(500);
  EXPECT_EQ(15u, table2.max_entries());
}

TYPED_TEST(QpackHeaderTableTest, SetDynamicTableCapacity) {
  // Dynamic table capacity does not affect MaxEntries.
  EXPECT_TRUE(this->SetDynamicTableCapacity(1024));
  EXPECT_EQ(32u * 1024, this->max_entries());

  EXPECT_TRUE(this->SetDynamicTableCapacity(500));
  EXPECT_EQ(32u * 1024, this->max_entries());

  // Dynamic table capacity cannot exceed maximum dynamic table capacity.
  EXPECT_FALSE(this->SetDynamicTableCapacity(
      2 * kMaximumDynamicTableCapacityForTesting));
}

TYPED_TEST(QpackHeaderTableTest, EntryFitsDynamicTableCapacity) {
  EXPECT_TRUE(this->SetDynamicTableCapacity(39));

  EXPECT_TRUE(this->EntryFitsDynamicTableCapacity("foo", "bar"));
  EXPECT_TRUE(this->EntryFitsDynamicTableCapacity("foo", "bar2"));
  EXPECT_FALSE(this->EntryFitsDynamicTableCapacity("foo", "bar12"));
}

class QpackEncoderHeaderTableTest
    : public QpackHeaderTableTest<QpackEncoderHeaderTable> {
 protected:
  ~QpackEncoderHeaderTableTest() override = default;

  void ExpectMatch(absl::string_view name, absl::string_view value,
                   QpackEncoderHeaderTable::MatchType expected_match_type,
                   bool expected_is_static, uint64_t expected_index) const {
    // Initialize outparams to a value different from the expected to ensure
    // that FindHeaderField() sets them.
    bool is_static = !expected_is_static;
    uint64_t index = expected_index + 1;

    QpackEncoderHeaderTable::MatchType matchtype =
        table_.FindHeaderField(name, value, &is_static, &index);

    EXPECT_EQ(expected_match_type, matchtype) << name << ": " << value;
    EXPECT_EQ(expected_is_static, is_static) << name << ": " << value;
    EXPECT_EQ(expected_index, index) << name << ": " << value;
  }

  void ExpectNoMatch(absl::string_view name, absl::string_view value) const {
    bool is_static = false;
    uint64_t index = 0;

    QpackEncoderHeaderTable::MatchType matchtype =
        table_.FindHeaderField(name, value, &is_static, &index);

    EXPECT_EQ(QpackEncoderHeaderTable::MatchType::kNoMatch, matchtype)
        << name << ": " << value;
  }

  uint64_t MaxInsertSizeWithoutEvictingGivenEntry(uint64_t index) const {
    return table_.MaxInsertSizeWithoutEvictingGivenEntry(index);
  }

  uint64_t draining_index(float draining_fraction) const {
    return table_.draining_index(draining_fraction);
  }
};

TEST_F(QpackEncoderHeaderTableTest, FindStaticHeaderField) {
  // A header name that has multiple entries with different values.
  ExpectMatch(":method", "GET",
              QpackEncoderHeaderTable::MatchType::kNameAndValue, true, 17u);

  ExpectMatch(":method", "POST",
              QpackEncoderHeaderTable::MatchType::kNameAndValue, true, 20u);

  ExpectMatch(":method", "TRACE", QpackEncoderHeaderTable::MatchType::kName,
              true, 15u);

  // A header name that has a single entry with non-empty value.
  ExpectMatch("accept-encoding", "gzip, deflate, br",
              QpackEncoderHeaderTable::MatchType::kNameAndValue, true, 31u);

  ExpectMatch("accept-encoding", "compress",
              QpackEncoderHeaderTable::MatchType::kName, true, 31u);

  ExpectMatch("accept-encoding", "", QpackEncoderHeaderTable::MatchType::kName,
              true, 31u);

  // A header name that has a single entry with empty value.
  ExpectMatch("location", "", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              true, 12u);

  ExpectMatch("location", "foo", QpackEncoderHeaderTable::MatchType::kName,
              true, 12u);

  // No matching header name.
  ExpectNoMatch("foo", "");
  ExpectNoMatch("foo", "bar");
}

TEST_F(QpackEncoderHeaderTableTest, FindDynamicHeaderField) {
  // Dynamic table is initially entry.
  ExpectNoMatch("foo", "bar");
  ExpectNoMatch("foo", "baz");

  // Insert one entry.
  InsertEntry("foo", "bar");

  // Match name and value.
  ExpectMatch("foo", "bar", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              false, 0u);

  // Match name only.
  ExpectMatch("foo", "baz", QpackEncoderHeaderTable::MatchType::kName, false,
              0u);

  // Insert an identical entry.  FindHeaderField() should return the index of
  // the most recently inserted matching entry.
  InsertEntry("foo", "bar");

  // Match name and value.
  ExpectMatch("foo", "bar", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              false, 1u);

  // Match name only.
  ExpectMatch("foo", "baz", QpackEncoderHeaderTable::MatchType::kName, false,
              1u);
}

TEST_F(QpackEncoderHeaderTableTest, FindHeaderFieldPrefersStaticTable) {
  // Insert an entry to the dynamic table that exists in the static table.
  InsertEntry(":method", "GET");

  // FindHeaderField() prefers static table if both have name-and-value match.
  ExpectMatch(":method", "GET",
              QpackEncoderHeaderTable::MatchType::kNameAndValue, true, 17u);

  // FindHeaderField() prefers static table if both have name match but no value
  // match, and prefers the first entry with matching name.
  ExpectMatch(":method", "TRACE", QpackEncoderHeaderTable::MatchType::kName,
              true, 15u);

  // Add new entry to the dynamic table.
  InsertEntry(":method", "TRACE");

  // FindHeaderField prefers name-and-value match in dynamic table over name
  // only match in static table.
  ExpectMatch(":method", "TRACE",
              QpackEncoderHeaderTable::MatchType::kNameAndValue, false, 1u);
}

TEST_F(QpackEncoderHeaderTableTest, EvictByInsertion) {
  EXPECT_TRUE(SetDynamicTableCapacity(40));

  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  EXPECT_EQ(1u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectMatch("foo", "bar", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 0u);

  // Inserting second entry evicts the first one.
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoMatch("foo", "bar");
  ExpectMatch("baz", "qux", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 1u);
}

TEST_F(QpackEncoderHeaderTableTest, EvictByUpdateTableSize) {
  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectMatch("foo", "bar", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 0u);
  ExpectMatch("baz", "qux", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 1u);

  EXPECT_TRUE(SetDynamicTableCapacity(40));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoMatch("foo", "bar");
  ExpectMatch("baz", "qux", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 1u);

  EXPECT_TRUE(SetDynamicTableCapacity(20));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(2u, dropped_entry_count());

  ExpectNoMatch("foo", "bar");
  ExpectNoMatch("baz", "qux");
}

TEST_F(QpackEncoderHeaderTableTest, EvictOldestOfIdentical) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert same entry twice.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  // Find most recently inserted entry.
  ExpectMatch("foo", "bar", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 1u);

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectMatch("foo", "bar", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 1u);
  ExpectMatch("baz", "qux", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 2u);
}

TEST_F(QpackEncoderHeaderTableTest, EvictOldestOfSameName) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert two entries with same name but different values.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "baz");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  // Find most recently inserted entry with matching name.
  ExpectMatch("foo", "foo", QpackEncoderHeaderTable::MatchType::kName,
              /* expected_is_static = */ false, 1u);

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectMatch("foo", "foo", QpackEncoderHeaderTable::MatchType::kName,
              /* expected_is_static = */ false, 1u);
  ExpectMatch("baz", "qux", QpackEncoderHeaderTable::MatchType::kNameAndValue,
              /* expected_is_static = */ false, 2u);
}

// Returns the size of the largest entry that could be inserted into the
// dynamic table without evicting entry |index|.
TEST_F(QpackEncoderHeaderTableTest, MaxInsertSizeWithoutEvictingGivenEntry) {
  const uint64_t dynamic_table_capacity = 100;
  EXPECT_TRUE(SetDynamicTableCapacity(dynamic_table_capacity));

  // Empty table can take an entry up to its capacity.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(0));

  const uint64_t entry_size1 = QpackEntry::Size("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(dynamic_table_capacity - entry_size1,
            MaxInsertSizeWithoutEvictingGivenEntry(0));
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(1));

  const uint64_t entry_size2 = QpackEntry::Size("baz", "foobar");
  InsertEntry("baz", "foobar");
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(2));
  // Second entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size2,
            MaxInsertSizeWithoutEvictingGivenEntry(1));
  // First and second entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size2 - entry_size1,
            MaxInsertSizeWithoutEvictingGivenEntry(0));

  // Third entry evicts first one.
  const uint64_t entry_size3 = QpackEntry::Size("last", "entry");
  InsertEntry("last", "entry");
  EXPECT_EQ(1u, dropped_entry_count());
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity, MaxInsertSizeWithoutEvictingGivenEntry(3));
  // Third entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size3,
            MaxInsertSizeWithoutEvictingGivenEntry(2));
  // Second and third entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size3 - entry_size2,
            MaxInsertSizeWithoutEvictingGivenEntry(1));
}

TEST_F(QpackEncoderHeaderTableTest, DrainingIndex) {
  EXPECT_TRUE(SetDynamicTableCapacity(4 * QpackEntry::Size("foo", "bar")));

  // Empty table: no draining entry.
  EXPECT_EQ(0u, draining_index(0.0));
  EXPECT_EQ(0u, draining_index(1.0));

  // Table with one entry.
  InsertEntry("foo", "bar");
  // Any entry can be referenced if none of the table is draining.
  EXPECT_EQ(0u, draining_index(0.0));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(1u, draining_index(1.0));

  // Table with two entries is at half capacity.
  InsertEntry("foo", "bar");
  // Any entry can be referenced if at most half of the table is draining,
  // because current entries only take up half of total capacity.
  EXPECT_EQ(0u, draining_index(0.0));
  EXPECT_EQ(0u, draining_index(0.5));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(2u, draining_index(1.0));

  // Table with four entries is full.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  // Any entry can be referenced if none of the table is draining.
  EXPECT_EQ(0u, draining_index(0.0));
  // In a full table with identically sized entries, |draining_fraction| of all
  // entries are draining.
  EXPECT_EQ(2u, draining_index(0.5));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(4u, draining_index(1.0));
}

class MockObserver : public QpackDecoderHeaderTable::Observer {
 public:
  ~MockObserver() override = default;

  MOCK_METHOD(void, OnInsertCountReachedThreshold, (), (override));
  MOCK_METHOD(void, Cancel, (), (override));
};

class QpackDecoderHeaderTableTest
    : public QpackHeaderTableTest<QpackDecoderHeaderTable> {
 protected:
  ~QpackDecoderHeaderTableTest() override = default;

  void ExpectEntryAtIndex(bool is_static, uint64_t index,
                          absl::string_view expected_name,
                          absl::string_view expected_value) const {
    const auto* entry = table_.LookupEntry(is_static, index);
    ASSERT_TRUE(entry);
    EXPECT_EQ(expected_name, entry->name());
    EXPECT_EQ(expected_value, entry->value());
  }

  void ExpectNoEntryAtIndex(bool is_static, uint64_t index) const {
    EXPECT_FALSE(table_.LookupEntry(is_static, index));
  }

  void RegisterObserver(uint64_t required_insert_count,
                        QpackDecoderHeaderTable::Observer* observer) {
    table_.RegisterObserver(required_insert_count, observer);
  }

  void UnregisterObserver(uint64_t required_insert_count,
                          QpackDecoderHeaderTable::Observer* observer) {
    table_.UnregisterObserver(required_insert_count, observer);
  }
};

TEST_F(QpackDecoderHeaderTableTest, LookupStaticEntry) {
  ExpectEntryAtIndex(/* is_static = */ true, 0, ":authority", "");

  ExpectEntryAtIndex(/* is_static = */ true, 1, ":path", "/");

  // 98 is the last entry.
  ExpectEntryAtIndex(/* is_static = */ true, 98, "x-frame-options",
                     "sameorigin");

  ASSERT_EQ(99u, QpackStaticTableVector().size());
  ExpectNoEntryAtIndex(/* is_static = */ true, 99);
}

TEST_F(QpackDecoderHeaderTableTest, InsertAndLookupDynamicEntry) {
  // Dynamic table is initially entry.
  ExpectNoEntryAtIndex(/* is_static = */ false, 0);
  ExpectNoEntryAtIndex(/* is_static = */ false, 1);
  ExpectNoEntryAtIndex(/* is_static = */ false, 2);
  ExpectNoEntryAtIndex(/* is_static = */ false, 3);

  // Insert one entry.
  InsertEntry("foo", "bar");

  ExpectEntryAtIndex(/* is_static = */ false, 0, "foo", "bar");

  ExpectNoEntryAtIndex(/* is_static = */ false, 1);
  ExpectNoEntryAtIndex(/* is_static = */ false, 2);
  ExpectNoEntryAtIndex(/* is_static = */ false, 3);

  // Insert a different entry.
  InsertEntry("baz", "bing");

  ExpectEntryAtIndex(/* is_static = */ false, 0, "foo", "bar");

  ExpectEntryAtIndex(/* is_static = */ false, 1, "baz", "bing");

  ExpectNoEntryAtIndex(/* is_static = */ false, 2);
  ExpectNoEntryAtIndex(/* is_static = */ false, 3);

  // Insert an entry identical to the most recently inserted one.
  InsertEntry("baz", "bing");

  ExpectEntryAtIndex(/* is_static = */ false, 0, "foo", "bar");

  ExpectEntryAtIndex(/* is_static = */ false, 1, "baz", "bing");

  ExpectEntryAtIndex(/* is_static = */ false, 2, "baz", "bing");

  ExpectNoEntryAtIndex(/* is_static = */ false, 3);
}

TEST_F(QpackDecoderHeaderTableTest, EvictByInsertion) {
  EXPECT_TRUE(SetDynamicTableCapacity(40));

  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  EXPECT_EQ(1u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(/* is_static = */ false, 0u, "foo", "bar");

  // Inserting second entry evicts the first one.
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(/* is_static = */ false, 0u);
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "baz", "qux");
}

TEST_F(QpackDecoderHeaderTableTest, EvictByUpdateTableSize) {
  ExpectNoEntryAtIndex(/* is_static = */ false, 0u);
  ExpectNoEntryAtIndex(/* is_static = */ false, 1u);

  // Entry size is 3 + 3 + 32 = 38.
  InsertEntry("foo", "bar");
  InsertEntry("baz", "qux");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(/* is_static = */ false, 0u, "foo", "bar");
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "baz", "qux");

  EXPECT_TRUE(SetDynamicTableCapacity(40));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(/* is_static = */ false, 0u);
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "baz", "qux");

  EXPECT_TRUE(SetDynamicTableCapacity(20));
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(2u, dropped_entry_count());

  ExpectNoEntryAtIndex(/* is_static = */ false, 0u);
  ExpectNoEntryAtIndex(/* is_static = */ false, 1u);
}

TEST_F(QpackDecoderHeaderTableTest, EvictOldestOfIdentical) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert same entry twice.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(/* is_static = */ false, 0u, "foo", "bar");
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "foo", "bar");
  ExpectNoEntryAtIndex(/* is_static = */ false, 2u);

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(/* is_static = */ false, 0u);
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "foo", "bar");
  ExpectEntryAtIndex(/* is_static = */ false, 2u, "baz", "qux");
}

TEST_F(QpackDecoderHeaderTableTest, EvictOldestOfSameName) {
  EXPECT_TRUE(SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert two entries with same name but different values.
  InsertEntry("foo", "bar");
  InsertEntry("foo", "baz");
  EXPECT_EQ(2u, inserted_entry_count());
  EXPECT_EQ(0u, dropped_entry_count());

  ExpectEntryAtIndex(/* is_static = */ false, 0u, "foo", "bar");
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "foo", "baz");
  ExpectNoEntryAtIndex(/* is_static = */ false, 2u);

  // Inserting third entry evicts the first one, not the second.
  InsertEntry("baz", "qux");
  EXPECT_EQ(3u, inserted_entry_count());
  EXPECT_EQ(1u, dropped_entry_count());

  ExpectNoEntryAtIndex(/* is_static = */ false, 0u);
  ExpectEntryAtIndex(/* is_static = */ false, 1u, "foo", "baz");
  ExpectEntryAtIndex(/* is_static = */ false, 2u, "baz", "qux");
}

TEST_F(QpackDecoderHeaderTableTest, RegisterObserver) {
  StrictMock<MockObserver> observer1;
  RegisterObserver(1, &observer1);
  EXPECT_CALL(observer1, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(1u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer1);

  // Registration order does not matter.
  StrictMock<MockObserver> observer2;
  StrictMock<MockObserver> observer3;
  RegisterObserver(3, &observer3);
  RegisterObserver(2, &observer2);

  EXPECT_CALL(observer2, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(2u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer3);

  EXPECT_CALL(observer3, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(3u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer2);

  // Multiple observers with identical |required_insert_count| should all be
  // notified.
  StrictMock<MockObserver> observer4;
  StrictMock<MockObserver> observer5;
  RegisterObserver(4, &observer4);
  RegisterObserver(4, &observer5);

  EXPECT_CALL(observer4, OnInsertCountReachedThreshold);
  EXPECT_CALL(observer5, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  EXPECT_EQ(4u, inserted_entry_count());
  Mock::VerifyAndClearExpectations(&observer4);
  Mock::VerifyAndClearExpectations(&observer5);
}

TEST_F(QpackDecoderHeaderTableTest, UnregisterObserver) {
  StrictMock<MockObserver> observer1;
  StrictMock<MockObserver> observer2;
  StrictMock<MockObserver> observer3;
  StrictMock<MockObserver> observer4;
  RegisterObserver(1, &observer1);
  RegisterObserver(2, &observer2);
  RegisterObserver(2, &observer3);
  RegisterObserver(3, &observer4);

  UnregisterObserver(2, &observer3);

  EXPECT_CALL(observer1, OnInsertCountReachedThreshold);
  EXPECT_CALL(observer2, OnInsertCountReachedThreshold);
  EXPECT_CALL(observer4, OnInsertCountReachedThreshold);
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  InsertEntry("foo", "bar");
  EXPECT_EQ(3u, inserted_entry_count());
}

TEST_F(QpackDecoderHeaderTableTest, Cancel) {
  StrictMock<MockObserver> observer;
  auto table = std::make_unique<QpackDecoderHeaderTable>();
  table->RegisterObserver(1, &observer);

  EXPECT_CALL(observer, Cancel);
  table.reset();
}

}  // namespace
}  // namespace test
}  // namespace quic
