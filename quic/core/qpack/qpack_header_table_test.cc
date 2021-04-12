// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/core/qpack/qpack_header_table.h"

#include <utility>

#include "absl/base/macros.h"
#include "absl/strings/string_view.h"
#include "quic/core/qpack/qpack_static_table.h"
#include "quic/platform/api/quic_test.h"
#include "spdy/core/hpack/hpack_entry.h"

using ::testing::Mock;
using ::testing::StrictMock;

namespace quic {
namespace test {
namespace {

const uint64_t kMaximumDynamicTableCapacityForTesting = 1024 * 1024;

template <typename T>
class QpackHeaderTableTest : public QuicTest {
 protected:
  QpackHeaderTableTest() {
    table_.SetMaximumDynamicTableCapacity(
        kMaximumDynamicTableCapacityForTesting);
    table_.SetDynamicTableCapacity(kMaximumDynamicTableCapacityForTesting);
  }
  ~QpackHeaderTableTest() override = default;

  void ExpectMatch(absl::string_view name,
                   absl::string_view value,
                   QpackHeaderTableBase::MatchType expected_match_type,
                   bool expected_is_static,
                   uint64_t expected_index) const {
    // Initialize outparams to a value different from the expected to ensure
    // that FindHeaderField() sets them.
    bool is_static = !expected_is_static;
    uint64_t index = expected_index + 1;

    QpackHeaderTableBase::MatchType matchtype =
        table_.FindHeaderField(name, value, &is_static, &index);

    EXPECT_EQ(expected_match_type, matchtype) << name << ": " << value;
    EXPECT_EQ(expected_is_static, is_static) << name << ": " << value;
    EXPECT_EQ(expected_index, index) << name << ": " << value;
  }

  void ExpectNoMatch(absl::string_view name, absl::string_view value) const {
    bool is_static = false;
    uint64_t index = 0;

    QpackHeaderTableBase::MatchType matchtype =
        table_.FindHeaderField(name, value, &is_static, &index);

    EXPECT_EQ(QpackHeaderTableBase::MatchType::kNoMatch, matchtype)
        << name << ": " << value;
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

TYPED_TEST(QpackHeaderTableTest, FindStaticHeaderField) {
  // A header name that has multiple entries with different values.
  this->ExpectMatch(":method", "GET",
                    QpackHeaderTableBase::MatchType::kNameAndValue, true, 17u);

  this->ExpectMatch(":method", "POST",
                    QpackHeaderTableBase::MatchType::kNameAndValue, true, 20u);

  this->ExpectMatch(":method", "TRACE", QpackHeaderTableBase::MatchType::kName,
                    true, 15u);

  // A header name that has a single entry with non-empty value.
  this->ExpectMatch("accept-encoding", "gzip, deflate, br",
                    QpackHeaderTableBase::MatchType::kNameAndValue, true, 31u);

  this->ExpectMatch("accept-encoding", "compress",
                    QpackHeaderTableBase::MatchType::kName, true, 31u);

  this->ExpectMatch("accept-encoding", "",
                    QpackHeaderTableBase::MatchType::kName, true, 31u);

  // A header name that has a single entry with empty value.
  this->ExpectMatch("location", "",
                    QpackHeaderTableBase::MatchType::kNameAndValue, true, 12u);

  this->ExpectMatch("location", "foo", QpackHeaderTableBase::MatchType::kName,
                    true, 12u);

  // No matching header name.
  this->ExpectNoMatch("foo", "");
  this->ExpectNoMatch("foo", "bar");
}

TYPED_TEST(QpackHeaderTableTest, FindDynamicHeaderField) {
  // Dynamic table is initially entry.
  this->ExpectNoMatch("foo", "bar");
  this->ExpectNoMatch("foo", "baz");

  // Insert one entry.
  this->InsertEntry("foo", "bar");

  // Match name and value.
  this->ExpectMatch("foo", "bar",
                    QpackHeaderTableBase::MatchType::kNameAndValue, false, 0u);

  // Match name only.
  this->ExpectMatch("foo", "baz", QpackHeaderTableBase::MatchType::kName, false,
                    0u);

  // Insert an identical entry.  FindHeaderField() should return the index of
  // the most recently inserted matching entry.
  this->InsertEntry("foo", "bar");

  // Match name and value.
  this->ExpectMatch("foo", "bar",
                    QpackHeaderTableBase::MatchType::kNameAndValue, false, 1u);

  // Match name only.
  this->ExpectMatch("foo", "baz", QpackHeaderTableBase::MatchType::kName, false,
                    1u);
}

TYPED_TEST(QpackHeaderTableTest, FindHeaderFieldPrefersStaticTable) {
  // Insert an entry to the dynamic table that exists in the static table.
  this->InsertEntry(":method", "GET");

  // FindHeaderField() prefers static table if both have name-and-value match.
  this->ExpectMatch(":method", "GET",
                    QpackHeaderTableBase::MatchType::kNameAndValue, true, 17u);

  // FindHeaderField() prefers static table if both have name match but no value
  // match, and prefers the first entry with matching name.
  this->ExpectMatch(":method", "TRACE", QpackHeaderTableBase::MatchType::kName,
                    true, 15u);

  // Add new entry to the dynamic table.
  this->InsertEntry(":method", "TRACE");

  // FindHeaderField prefers name-and-value match in dynamic table over name
  // only match in static table.
  this->ExpectMatch(":method", "TRACE",
                    QpackHeaderTableBase::MatchType::kNameAndValue, false, 1u);
}

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

TYPED_TEST(QpackHeaderTableTest, EvictByInsertion) {
  EXPECT_TRUE(this->SetDynamicTableCapacity(40));

  // Entry size is 3 + 3 + 32 = 38.
  this->InsertEntry("foo", "bar");
  EXPECT_EQ(1u, this->inserted_entry_count());
  EXPECT_EQ(0u, this->dropped_entry_count());

  this->ExpectMatch("foo", "bar",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 0u);

  // Inserting second entry evicts the first one.
  this->InsertEntry("baz", "qux");
  EXPECT_EQ(2u, this->inserted_entry_count());
  EXPECT_EQ(1u, this->dropped_entry_count());

  this->ExpectNoMatch("foo", "bar");
  this->ExpectMatch("baz", "qux",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 1u);
}

TYPED_TEST(QpackHeaderTableTest, EvictByUpdateTableSize) {
  // Entry size is 3 + 3 + 32 = 38.
  this->InsertEntry("foo", "bar");
  this->InsertEntry("baz", "qux");
  EXPECT_EQ(2u, this->inserted_entry_count());
  EXPECT_EQ(0u, this->dropped_entry_count());

  this->ExpectMatch("foo", "bar",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 0u);
  this->ExpectMatch("baz", "qux",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 1u);

  EXPECT_TRUE(this->SetDynamicTableCapacity(40));
  EXPECT_EQ(2u, this->inserted_entry_count());
  EXPECT_EQ(1u, this->dropped_entry_count());

  this->ExpectNoMatch("foo", "bar");
  this->ExpectMatch("baz", "qux",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 1u);

  EXPECT_TRUE(this->SetDynamicTableCapacity(20));
  EXPECT_EQ(2u, this->inserted_entry_count());
  EXPECT_EQ(2u, this->dropped_entry_count());

  this->ExpectNoMatch("foo", "bar");
  this->ExpectNoMatch("baz", "qux");
}

TYPED_TEST(QpackHeaderTableTest, EvictOldestOfIdentical) {
  EXPECT_TRUE(this->SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert same entry twice.
  this->InsertEntry("foo", "bar");
  this->InsertEntry("foo", "bar");
  EXPECT_EQ(2u, this->inserted_entry_count());
  EXPECT_EQ(0u, this->dropped_entry_count());

  // Find most recently inserted entry.
  this->ExpectMatch("foo", "bar",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 1u);

  // Inserting third entry evicts the first one, not the second.
  this->InsertEntry("baz", "qux");
  EXPECT_EQ(3u, this->inserted_entry_count());
  EXPECT_EQ(1u, this->dropped_entry_count());

  this->ExpectMatch("foo", "bar",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 1u);
  this->ExpectMatch("baz", "qux",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 2u);
}

TYPED_TEST(QpackHeaderTableTest, EvictOldestOfSameName) {
  EXPECT_TRUE(this->SetDynamicTableCapacity(80));

  // Entry size is 3 + 3 + 32 = 38.
  // Insert two entries with same name but different values.
  this->InsertEntry("foo", "bar");
  this->InsertEntry("foo", "baz");
  EXPECT_EQ(2u, this->inserted_entry_count());
  EXPECT_EQ(0u, this->dropped_entry_count());

  // Find most recently inserted entry with matching name.
  this->ExpectMatch("foo", "foo", QpackHeaderTableBase::MatchType::kName,
                    /* expected_is_static = */ false, 1u);

  // Inserting third entry evicts the first one, not the second.
  this->InsertEntry("baz", "qux");
  EXPECT_EQ(3u, this->inserted_entry_count());
  EXPECT_EQ(1u, this->dropped_entry_count());

  this->ExpectMatch("foo", "foo", QpackHeaderTableBase::MatchType::kName,
                    /* expected_is_static = */ false, 1u);
  this->ExpectMatch("baz", "qux",
                    QpackHeaderTableBase::MatchType::kNameAndValue,
                    /* expected_is_static = */ false, 2u);
}

// Returns the size of the largest entry that could be inserted into the
// dynamic table without evicting entry |index|.
TYPED_TEST(QpackHeaderTableTest, MaxInsertSizeWithoutEvictingGivenEntry) {
  const uint64_t dynamic_table_capacity = 100;
  TypeParam table;
  table.SetMaximumDynamicTableCapacity(dynamic_table_capacity);
  EXPECT_TRUE(table.SetDynamicTableCapacity(dynamic_table_capacity));

  // Empty table can take an entry up to its capacity.
  EXPECT_EQ(dynamic_table_capacity,
            table.MaxInsertSizeWithoutEvictingGivenEntry(0));

  const uint64_t entry_size1 = QpackEntry::Size("foo", "bar");
  table.InsertEntry("foo", "bar");
  EXPECT_EQ(dynamic_table_capacity - entry_size1,
            table.MaxInsertSizeWithoutEvictingGivenEntry(0));
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity,
            table.MaxInsertSizeWithoutEvictingGivenEntry(1));

  const uint64_t entry_size2 = QpackEntry::Size("baz", "foobar");
  table.InsertEntry("baz", "foobar");
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity,
            table.MaxInsertSizeWithoutEvictingGivenEntry(2));
  // Second entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size2,
            table.MaxInsertSizeWithoutEvictingGivenEntry(1));
  // First and second entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size2 - entry_size1,
            table.MaxInsertSizeWithoutEvictingGivenEntry(0));

  // Third entry evicts first one.
  const uint64_t entry_size3 = QpackEntry::Size("last", "entry");
  table.InsertEntry("last", "entry");
  EXPECT_EQ(1u, table.dropped_entry_count());
  // Table can take an entry up to its capacity if all entries are allowed to be
  // evicted.
  EXPECT_EQ(dynamic_table_capacity,
            table.MaxInsertSizeWithoutEvictingGivenEntry(3));
  // Third entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size3,
            table.MaxInsertSizeWithoutEvictingGivenEntry(2));
  // Second and third entry must stay.
  EXPECT_EQ(dynamic_table_capacity - entry_size3 - entry_size2,
            table.MaxInsertSizeWithoutEvictingGivenEntry(1));
}

TYPED_TEST(QpackHeaderTableTest, DrainingIndex) {
  TypeParam table;
  table.SetMaximumDynamicTableCapacity(kMaximumDynamicTableCapacityForTesting);
  EXPECT_TRUE(
      table.SetDynamicTableCapacity(4 * QpackEntry::Size("foo", "bar")));

  // Empty table: no draining entry.
  EXPECT_EQ(0u, table.draining_index(0.0));
  EXPECT_EQ(0u, table.draining_index(1.0));

  // Table with one entry.
  table.InsertEntry("foo", "bar");
  // Any entry can be referenced if none of the table is draining.
  EXPECT_EQ(0u, table.draining_index(0.0));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(1u, table.draining_index(1.0));

  // Table with two entries is at half capacity.
  table.InsertEntry("foo", "bar");
  // Any entry can be referenced if at most half of the table is draining,
  // because current entries only take up half of total capacity.
  EXPECT_EQ(0u, table.draining_index(0.0));
  EXPECT_EQ(0u, table.draining_index(0.5));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(2u, table.draining_index(1.0));

  // Table with four entries is full.
  table.InsertEntry("foo", "bar");
  table.InsertEntry("foo", "bar");
  // Any entry can be referenced if none of the table is draining.
  EXPECT_EQ(0u, table.draining_index(0.0));
  // In a full table with identically sized entries, |draining_fraction| of all
  // entries are draining.
  EXPECT_EQ(2u, table.draining_index(0.5));
  // No entry can be referenced if all of the table is draining.
  EXPECT_EQ(4u, table.draining_index(1.0));
}

TYPED_TEST(QpackHeaderTableTest, EntryFitsDynamicTableCapacity) {
  EXPECT_TRUE(this->SetDynamicTableCapacity(39));

  EXPECT_TRUE(this->EntryFitsDynamicTableCapacity("foo", "bar"));
  EXPECT_TRUE(this->EntryFitsDynamicTableCapacity("foo", "bar2"));
  EXPECT_FALSE(this->EntryFitsDynamicTableCapacity("foo", "bar12"));
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

  void ExpectEntryAtIndex(bool is_static,
                          uint64_t index,
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
