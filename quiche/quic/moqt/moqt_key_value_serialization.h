// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_KEY_VALUE_SERIALIZATION_H_
#define QUICHE_QUIC_MOQT_MOQT_KEY_VALUE_SERIALIZATION_H_

#include <cstddef>
#include <cstdint>
#include <variant>

#include "absl/functional/overload.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/quiche_data_writer.h"
#include "quiche/common/wire_serialization.h"

namespace moqt {

class QUICHE_EXPORT WireKeyVarIntPair {
 public:
  explicit WireKeyVarIntPair(uint64_t key, uint64_t value)
      : key_(key), value_(value) {}

  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(quiche::WireMoqVarInt(key_),
                                       quiche::WireMoqVarInt(value_));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(writer, quiche::WireMoqVarInt(key_),
                                       quiche::WireMoqVarInt(value_));
  }

 private:
  const uint64_t key_;
  const uint64_t value_;
};

class QUICHE_EXPORT WireKeyStringPair {
 public:
  explicit WireKeyStringPair(uint64_t key, absl::string_view value)
      : key_(key), value_(value) {}
  size_t GetLengthOnWire() {
    return quiche::ComputeLengthOnWire(
        quiche::WireMoqVarInt(key_),
        quiche::WireStringWithMoqVarIntLength(value_));
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    return quiche::SerializeIntoWriter(
        writer, quiche::WireMoqVarInt(key_),
        quiche::WireStringWithMoqVarIntLength(value_));
  }

 private:
  const uint64_t key_;
  const absl::string_view value_;
};

class QUICHE_EXPORT WireKeyValuePairList {
 public:
  explicit WireKeyValuePairList(const KeyValuePairList& list) : list_(list) {}

  size_t GetLengthOnWire() {
    size_t total = 0;
    uint64_t last_key = 0;
    list_.ForEach([&](uint64_t key,
                      std::variant<uint64_t, absl::string_view> value) {
      total += std::visit(
          absl::Overload{
              [&](uint64_t val) {
                return WireKeyVarIntPair(key - last_key, val).GetLengthOnWire();
              },
              [&](absl::string_view val) {
                return WireKeyStringPair(key - last_key, val).GetLengthOnWire();
              }},
          value);
      last_key = key;
      return true;
    });
    return total;
  }
  absl::Status SerializeIntoWriter(quiche::QuicheDataWriter& writer) {
    uint64_t last_key = 0;
    absl::Status status = absl::OkStatus();
    list_.ForEach(
        [&](uint64_t key, std::variant<uint64_t, absl::string_view> value) {
          status = std::visit(
              absl::Overload{[&](uint64_t val) {
                               return WireKeyVarIntPair(key - last_key, val)
                                   .SerializeIntoWriter(writer);
                             },
                             [&](absl::string_view val) {
                               return WireKeyStringPair(key - last_key, val)
                                   .SerializeIntoWriter(writer);
                             }},
              value);
          last_key = key;
          return quiche::IsWriterStatusOk(status);
        });
    return status;
  }

 private:
  const KeyValuePairList& list_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_KEY_VALUE_SERIALIZATION_H_
