// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_MOQT_KEY_VALUE_PAIR_H_
#define QUICHE_QUIC_MOQT_MOQT_KEY_VALUE_PAIR_H_

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "absl/container/btree_map.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/quiche_callbacks.h"

namespace moqt {

// Encodes a list of key-value pairs common to both parameters and extensions.
// If the key is odd, it is a length-prefixed string (which may encode further
// item-specific structure). If the key is even, it is a varint.
// This class does not interpret the semantic meaning of the keys and values.
// Keys must be ordered.
class QUICHE_EXPORT KeyValuePairList {
 public:
  KeyValuePairList() = default;

  size_t size() const { return map_.size(); }
  void insert(uint64_t key, std::variant<uint64_t, absl::string_view> value);
  size_t count(uint64_t key) const { return map_.count(key); }
  bool contains(uint64_t key) const { return map_.contains(key); }

  using ValueCallback = quiche::UnretainedCallback<bool(
      uint64_t, std::variant<uint64_t, absl::string_view>)>;
  // Iterates through the whole list in increasing numerical order of key, and
  // executes |callback| for each element.
  // Returns false if |callback| returns false for any element.
  bool ForEach(ValueCallback callback) const;
  using ValueVector = std::vector<std::variant<uint64_t, absl::string_view>>;
  ValueVector Get(uint64_t key) const;
  void clear() { map_.clear(); }

 private:
  absl::btree_multimap<uint64_t, std::variant<uint64_t, std::string>> map_;
};

enum AuthTokenType : uint64_t {
  kOutOfBand = 0x0,

  kMaxAuthTokenType = 0x0,
};

enum AuthTokenAliasType : uint64_t {
  kDelete = 0x0,
  kRegister = 0x1,
  kUseAlias = 0x2,
  kUseValue = 0x3,

  kMaxValue = 0x3,
};

struct AuthToken {
  AuthToken(uint64_t alias, AuthTokenAliasType alias_type)
      : alias_type(alias_type), alias(alias) {
    QUICHE_DCHECK(alias_type == AuthTokenAliasType::kDelete ||
                  alias_type == AuthTokenAliasType::kUseAlias);
  }
  AuthToken(uint64_t alias, AuthTokenType type, absl::string_view value)
      : alias_type(AuthTokenAliasType::kRegister),
        alias(alias),
        type(type),
        value(value) {}
  AuthToken(AuthTokenType type, absl::string_view value)
      : alias_type(AuthTokenAliasType::kUseValue), type(type), value(value) {}
  bool operator==(const AuthToken& other) const = default;

  AuthTokenAliasType alias_type;
  std::optional<uint64_t> alias;
  std::optional<AuthTokenType> type;
  std::optional<std::string> value;
};

using AuthTokenSerializer =
    quiche::UnretainedCallback<quiche::QuicheBuffer(const AuthToken&)>;

// Setup parameters.
inline constexpr uint64_t kDefaultMaxRequestId = 0;
// TODO(martinduke): Implement an auth token cache.
inline constexpr uint64_t kDefaultMaxAuthTokenCacheSize = 0;
inline constexpr bool kDefaultSupportObjectAcks = false;
enum class QUICHE_EXPORT SetupParameter : uint64_t {
  kPath = 0x1,
  kMaxRequestId = 0x2,
  kAuthorizationToken = 0x3,
  kMaxAuthTokenCacheSize = 0x4,
  kAuthority = 0x5,
  kMoqtImplementation = 0x7,

  // QUICHE-specific extensions.
  // Indicates support for OACK messages.
  kSupportObjectAcks = 0xbbf1438,
};
struct QUICHE_EXPORT SetupParameters {
  SetupParameters() = default;
  // Constructors for tests.
  SetupParameters(absl::string_view path, absl::string_view authority,
                  uint64_t max_request_id)
      : path(path), max_request_id(max_request_id), authority(authority) {}
  SetupParameters(uint64_t max_request_id) : max_request_id(max_request_id) {}

  std::optional<std::string> path;
  std::optional<uint64_t> max_request_id;
  // TODO(martinduke): Turn authorization_token into structured data.
  std::vector<AuthToken> authorization_tokens;
  std::optional<uint64_t> max_auth_token_cache_size;
  std::optional<std::string> authority;
  std::optional<std::string> moqt_implementation;

  std::optional<bool> support_object_acks;
  bool operator==(const SetupParameters& other) const = default;
};
// If kProtocolViolation, there are illegal duplicates.
MoqtError KeyValuePairListToSetupParameters(const KeyValuePairList& parameters,
                                            SetupParameters& out);
void SetupParametersToKeyValuePairList(const SetupParameters& parameters,
                                       KeyValuePairList& out,
                                       AuthTokenSerializer serializer);

// Version specific parameters.
// TODO(martinduke): Replace with MessageParameters and delete when all
// messages are migrated.
enum class QUICHE_EXPORT VersionSpecificParameter : uint64_t {
  kDeliveryTimeout = 0x2,
  kAuthorizationToken = 0x3,
  kMaxCacheDuration = 0x4,

  // QUICHE-specific extensions.
  kOackWindowSize = 0xbbf1438,
};
struct VersionSpecificParameters {
  VersionSpecificParameters() = default;
  // Likely parameter combinations.
  VersionSpecificParameters(quic::QuicTimeDelta delivery_timeout,
                            quic::QuicTimeDelta max_cache_duration)
      : delivery_timeout(delivery_timeout),
        max_cache_duration(max_cache_duration) {}
  VersionSpecificParameters(AuthTokenType token_type, absl::string_view token) {
    authorization_tokens.emplace_back(token_type, token);
  }
  VersionSpecificParameters(quic::QuicTimeDelta delivery_timeout,
                            AuthTokenType token_type, absl::string_view token)
      : delivery_timeout(delivery_timeout) {
    authorization_tokens.emplace_back(token_type, token);
  }

  std::vector<AuthToken> authorization_tokens;
  quic::QuicTimeDelta delivery_timeout = quic::QuicTimeDelta::Infinite();
  quic::QuicTimeDelta max_cache_duration = quic::QuicTimeDelta::Infinite();
  std::optional<quic::QuicTimeDelta> oack_window_size;

  bool operator==(const VersionSpecificParameters& other) const = default;
};
// If kProtocolViolation, there are illegal duplicates.
MoqtError KeyValuePairListToVersionSpecificParameters(
    const KeyValuePairList& parameters, VersionSpecificParameters& out);
void VersionSpecificParametersToKeyValuePairList(
    const VersionSpecificParameters& parameters, KeyValuePairList& out,
    AuthTokenSerializer serializer);

// TODO(martinduke): Extension Headers (MOQT draft-16 Sec 11)

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_KEY_VALUE_PAIR_H_
