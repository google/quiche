// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/moqt_key_value_pair.h"

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/header_validator.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace moqt {

namespace {

MoqtError ParseAuthTokenParameter(absl::string_view field,
                                  std::vector<AuthToken>& out) {
  quic::QuicDataReader reader(field);
  AuthTokenAliasType alias_type;
  uint64_t alias;
  AuthTokenType type;
  absl::string_view token;
  uint64_t value;
  if (!reader.ReadVarInt62(&value) || value > AuthTokenAliasType::kMaxValue) {
    return MoqtError::kKeyValueFormattingError;
  }
  alias_type = static_cast<AuthTokenAliasType>(value);
  switch (alias_type) {
    case AuthTokenAliasType::kUseValue:
      if (!reader.ReadVarInt62(&value) ||
          value > AuthTokenType::kMaxAuthTokenType) {
        return MoqtError::kKeyValueFormattingError;
      }
      type = static_cast<AuthTokenType>(value);
      token = reader.PeekRemainingPayload();
      out.push_back(AuthToken(type, token));
      break;
    case AuthTokenAliasType::kUseAlias:
      if (!reader.ReadVarInt62(&value)) {
        return MoqtError::kKeyValueFormattingError;
      }
      out.push_back(AuthToken(value, alias_type));
      break;
    case AuthTokenAliasType::kRegister:
      if (!reader.ReadVarInt62(&alias) || !reader.ReadVarInt62(&value)) {
        return MoqtError::kKeyValueFormattingError;
      }
      type = static_cast<AuthTokenType>(value);
      token = reader.PeekRemainingPayload();
      out.push_back(AuthToken(alias, type, token));
      break;
    case AuthTokenAliasType::kDelete:
      if (!reader.ReadVarInt62(&alias)) {
        return MoqtError::kKeyValueFormattingError;
      }
      out.push_back(AuthToken(alias, alias_type));
      break;
  }
  return MoqtError::kNoError;
}
}  // namespace

void KeyValuePairList::insert(uint64_t key,
                              std::variant<uint64_t, absl::string_view> value) {
  QUICHE_DCHECK(
      (key % 2 == 1 && std::holds_alternative<absl::string_view>(value)) ||
      (key % 2 == 0 && std::holds_alternative<uint64_t>(value)));
  if (std::holds_alternative<absl::string_view>(value)) {
    map_.insert({key, std::string(std::get<absl::string_view>(value))});
  } else {
    map_.insert({key, std::get<uint64_t>(value)});
  }
}

bool KeyValuePairList::ForEach(ValueCallback callback) const {
  for (const auto& [key, value] : map_) {
    if (!std::visit([&](const auto& val) { return callback(key, val); },
                    value)) {
      return false;
    }
  }
  return true;
}

KeyValuePairList::ValueVector KeyValuePairList::Get(uint64_t key) const {
  std::vector<std::variant<uint64_t, absl::string_view>> values;
  auto entries = map_.equal_range(key);
  for (auto it = entries.first; it != entries.second; ++it) {
    std::visit([&](const auto& value) { values.push_back(value); }, it->second);
  }
  return values;
}

MoqtError KeyValuePairListToSetupParameters(const KeyValuePairList& parameters,
                                            SetupParameters& out) {
  MoqtError error = MoqtError::kNoError;
  // If this callback returns false without explicitly setting an error, then
  // the error is a duplicate parameter (kProtocolViolation)
  bool result = parameters.ForEach(
      [&](uint64_t key, std::variant<uint64_t, absl::string_view> value) {
        switch (static_cast<SetupParameter>(key)) {
          case SetupParameter::kMaxRequestId:
            if (out.max_request_id.has_value()) {
              return false;
            }
            out.max_request_id = std::get<uint64_t>(value);
            break;
          case SetupParameter::kMaxAuthTokenCacheSize:
            if (out.max_auth_token_cache_size.has_value()) {
              return false;
            }
            out.max_auth_token_cache_size = std::get<uint64_t>(value);
            break;
          case SetupParameter::kPath:
            if (out.path.has_value()) {
              return false;
            }
            if (!http2::adapter::HeaderValidator::IsValidPath(
                    std::get<absl::string_view>(value),
                    /*allow_fragment=*/false)) {
              error = MoqtError::kMalformedPath;
              return false;
            }
            out.path = std::get<absl::string_view>(value);
            break;
          case SetupParameter::kAuthorizationToken:
            error = ParseAuthTokenParameter(std::get<absl::string_view>(value),
                                            out.authorization_tokens);
            if (error != MoqtError::kNoError) {
              return false;
            }
            break;
          case SetupParameter::kAuthority:
            if (!http2::adapter::HeaderValidator::IsValidAuthority(
                    std::get<absl::string_view>(value))) {
              error = MoqtError::kMalformedAuthority;
              return false;
            }
            out.authority = std::get<absl::string_view>(value);
            break;
          case SetupParameter::kMoqtImplementation:
            if (out.moqt_implementation.has_value()) {
              return false;
            }
            QUICHE_LOG(INFO) << "Peer MOQT implementation: "
                             << std::get<absl::string_view>(value);
            out.moqt_implementation = std::get<absl::string_view>(value);
            break;
          case SetupParameter::kSupportObjectAcks:
            if (out.support_object_acks.has_value()) {
              return false;
            }
            if (std::get<uint64_t>(value) > 1) {
              error = MoqtError::kKeyValueFormattingError;
              return false;
            }
            out.support_object_acks = (std::get<uint64_t>(value) == 1);
            break;
          default:
            break;
        }
        return true;
      });
  if (!result && error == MoqtError::kNoError) {
    return MoqtError::kProtocolViolation;
  }
  return error;
}

void SetupParametersToKeyValuePairList(const SetupParameters& parameters,
                                       KeyValuePairList& out,
                                       AuthTokenSerializer serializer) {
  out.clear();
  if (parameters.max_request_id.has_value()) {
    out.insert(static_cast<uint64_t>(SetupParameter::kMaxRequestId),
               *parameters.max_request_id);
  }
  if (parameters.max_auth_token_cache_size.has_value()) {
    out.insert(static_cast<uint64_t>(SetupParameter::kMaxAuthTokenCacheSize),
               *parameters.max_auth_token_cache_size);
  }
  if (parameters.path.has_value()) {
    out.insert(static_cast<uint64_t>(SetupParameter::kPath), *parameters.path);
  }
  for (const AuthToken& token : parameters.authorization_tokens) {
    out.insert(static_cast<uint64_t>(SetupParameter::kAuthorizationToken),
               serializer(token).AsStringView());
  }
  if (parameters.authority.has_value()) {
    out.insert(static_cast<uint64_t>(SetupParameter::kAuthority),
               *parameters.authority);
  }
  if (parameters.moqt_implementation.has_value()) {
    out.insert(static_cast<uint64_t>(SetupParameter::kMoqtImplementation),
               *parameters.moqt_implementation);
  }
  if (parameters.support_object_acks.has_value()) {
    out.insert(static_cast<uint64_t>(SetupParameter::kSupportObjectAcks),
               *parameters.support_object_acks ? 1ULL : 0ULL);
  }
}

MoqtError KeyValuePairListToVersionSpecificParameters(
    const KeyValuePairList& parameters, VersionSpecificParameters& out) {
  MoqtError error = MoqtError::kNoError;
  if (parameters.count(static_cast<uint64_t>(
          VersionSpecificParameter::kDeliveryTimeout)) > 1 ||
      parameters.count(static_cast<uint64_t>(
          VersionSpecificParameter::kMaxCacheDuration)) > 1) {
    return MoqtError::kProtocolViolation;
  }
  parameters.ForEach([&](uint64_t key,
                         std::variant<uint64_t, absl::string_view> value) {
    VersionSpecificParameter parameter =
        static_cast<VersionSpecificParameter>(key);
    switch (parameter) {
      case VersionSpecificParameter::kDeliveryTimeout:
        out.delivery_timeout =
            quic::QuicTimeDelta::TryFromMilliseconds(std::get<uint64_t>(value))
                .value_or(quic::QuicTimeDelta::Infinite());
        break;
      case VersionSpecificParameter::kMaxCacheDuration:
        out.max_cache_duration =
            quic::QuicTimeDelta::TryFromMilliseconds(std::get<uint64_t>(value))
                .value_or(quic::QuicTimeDelta::Infinite());
        break;
      case VersionSpecificParameter::kOackWindowSize:
        out.oack_window_size =
            quic::QuicTimeDelta::FromMicroseconds(std::get<uint64_t>(value));
        break;
      case VersionSpecificParameter::kAuthorizationToken:
        error = ParseAuthTokenParameter(std::get<absl::string_view>(value),
                                        out.authorization_tokens);
        if (error != MoqtError::kNoError) {
          return false;
        }
        break;
      default:
        break;
    }
    return true;
  });
  return error;
}

void VersionSpecificParametersToKeyValuePairList(
    const VersionSpecificParameters& parameters, KeyValuePairList& out,
    AuthTokenSerializer serializer) {
  out.clear();
  if (parameters.delivery_timeout != quic::QuicTimeDelta::Infinite()) {
    out.insert(
        static_cast<uint64_t>(VersionSpecificParameter::kDeliveryTimeout),
        static_cast<uint64_t>(parameters.delivery_timeout.ToMilliseconds()));
  }
  for (const AuthToken& token : parameters.authorization_tokens) {
    out.insert(
        static_cast<uint64_t>(VersionSpecificParameter::kAuthorizationToken),
        serializer(token).AsStringView());
  }
  if (parameters.max_cache_duration != quic::QuicTimeDelta::Infinite()) {
    out.insert(
        static_cast<uint64_t>(VersionSpecificParameter::kMaxCacheDuration),
        static_cast<uint64_t>(parameters.max_cache_duration.ToMilliseconds()));
  }
  if (parameters.oack_window_size.has_value()) {
    out.insert(
        static_cast<uint64_t>(VersionSpecificParameter::kOackWindowSize),
        static_cast<uint64_t>(parameters.oack_window_size->ToMicroseconds()));
  }
}

}  // namespace moqt
