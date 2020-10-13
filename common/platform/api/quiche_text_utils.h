// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_PLATFORM_API_QUICHE_TEXT_UTILS_H_
#define QUICHE_COMMON_PLATFORM_API_QUICHE_TEXT_UTILS_H_

#include <string>

#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_export.h"
#include "net/quiche/common/platform/impl/quiche_text_utils_impl.h"

namespace quiche {

// Various utilities for manipulating text.
class QUICHE_EXPORT QuicheTextUtils {
 public:
  // Returns true if |data| starts with |prefix|, case sensitively.
  static bool StartsWith(absl::string_view data, absl::string_view prefix) {
    return quiche::QuicheTextUtilsImpl::StartsWith(data, prefix);
  }

  // Returns true if |data| ends with |suffix|, case sensitively.
  static bool EndsWith(absl::string_view data, absl::string_view suffix) {
    return quiche::QuicheTextUtilsImpl::EndsWith(data, suffix);
  }

  // Returns true if |data| ends with |suffix|, case insensitively.
  static bool EndsWithIgnoreCase(absl::string_view data,
                                 absl::string_view suffix) {
    return quiche::QuicheTextUtilsImpl::EndsWithIgnoreCase(data, suffix);
  }

  // Returns a new string in which |data| has been converted to lower case.
  static std::string ToLower(absl::string_view data) {
    return quiche::QuicheTextUtilsImpl::ToLower(data);
  }

  // Removes leading and trailing whitespace from |data|.
  static void RemoveLeadingAndTrailingWhitespace(absl::string_view* data) {
    quiche::QuicheTextUtilsImpl::RemoveLeadingAndTrailingWhitespace(data);
  }

  // Returns true if |in| represents a valid uint64, and stores that value in
  // |out|.
  static bool StringToUint64(absl::string_view in, uint64_t* out) {
    return quiche::QuicheTextUtilsImpl::StringToUint64(in, out);
  }

  // Returns true if |in| represents a valid int, and stores that value in
  // |out|.
  static bool StringToInt(absl::string_view in, int* out) {
    return quiche::QuicheTextUtilsImpl::StringToInt(in, out);
  }

  // Returns true if |in| represents a valid uint32, and stores that value in
  // |out|.
  static bool StringToUint32(absl::string_view in, uint32_t* out) {
    return quiche::QuicheTextUtilsImpl::StringToUint32(in, out);
  }

  // Returns true if |in| represents a valid size_t, and stores that value in
  // |out|.
  static bool StringToSizeT(absl::string_view in, size_t* out) {
    return quiche::QuicheTextUtilsImpl::StringToSizeT(in, out);
  }

  // Returns a new string representing |in|.
  static std::string Uint64ToString(uint64_t in) {
    return quiche::QuicheTextUtilsImpl::Uint64ToString(in);
  }

  // This converts |length| bytes of binary to a 2*|length|-character
  // hexadecimal representation.
  // Return value: 2*|length| characters of ASCII string.
  static std::string HexEncode(const char* data, size_t length) {
    return HexEncode(absl::string_view(data, length));
  }

  // This converts |data.length()| bytes of binary to a
  // 2*|data.length()|-character hexadecimal representation.
  // Return value: 2*|data.length()| characters of ASCII string.
  static std::string HexEncode(absl::string_view data) {
    return quiche::QuicheTextUtilsImpl::HexEncode(data);
  }

  // This converts a uint32 into an 8-character hexidecimal
  // representation.  Return value: 8 characters of ASCII string.
  static std::string Hex(uint32_t v) {
    return quiche::QuicheTextUtilsImpl::Hex(v);
  }

  // Converts |data| from a hexadecimal ASCII string to a binary string
  // that is |data.length()/2| bytes long.
  static std::string HexDecode(absl::string_view data) {
    return quiche::QuicheTextUtilsImpl::HexDecode(data);
  }

  // Base64 encodes with no padding |data_len| bytes of |data| into |output|.
  static void Base64Encode(const uint8_t* data,
                           size_t data_len,
                           std::string* output) {
    return quiche::QuicheTextUtilsImpl::Base64Encode(data, data_len, output);
  }

  // Decodes a base64-encoded |input|.  Returns nullopt when the input is
  // invalid.
  static absl::optional<std::string> Base64Decode(absl::string_view input) {
    return quiche::QuicheTextUtilsImpl::Base64Decode(input);
  }

  // Returns a string containing hex and ASCII representations of |binary|,
  // side-by-side in the style of hexdump. Non-printable characters will be
  // printed as '.' in the ASCII output.
  // For example, given the input "Hello, QUIC!\01\02\03\04", returns:
  // "0x0000:  4865 6c6c 6f2c 2051 5549 4321 0102 0304  Hello,.QUIC!...."
  static std::string HexDump(absl::string_view binary_data) {
    return quiche::QuicheTextUtilsImpl::HexDump(binary_data);
  }

  // Returns true if |data| contains any uppercase characters.
  static bool ContainsUpperCase(absl::string_view data) {
    return quiche::QuicheTextUtilsImpl::ContainsUpperCase(data);
  }

  // Returns true if |data| contains only decimal digits.
  static bool IsAllDigits(absl::string_view data) {
    return quiche::QuicheTextUtilsImpl::IsAllDigits(data);
  }

  // Splits |data| into a vector of pieces delimited by |delim|.
  static std::vector<absl::string_view> Split(absl::string_view data,
                                              char delim) {
    return quiche::QuicheTextUtilsImpl::Split(data, delim);
  }
};

}  // namespace quiche

#endif  // QUICHE_COMMON_PLATFORM_API_QUICHE_TEXT_UTILS_H_
