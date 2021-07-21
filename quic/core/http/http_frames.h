// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_HTTP_FRAMES_H_
#define QUICHE_QUIC_CORE_HTTP_HTTP_FRAMES_H_

#include <algorithm>
#include <cstdint>
#include <limits>
#include <map>
#include <ostream>
#include <sstream>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/string_view.h"
#include "absl/types/optional.h"
#include "quic/core/http/http_constants.h"
#include "quic/core/quic_types.h"
#include "spdy/core/spdy_protocol.h"

namespace quic {

// TODO(b/171463363): Remove.
using PushId = uint64_t;

enum class HttpFrameType {
  DATA = 0x0,
  HEADERS = 0x1,
  CANCEL_PUSH = 0X3,
  SETTINGS = 0x4,
  PUSH_PROMISE = 0x5,
  GOAWAY = 0x7,
  MAX_PUSH_ID = 0xD,
  // https://tools.ietf.org/html/draft-davidben-http-client-hint-reliability-02
  ACCEPT_CH = 0x89,
  // https://tools.ietf.org/html/draft-ietf-httpbis-priority-03
  PRIORITY_UPDATE_REQUEST_STREAM = 0xF0700,
  // https://www.ietf.org/archive/id/draft-ietf-webtrans-http3-00.html
  WEBTRANSPORT_STREAM = 0x41,
  // https://datatracker.ietf.org/doc/html/draft-ietf-masque-h3-datagram-03
  CAPSULE = 0xffcab5,
};

// 7.2.1.  DATA
//
//   DATA frames (type=0x0) convey arbitrary, variable-length sequences of
//   octets associated with an HTTP request or response payload.
struct QUIC_EXPORT_PRIVATE DataFrame {
  absl::string_view data;
};

// 7.2.2.  HEADERS
//
//   The HEADERS frame (type=0x1) is used to carry a header block,
//   compressed using QPACK.
struct QUIC_EXPORT_PRIVATE HeadersFrame {
  absl::string_view headers;
};

// 7.2.4.  SETTINGS
//
//   The SETTINGS frame (type=0x4) conveys configuration parameters that
//   affect how endpoints communicate, such as preferences and constraints
//   on peer behavior

using SettingsMap = absl::flat_hash_map<uint64_t, uint64_t>;

struct QUIC_EXPORT_PRIVATE SettingsFrame {
  SettingsMap values;

  bool operator==(const SettingsFrame& rhs) const {
    return values == rhs.values;
  }

  std::string ToString() const {
    std::string s;
    for (auto it : values) {
      std::string setting = absl::StrCat(
          H3SettingsToString(
              static_cast<Http3AndQpackSettingsIdentifiers>(it.first)),
          " = ", it.second, "; ");
      absl::StrAppend(&s, setting);
    }
    return s;
  }
  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(std::ostream& os,
                                                      const SettingsFrame& s) {
    os << s.ToString();
    return os;
  }
};

// 7.2.6.  GOAWAY
//
//   The GOAWAY frame (type=0x7) is used to initiate shutdown of a connection by
//   either endpoint.
struct QUIC_EXPORT_PRIVATE GoAwayFrame {
  // When sent from server to client, |id| is a stream ID that should refer to
  // a client-initiated bidirectional stream.
  // When sent from client to server, |id| is a push ID.
  uint64_t id;

  bool operator==(const GoAwayFrame& rhs) const { return id == rhs.id; }
};

// 7.2.7.  MAX_PUSH_ID
//
//   The MAX_PUSH_ID frame (type=0xD) is used by clients to control the
//   number of server pushes that the server can initiate.
struct QUIC_EXPORT_PRIVATE MaxPushIdFrame {
  PushId push_id;

  bool operator==(const MaxPushIdFrame& rhs) const {
    return push_id == rhs.push_id;
  }
};

// https://httpwg.org/http-extensions/draft-ietf-httpbis-priority.html
//
// The PRIORITY_UPDATE frame specifies the sender-advised priority of a stream.
// Frame type 0xf0700 (called PRIORITY_UPDATE_REQUEST_STREAM in the
// implementation) is used for for request streams.
// Frame type 0xf0701 is used for push streams and is not implemented.

// Length of a priority frame's first byte.
const QuicByteCount kPriorityFirstByteLength = 1;

enum PrioritizedElementType : uint8_t {
  REQUEST_STREAM = 0x00,
  PUSH_STREAM = 0x80,
};

struct QUIC_EXPORT_PRIVATE PriorityUpdateFrame {
  PrioritizedElementType prioritized_element_type = REQUEST_STREAM;
  uint64_t prioritized_element_id = 0;
  std::string priority_field_value;

  bool operator==(const PriorityUpdateFrame& rhs) const {
    return std::tie(prioritized_element_type, prioritized_element_id,
                    priority_field_value) ==
           std::tie(rhs.prioritized_element_type, rhs.prioritized_element_id,
                    rhs.priority_field_value);
  }
  std::string ToString() const {
    return absl::StrCat("Priority Frame : {prioritized_element_type: ",
                        static_cast<int>(prioritized_element_type),
                        ", prioritized_element_id: ", prioritized_element_id,
                        ", priority_field_value: ", priority_field_value, "}");
  }

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(
      std::ostream& os,
      const PriorityUpdateFrame& s) {
    os << s.ToString();
    return os;
  }
};

// ACCEPT_CH
// https://tools.ietf.org/html/draft-davidben-http-client-hint-reliability-02
//
struct QUIC_EXPORT_PRIVATE AcceptChFrame {
  std::vector<spdy::AcceptChOriginValuePair> entries;

  bool operator==(const AcceptChFrame& rhs) const {
    return entries.size() == rhs.entries.size() &&
           std::equal(entries.begin(), entries.end(), rhs.entries.begin());
  }

  std::string ToString() const {
    std::stringstream s;
    s << *this;
    return s.str();
  }

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(
      std::ostream& os,
      const AcceptChFrame& frame) {
    os << "ACCEPT_CH frame with " << frame.entries.size() << " entries: ";
    for (auto& entry : frame.entries) {
      os << "origin: " << entry.origin << "; value: " << entry.value;
    }
    return os;
  }
};

enum class CapsuleType : uint64_t {
  // Casing in this enum matches the IETF specification.
  REGISTER_DATAGRAM_CONTEXT = 0x00,
  CLOSE_DATAGRAM_CONTEXT = 0x01,
  DATAGRAM = 0x02,
  REGISTER_DATAGRAM_NO_CONTEXT = 0x03,
};

inline std::string CapsuleTypeToString(CapsuleType capsule_type) {
  switch (capsule_type) {
    case CapsuleType::REGISTER_DATAGRAM_CONTEXT:
      return "REGISTER_DATAGRAM_CONTEXT";
    case CapsuleType::CLOSE_DATAGRAM_CONTEXT:
      return "CLOSE_DATAGRAM_CONTEXT";
    case CapsuleType::DATAGRAM:
      return "DATAGRAM";
    case CapsuleType::REGISTER_DATAGRAM_NO_CONTEXT:
      return "REGISTER_DATAGRAM_NO_CONTEXT";
  }
  return absl::StrCat("Unknown(", static_cast<uint64_t>(capsule_type), ")");
}

inline std::ostream& operator<<(std::ostream& os,
                                const CapsuleType& capsule_type) {
  os << CapsuleTypeToString(capsule_type);
  return os;
}

// CAPSULE HTTP frame from draft-ietf-masque-h3-datagram.
struct QUIC_EXPORT_PRIVATE CapsuleFrame {
  CapsuleType capsule_type;
  union {
    struct {
      QuicDatagramContextId context_id;
      absl::string_view context_extensions;
    } register_datagram_context_capsule;
    struct {
      QuicDatagramContextId context_id;
      absl::string_view context_extensions;
    } close_datagram_context_capsule;
    struct {
      absl::optional<QuicDatagramContextId> context_id;
      absl::string_view http_datagram_payload;
    } datagram_capsule;
    struct {
      absl::string_view context_extensions;
    } register_datagram_no_context_capsule;
    absl::string_view unknown_capsule_data;
  };

  explicit CapsuleFrame(CapsuleType capsule_type) : capsule_type(capsule_type) {
    switch (capsule_type) {
      case CapsuleType::REGISTER_DATAGRAM_CONTEXT:
        register_datagram_context_capsule.context_id = 0;
        register_datagram_context_capsule.context_extensions =
            absl::string_view();
        break;
      case CapsuleType::CLOSE_DATAGRAM_CONTEXT:
        close_datagram_context_capsule.context_id = 0;
        close_datagram_context_capsule.context_extensions = absl::string_view();
        break;
      case CapsuleType::DATAGRAM:
        datagram_capsule.context_id = absl::nullopt;
        datagram_capsule.http_datagram_payload = absl::string_view();
        break;
      case CapsuleType::REGISTER_DATAGRAM_NO_CONTEXT:
        register_datagram_no_context_capsule.context_extensions =
            absl::string_view();
        break;
      default:
        unknown_capsule_data = absl::string_view();
        break;
    }
  }

  CapsuleFrame()
      : CapsuleFrame(
            static_cast<CapsuleType>(std::numeric_limits<uint64_t>::max())) {}

  CapsuleFrame& operator=(const CapsuleFrame& other) {
    capsule_type = other.capsule_type;
    switch (capsule_type) {
      case CapsuleType::REGISTER_DATAGRAM_CONTEXT:
        register_datagram_context_capsule.context_id =
            other.register_datagram_context_capsule.context_id;
        register_datagram_context_capsule.context_extensions =
            other.register_datagram_context_capsule.context_extensions;
        break;
      case CapsuleType::CLOSE_DATAGRAM_CONTEXT:
        close_datagram_context_capsule.context_id =
            other.close_datagram_context_capsule.context_id;
        close_datagram_context_capsule.context_extensions =
            other.close_datagram_context_capsule.context_extensions;
        break;
      case CapsuleType::DATAGRAM:
        datagram_capsule.context_id = other.datagram_capsule.context_id;
        datagram_capsule.http_datagram_payload =
            other.datagram_capsule.http_datagram_payload;
        break;
      case CapsuleType::REGISTER_DATAGRAM_NO_CONTEXT:
        register_datagram_no_context_capsule.context_extensions =
            other.register_datagram_no_context_capsule.context_extensions;
        break;
      default:
        unknown_capsule_data = other.unknown_capsule_data;
        break;
    }
    return *this;
  }

  CapsuleFrame(const CapsuleFrame& other) : CapsuleFrame(other.capsule_type) {
    *this = other;
  }

  bool operator==(const CapsuleFrame& other) const {
    if (capsule_type != other.capsule_type) {
      return false;
    }
    switch (capsule_type) {
      case CapsuleType::REGISTER_DATAGRAM_CONTEXT:
        return register_datagram_context_capsule.context_id ==
                   other.register_datagram_context_capsule.context_id &&
               register_datagram_context_capsule.context_extensions ==
                   other.register_datagram_context_capsule.context_extensions;
      case CapsuleType::CLOSE_DATAGRAM_CONTEXT:
        return close_datagram_context_capsule.context_id ==
                   other.close_datagram_context_capsule.context_id &&
               close_datagram_context_capsule.context_extensions ==
                   other.close_datagram_context_capsule.context_extensions;
      case CapsuleType::DATAGRAM:
        return datagram_capsule.context_id ==
                   other.datagram_capsule.context_id &&
               datagram_capsule.http_datagram_payload ==
                   other.datagram_capsule.http_datagram_payload;
      case CapsuleType::REGISTER_DATAGRAM_NO_CONTEXT:
        return register_datagram_no_context_capsule.context_extensions ==
               other.register_datagram_no_context_capsule.context_extensions;
      default:
        return unknown_capsule_data == other.unknown_capsule_data;
    }
  }

  std::string ToString() const {
    std::string rv = CapsuleTypeToString(capsule_type);
    switch (capsule_type) {
      case CapsuleType::REGISTER_DATAGRAM_CONTEXT:
        absl::StrAppend(&rv, "(", register_datagram_context_capsule.context_id,
                        ")");
        break;
      case CapsuleType::CLOSE_DATAGRAM_CONTEXT:
        absl::StrAppend(&rv, "(", close_datagram_context_capsule.context_id,
                        ")");
        break;
      case CapsuleType::DATAGRAM:
        if (datagram_capsule.context_id.has_value()) {
          absl::StrAppend(&rv, "(", datagram_capsule.context_id.value(), ")");
        }
        break;
      case CapsuleType::REGISTER_DATAGRAM_NO_CONTEXT:
        break;
      default:
        break;
    }
    return rv;
  }

  friend QUIC_EXPORT_PRIVATE std::ostream& operator<<(
      std::ostream& os, const CapsuleFrame& frame) {
    os << frame.ToString();
    return os;
  }
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_HTTP_FRAMES_H_
