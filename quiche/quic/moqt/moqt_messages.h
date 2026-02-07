// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Structured data for message types in draft-ietf-moq-transport-02.

#ifndef QUICHE_QUIC_MOQT_MOQT_MESSAGES_H_
#define QUICHE_QUIC_MOQT_MOQT_MESSAGES_H_

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <string>
#include <utility>
#include <variant>
#include <vector>

#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/moqt/moqt_error.h"
#include "quiche/quic/moqt/moqt_key_value_pair.h"
#include "quiche/quic/moqt/moqt_names.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/common/platform/api/quiche_export.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace moqt {

inline constexpr quic::ParsedQuicVersionVector GetMoqtSupportedQuicVersions() {
  return quic::ParsedQuicVersionVector{quic::ParsedQuicVersion::RFCv1()};
}

inline constexpr absl::string_view kDraft16 = "moqt-16";
inline constexpr absl::string_view kDefaultMoqtVersion = kDraft16;
inline constexpr absl::string_view kUnrecognizedVersionForTests = "moqt-15";

inline constexpr absl::string_view kImplementationName =
    "Google QUICHE MOQT draft 16";
inline constexpr uint64_t kDefaultInitialMaxRequestId = 100;
struct QUICHE_EXPORT MoqtSessionParameters {
  // TODO: support multiple versions.
  MoqtSessionParameters() = default;
  explicit MoqtSessionParameters(quic::Perspective perspective)
      : perspective(perspective), using_webtrans(true) {}
  MoqtSessionParameters(quic::Perspective perspective, std::string path,
                        std::string authority)
      : perspective(perspective),
        using_webtrans(false),
        path(std::move(path)),
        authority(std::move(authority)) {}
  MoqtSessionParameters(quic::Perspective perspective, std::string path,
                        std::string authority, uint64_t max_request_id)
      : perspective(perspective),
        using_webtrans(true),
        path(std::move(path)),
        max_request_id(max_request_id),
        authority(std::move(authority)) {}
  MoqtSessionParameters(quic::Perspective perspective, uint64_t max_request_id)
      : perspective(perspective), max_request_id(max_request_id) {}
  bool operator==(const MoqtSessionParameters& other) const = default;

  std::string version = std::string(kDefaultMoqtVersion);
  bool deliver_partial_objects = false;
  quic::Perspective perspective = quic::Perspective::IS_SERVER;
  bool using_webtrans = true;
  std::string path;
  uint64_t max_request_id = kDefaultInitialMaxRequestId;
  uint64_t max_auth_token_cache_size = kDefaultMaxAuthTokenCacheSize;
  bool support_object_acks = false;
  // TODO(martinduke): Turn authorization_token into structured data.
  std::vector<AuthToken> authorization_token;
  std::string authority;
  std::string moqt_implementation;

  // Takes the relevant fields from this object and populates |out| if not the
  // protocol default value.
  void ToSetupParameters(SetupParameters& out) const;
};

// The maximum length of a message, excluding any OBJECT payload. This prevents
// DoS attack via forcing the parser to buffer a large message (OBJECT payloads
// are not buffered by the parser).
inline constexpr size_t kMaxMessageHeaderSize = 2048;

class QUICHE_EXPORT MoqtDataStreamType {
 public:
  static constexpr uint64_t kFetch = 0x05;
  static constexpr uint64_t kPadding = 0x26d3;
  static constexpr uint64_t kSubgroup = 0x10;
  static constexpr uint64_t kExtensions = 0x01;
  static constexpr uint64_t kEndOfGroup = 0x08;
  static constexpr uint64_t kDefaultPriority = 0x20;
  // These two cannot simultaneously be true;
  static constexpr uint64_t kFirstObjectId = 0x02;
  static constexpr uint64_t kSubgroupId = 0x04;

  // Factory functions.
  static std::optional<MoqtDataStreamType> FromValue(uint64_t value) {
    MoqtDataStreamType stream_type(value);
    if (stream_type.IsFetch() || stream_type.IsPadding()) {
      return stream_type;
    }
    if (!(value & kSubgroup)) {
      return std::nullopt;
    }
    if (value > (kSubgroup | kExtensions | kEndOfGroup | kDefaultPriority |
                 kFirstObjectId | kSubgroupId)) {
      // Reserved bits.
      return std::nullopt;
    }
    if ((value & kSubgroupId) && (value & kFirstObjectId)) {
      return std::nullopt;
    }
    return stream_type;
  }
  static MoqtDataStreamType Fetch() { return MoqtDataStreamType(kFetch); }
  static MoqtDataStreamType Padding() { return MoqtDataStreamType(kPadding); }
  static MoqtDataStreamType Subgroup(uint64_t subgroup_id,
                                     uint64_t first_object_id,
                                     bool no_extension_headers,
                                     bool default_priority,
                                     bool end_of_group = false) {
    uint64_t value = kSubgroup;
    if (!no_extension_headers) {
      value |= kExtensions;
    }
    if (end_of_group) {
      value |= kEndOfGroup;
    }
    if (default_priority) {
      value |= kDefaultPriority;
    }
    if (subgroup_id == 0) {
      return MoqtDataStreamType(value);
    }
    if (subgroup_id == first_object_id) {
      value |= kFirstObjectId;
    } else {
      value |= kSubgroupId;
    }
    return MoqtDataStreamType(value);
  }
  MoqtDataStreamType(const MoqtDataStreamType& other) = default;
  bool IsFetch() const { return value_ == kFetch; }
  bool IsPadding() const { return value_ == kPadding; }
  bool IsSubgroup() const { return value_ & kSubgroup; }
  bool IsSubgroupPresent() const {
    return IsSubgroup() && (value_ & kSubgroupId);
  }
  bool SubgroupIsZero() const {
    return IsSubgroup() && !(value_ & (kSubgroupId | kFirstObjectId));
  }
  bool SubgroupIsFirstObjectId() const {
    return IsSubgroup() && (value_ & kFirstObjectId);
  }
  bool AreExtensionHeadersPresent() const {
    return IsSubgroup() && (value_ & kExtensions);
  }
  bool EndOfGroupInStream() const {
    return IsSubgroup() && (value_ & kEndOfGroup);
  }
  bool HasDefaultPriority() const {
    return IsSubgroup() && (value_ & kDefaultPriority);
  }

  uint64_t value() const { return value_; }
  bool operator==(const MoqtDataStreamType& other) const = default;

 private:
  explicit MoqtDataStreamType(uint64_t value) : value_(value) {}
  const uint64_t value_;
};

class QUICHE_EXPORT MoqtDatagramType {
 public:
  static constexpr uint64_t kExtensions = 0x01;
  static constexpr uint64_t kEndOfGroup = 0x02;
  static constexpr uint64_t kZeroObjectId = 0x04;
  static constexpr uint64_t kDefaultPriority = 0x08;
  static constexpr uint64_t kStatus = 0x20;
  // The arguments here are properties of the object. The constructor creates
  // the appropriate type given those properties and the spec restrictions.
  MoqtDatagramType(bool payload, bool extension, bool end_of_group,
                   bool default_priority, bool zero_object_id)
      : value_(0) {
    // Avoid illegal types. Status cannot coexist with the zero-object-id flag
    // or the end-of-group flag.
    if (!payload && !end_of_group) {
      // The only way to express non-normal, non-end-of-group with no payload is
      // with an explicit status, so we cannot utilize object ID compression.
      zero_object_id = false;
    } else if (zero_object_id) {
      // zero-object-id saves a byte; no-payload does not.
      payload = true;
    } else if (!payload) {
      // If it's an empty end-of-group object, use the explict status because
      // it's more readable.
      end_of_group = false;
    }
    if (extension) {
      value_ |= kExtensions;
    }
    if (end_of_group) {
      value_ |= kEndOfGroup;
    }
    if (zero_object_id) {
      value_ |= kZeroObjectId;
    }
    if (default_priority) {
      value_ |= kDefaultPriority;
    }
    if (!payload) {
      value_ |= kStatus;
    }
  }
  static std::optional<MoqtDatagramType> FromValue(uint64_t value) {
    if (value > (kExtensions | kEndOfGroup | kZeroObjectId | kDefaultPriority |
                 kStatus)) {
      return std::nullopt;
    }
    if ((value & kStatus) && (value & kEndOfGroup)) {
      return std::nullopt;
    }
    return MoqtDatagramType(value);
  }
  bool has_status() const { return value_ & kStatus; }
  bool has_default_priority() const { return value_ & kDefaultPriority; }
  bool has_object_id() const { return !(value_ & kZeroObjectId); }
  bool end_of_group() const { return value_ & kEndOfGroup; }
  bool has_extension() const { return value_ & kExtensions; }
  uint64_t value() const { return value_; }

  bool operator==(const MoqtDatagramType& other) const = default;

 private:
  uint64_t value_;
  explicit MoqtDatagramType(uint64_t value) : value_(value) {}
};

enum class QUICHE_EXPORT MoqtMessageType : uint64_t {
  kRequestUpdate = 0x02,
  kSubscribe = 0x03,
  kSubscribeOk = 0x04,
  kRequestError = 0x05,
  kPublishNamespace = 0x06,
  kRequestOk = 0x07,
  kNamespace = 0x08,
  kPublishNamespaceDone = 0x09,
  kUnsubscribe = 0x0a,
  kPublishDone = 0x0b,
  kPublishNamespaceCancel = 0x0c,
  kTrackStatus = 0x0d,
  kNamespaceDone = 0x0e,
  kGoAway = 0x10,
  kSubscribeNamespace = 0x11,
  kMaxRequestId = 0x15,
  kFetch = 0x16,
  kFetchCancel = 0x17,
  kFetchOk = 0x18,
  kRequestsBlocked = 0x1a,
  kPublish = 0x1d,
  kPublishOk = 0x1e,
  kClientSetup = 0x20,
  kServerSetup = 0x21,

  // QUICHE-specific extensions.

  // kObjectAck (OACK for short) is a frame used by the receiver indicating that
  // it has received and processed the specified object.
  kObjectAck = 0x3184,
};

// A tuple uniquely identifying a WebTransport data stream associated with a
// subscription. By convention, if a DataStreamIndex is necessary for a datagram
// track, `subgroup` is set to zero.
struct DataStreamIndex {
  uint64_t group = 0;
  uint64_t subgroup = 0;

  DataStreamIndex() = default;
  DataStreamIndex(uint64_t group, uint64_t subgroup)
      : group(group), subgroup(subgroup) {}

  auto operator<=>(const DataStreamIndex&) const = default;

  template <typename H>
  friend H AbslHashValue(H h, const DataStreamIndex& index) {
    return H::combine(std::move(h), index.group, index.subgroup);
  }
};

struct SubgroupPriority {
  uint8_t publisher_priority = 0xf0;
  uint64_t subgroup_id = 0;

  auto operator<=>(const SubgroupPriority&) const = default;
};

template <typename H>
H AbslHashValue(H h, const Location& m) {
  return H::combine(std::move(h), m.group, m.object);
}

// TODO(martinduke): Collapse both Setup messages into SetupParameters.
struct QUICHE_EXPORT MoqtClientSetup {
  SetupParameters parameters;
};

struct QUICHE_EXPORT MoqtServerSetup {
  SetupParameters parameters;
};

// These codes do not appear on the wire.
enum class QUICHE_EXPORT MoqtForwardingPreference : uint8_t {
  kSubgroup,
  kDatagram,
};

enum class QUICHE_EXPORT MoqtObjectStatus : uint64_t {
  kNormal = 0x0,
  kObjectDoesNotExist = 0x1,
  kEndOfGroup = 0x3,
  kEndOfTrack = 0x4,
  kInvalidObjectStatus = 0x5,
};

MoqtObjectStatus IntegerToObjectStatus(uint64_t integer);

// The data contained in every Object message, although the message type
// implies some of the values.
struct QUICHE_EXPORT MoqtObject {
  uint64_t track_alias;  // For FETCH, this is the subscribe ID.
  uint64_t group_id;
  uint64_t object_id;
  MoqtPriority publisher_priority;
  std::string extension_headers;  // Raw, unparsed extension headers.
  MoqtObjectStatus object_status;
  uint64_t subgroup_id;
  uint64_t payload_length;
};

struct QUICHE_EXPORT MoqtRequestError {
  uint64_t request_id;
  RequestErrorCode error_code;
  std::optional<quic::QuicTimeDelta> retry_interval;
  std::string reason_phrase;
};

struct QUICHE_EXPORT MoqtSubscribe {
  MoqtSubscribe() = default;
  MoqtSubscribe(uint64_t request_id, FullTrackName full_track_name,
                MessageParameters parameters)
      : request_id(request_id),
        full_track_name(full_track_name),
        parameters(parameters) {}
  uint64_t request_id;
  FullTrackName full_track_name;
  MessageParameters parameters;
};

struct QUICHE_EXPORT MoqtSubscribeOk {
  uint64_t request_id;
  uint64_t track_alias;
  MessageParameters parameters;
  TrackExtensions extensions;
};

struct QUICHE_EXPORT MoqtUnsubscribe {
  uint64_t request_id;
};

enum class QUICHE_EXPORT PublishDoneCode : uint64_t {
  kInternalError = 0x0,
  kUnauthorized = 0x1,
  kTrackEnded = 0x2,
  kSubscriptionEnded = 0x3,
  kGoingAway = 0x4,
  kExpired = 0x5,
  kTooFarBehind = 0x6,
  kMalformedTrack = 0x7,
};

struct QUICHE_EXPORT MoqtPublishDone {
  uint64_t request_id;
  PublishDoneCode status_code;
  uint64_t stream_count;
  std::string error_reason;
};

struct QUICHE_EXPORT MoqtRequestUpdate {
  uint64_t request_id;
  uint64_t existing_request_id;
  MessageParameters parameters;
};

struct QUICHE_EXPORT MoqtPublishNamespace {
  uint64_t request_id;
  TrackNamespace track_namespace;
  VersionSpecificParameters parameters;
};

struct QUICHE_EXPORT MoqtRequestOk {
  uint64_t request_id;
  MessageParameters parameters;
};

struct QUICHE_EXPORT MoqtPublishNamespaceDone {
  TrackNamespace track_namespace;
};

struct QUICHE_EXPORT MoqtPublishNamespaceCancel {
  TrackNamespace track_namespace;
  RequestErrorCode error_code;
  std::string error_reason;
};

struct QUICHE_EXPORT MoqtTrackStatus : public MoqtSubscribe {
  MoqtTrackStatus() = default;
  MoqtTrackStatus(MoqtSubscribe subscribe) : MoqtSubscribe(subscribe) {}
};

struct QUICHE_EXPORT MoqtGoAway {
  std::string new_session_uri;
};

enum class QUICHE_EXPORT SubscribeNamespaceOption : uint64_t {
  kPublish = 0x00,
  kNamespace = 0x01,
  kBoth = 0x02,
};
static constexpr uint64_t kMaxSubscribeOption = 0x02;

struct QUICHE_EXPORT MoqtSubscribeNamespace {
  uint64_t request_id;
  TrackNamespace track_namespace_prefix;
  SubscribeNamespaceOption subscribe_options;
  MessageParameters parameters;
};

struct QUICHE_EXPORT MoqtNamespace {
  TrackNamespace track_namespace_suffix;
};

struct QUICHE_EXPORT MoqtNamespaceDone {
  TrackNamespace track_namespace_suffix;
};

struct QUICHE_EXPORT MoqtMaxRequestId {
  uint64_t max_request_id;
};

enum class QUICHE_EXPORT FetchType : uint64_t {
  kStandalone = 0x1,
  kRelativeJoining = 0x2,
  kAbsoluteJoining = 0x3,
};

struct StandaloneFetch {
  StandaloneFetch() = default;
  StandaloneFetch(FullTrackName full_track_name, Location start_location,
                  Location end_location)
      : full_track_name(full_track_name),
        start_location(start_location),
        end_location(end_location) {}
  FullTrackName full_track_name;
  Location start_location;
  Location end_location;
  bool operator==(const StandaloneFetch& other) const {
    return full_track_name == other.full_track_name &&
           start_location == other.start_location &&
           end_location == other.end_location;
  }
  bool operator!=(const StandaloneFetch& other) const {
    return !(*this == other);
  }
};

struct JoiningFetchRelative {
  JoiningFetchRelative(uint64_t joining_request_id, uint64_t joining_start)
      : joining_request_id(joining_request_id), joining_start(joining_start) {}
  uint64_t joining_request_id;
  uint64_t joining_start;
  bool operator==(const JoiningFetchRelative& other) const {
    return joining_request_id == other.joining_request_id &&
           joining_start == other.joining_start;
  }
  bool operator!=(const JoiningFetchRelative& other) const {
    return !(*this == other);
  }
};

struct JoiningFetchAbsolute {
  JoiningFetchAbsolute(uint64_t joining_request_id, uint64_t joining_start)
      : joining_request_id(joining_request_id), joining_start(joining_start) {}
  uint64_t joining_request_id;
  uint64_t joining_start;
  bool operator==(const JoiningFetchAbsolute& other) const {
    return joining_request_id == other.joining_request_id &&
           joining_start == other.joining_start;
  }
  bool operator!=(const JoiningFetchAbsolute& other) const {
    return !(*this == other);
  }
};

struct QUICHE_EXPORT MoqtFetch {
  uint64_t request_id;
  MoqtPriority subscriber_priority;
  std::optional<MoqtDeliveryOrder> group_order;
  std::variant<StandaloneFetch, JoiningFetchRelative, JoiningFetchAbsolute>
      fetch;
  VersionSpecificParameters parameters;
};

struct QUICHE_EXPORT MoqtFetchOk {
  uint64_t request_id;
  MoqtDeliveryOrder group_order;
  bool end_of_track;
  Location end_location;
  VersionSpecificParameters parameters;
};

struct QUICHE_EXPORT MoqtFetchCancel {
  uint64_t request_id;
};

struct QUICHE_EXPORT MoqtRequestsBlocked {
  uint64_t max_request_id;
};

struct QUICHE_EXPORT MoqtPublish {
  uint64_t request_id;
  FullTrackName full_track_name;
  uint64_t track_alias;
  MoqtDeliveryOrder group_order;
  std::optional<Location> largest_location;
  bool forward;
  VersionSpecificParameters parameters;
};

struct QUICHE_EXPORT MoqtPublishOk {
  uint64_t request_id;
  bool forward;
  MoqtPriority subscriber_priority;
  MoqtDeliveryOrder group_order;
  MoqtFilterType filter_type;
  std::optional<Location> start;
  std::optional<uint64_t> end_group;
  VersionSpecificParameters parameters;
};

// All of the four values in this message are encoded as varints.
// `delta_from_deadline` is encoded as an absolute value, with the lowest bit
// indicating the sign (0 if positive).
struct QUICHE_EXPORT MoqtObjectAck {
  uint64_t subscribe_id;
  uint64_t group_id;
  uint64_t object_id;
  // Positive if the object has been received before the deadline.
  quic::QuicTimeDelta delta_from_deadline = quic::QuicTimeDelta::Zero();
};

// Returns false if the parameters cannot be in |message type|.
MoqtError SetupParametersAllowedByMessage(const SetupParameters& parameters,
                                          MoqtMessageType message_type,
                                          bool webtrans);
// Returns false if the parameters cannot be in |message type|.
bool VersionSpecificParametersAllowedByMessage(
    const VersionSpecificParameters& parameters, MoqtMessageType message_type);

std::string MoqtMessageTypeToString(MoqtMessageType message_type);
std::string MoqtDataStreamTypeToString(MoqtDataStreamType type);
std::string MoqtDatagramTypeToString(MoqtDatagramType type);

std::string MoqtForwardingPreferenceToString(
    MoqtForwardingPreference preference);

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_MOQT_MESSAGES_H_
