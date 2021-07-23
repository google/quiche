#include "http2/adapter/test_utils.h"

#include "common/quiche_endian.h"
#include "spdy/core/spdy_frame_reader.h"

namespace http2 {
namespace adapter {
namespace test {

TestDataFrameSource::TestDataFrameSource(Http2VisitorInterface& visitor,
                                         absl::string_view data_payload,
                                         bool has_fin)
    : visitor_(visitor), has_fin_(has_fin) {
  if (!data_payload.empty()) {
    payload_fragments_.push_back(std::string(data_payload));
    current_fragment_ = payload_fragments_.front();
  }
}

TestDataFrameSource::TestDataFrameSource(
    Http2VisitorInterface& visitor,
    absl::Span<absl::string_view> payload_fragments,
    bool has_fin)
    : visitor_(visitor), has_fin_(has_fin) {
  payload_fragments_.reserve(payload_fragments.size());
  for (absl::string_view fragment : payload_fragments) {
    if (!fragment.empty()) {
      payload_fragments_.push_back(std::string(fragment));
    }
  }
  if (!payload_fragments_.empty()) {
    current_fragment_ = payload_fragments_.front();
  }
}

std::pair<ssize_t, bool> TestDataFrameSource::SelectPayloadLength(
    size_t max_length) {
  if (!is_data_available_) {
    return {kBlocked, false};
  }
  // The stream is done if there's no more data, or if |max_length| is at least
  // as large as the remaining data.
  const bool end_data =
      current_fragment_.empty() || (payload_fragments_.size() == 1 &&
                                    max_length >= current_fragment_.size());
  const ssize_t length = std::min(max_length, current_fragment_.size());
  return {length, end_data};
}

bool TestDataFrameSource::Send(absl::string_view frame_header,
                               size_t payload_length) {
  QUICHE_LOG_IF(DFATAL, payload_length > current_fragment_.size())
      << "payload_length: " << payload_length
      << " current_fragment_size: " << current_fragment_.size();
  const std::string concatenated =
      absl::StrCat(frame_header, current_fragment_.substr(0, payload_length));
  const ssize_t result = visitor_.OnReadyToSend(concatenated);
  if (result < 0) {
    // Write encountered error.
    visitor_.OnConnectionError();
    current_fragment_ = {};
    payload_fragments_.clear();
    return false;
  } else if (result == 0) {
    // Write blocked.
    return false;
  } else if (result < concatenated.size()) {
    // Probably need to handle this better within this test class.
    QUICHE_LOG(DFATAL)
        << "DATA frame not fully flushed. Connection will be corrupt!";
    visitor_.OnConnectionError();
    current_fragment_ = {};
    payload_fragments_.clear();
    return false;
  }
  if (payload_length > 0) {
    current_fragment_.remove_prefix(payload_length);
  }
  if (current_fragment_.empty() && !payload_fragments_.empty()) {
    payload_fragments_.erase(payload_fragments_.begin());
    if (!payload_fragments_.empty()) {
      current_fragment_ = payload_fragments_.front();
    }
  }
  return true;
}

namespace {

using TypeAndOptionalLength =
    std::pair<spdy::SpdyFrameType, absl::optional<size_t>>;

std::vector<std::pair<const char*, std::string>> LogFriendly(
    const std::vector<TypeAndOptionalLength>& types_and_lengths) {
  std::vector<std::pair<const char*, std::string>> out;
  out.reserve(types_and_lengths.size());
  for (const auto type_and_length : types_and_lengths) {
    out.push_back({spdy::FrameTypeToString(type_and_length.first),
                   type_and_length.second
                       ? absl::StrCat(type_and_length.second.value())
                       : "<unspecified>"});
  }
  return out;
}

// Custom gMock matcher, used to implement EqualsFrames().
class SpdyControlFrameMatcher
    : public testing::MatcherInterface<absl::string_view> {
 public:
  explicit SpdyControlFrameMatcher(
      std::vector<TypeAndOptionalLength> types_and_lengths)
      : expected_types_and_lengths_(std::move(types_and_lengths)) {}

  bool MatchAndExplain(absl::string_view s,
                       testing::MatchResultListener* listener) const override {
    spdy::SpdyFrameReader reader(s.data(), s.size());

    for (TypeAndOptionalLength expected : expected_types_and_lengths_) {
      if (!MatchAndExplainOneFrame(expected.first, expected.second, &reader,
                                   listener)) {
        return false;
      }
    }
    if (!reader.IsDoneReading()) {
      size_t bytes_remaining = s.size() - reader.GetBytesConsumed();
      *listener << "; " << bytes_remaining << " bytes left to read!";
      return false;
    }
    return true;
  }

  bool MatchAndExplainOneFrame(spdy::SpdyFrameType expected_type,
                               absl::optional<size_t> expected_length,
                               spdy::SpdyFrameReader* reader,
                               testing::MatchResultListener* listener) const {
    uint32_t payload_length;
    if (!reader->ReadUInt24(&payload_length)) {
      *listener << "; unable to read length field for expected_type "
                << FrameTypeToString(expected_type) << ". data too short!";
      return false;
    }

    if (expected_length && payload_length != expected_length.value()) {
      *listener << "; actual length: " << payload_length
                << " but expected length: " << expected_length.value();
      return false;
    }

    uint8_t raw_type;
    if (!reader->ReadUInt8(&raw_type)) {
      *listener << "; unable to read type field for expected_type "
                << FrameTypeToString(expected_type) << ". data too short!";
      return false;
    }

    if (!spdy::IsDefinedFrameType(raw_type)) {
      *listener << "; expected type " << FrameTypeToString(expected_type)
                << " but raw type " << static_cast<int>(raw_type)
                << " is not a defined frame type!";
      return false;
    }

    spdy::SpdyFrameType actual_type = spdy::ParseFrameType(raw_type);
    if (actual_type != expected_type) {
      *listener << "; actual type: " << FrameTypeToString(actual_type)
                << " but expected type: " << FrameTypeToString(expected_type);
      return false;
    }

    // Seek past flags (1B), stream ID (4B), and payload. Reach the next frame.
    reader->Seek(5 + payload_length);
    return true;
  }

  void DescribeTo(std::ostream* os) const override {
    *os << "Data contains frames of types in sequence "
        << LogFriendly(expected_types_and_lengths_);
  }

  void DescribeNegationTo(std::ostream* os) const override {
    *os << "Data does not contain frames of types in sequence "
        << LogFriendly(expected_types_and_lengths_);
  }

 private:
  const std::vector<TypeAndOptionalLength> expected_types_and_lengths_;
};

}  // namespace

testing::Matcher<absl::string_view> EqualsFrames(
    std::vector<std::pair<spdy::SpdyFrameType, absl::optional<size_t>>>
        types_and_lengths) {
  return MakeMatcher(new SpdyControlFrameMatcher(std::move(types_and_lengths)));
}

testing::Matcher<absl::string_view> EqualsFrames(
    std::vector<spdy::SpdyFrameType> types) {
  std::vector<std::pair<spdy::SpdyFrameType, absl::optional<size_t>>>
      types_and_lengths;
  types_and_lengths.reserve(types.size());
  for (spdy::SpdyFrameType type : types) {
    types_and_lengths.push_back({type, absl::nullopt});
  }
  return MakeMatcher(new SpdyControlFrameMatcher(std::move(types_and_lengths)));
}

}  // namespace test
}  // namespace adapter
}  // namespace http2
