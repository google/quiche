#include "http2/adapter/test_utils.h"

#include "spdy/core/spdy_frame_reader.h"

namespace http2 {
namespace adapter {
namespace test {
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
