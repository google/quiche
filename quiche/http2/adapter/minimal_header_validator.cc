#include "quiche/http2/adapter/minimal_header_validator.h"

#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/header_validator_base.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace http2 {
namespace adapter {

namespace {

constexpr absl::string_view kInvalidChars("\0\r\n", 3);

}  // namespace

void MinimalHeaderValidator::StartHeaderBlock() {
  HeaderValidatorBase::StartHeaderBlock();
  has_method_ = false;
  has_scheme_ = false;
  has_path_ = false;
}

HeaderValidatorBase::HeaderStatus MinimalHeaderValidator::ValidateSingleHeader(
    absl::string_view key, absl::string_view value) {
  if (key.empty()) {
    return HEADER_FIELD_INVALID;
  }
  if (key.find_first_of(kInvalidChars) != absl::string_view::npos ||
      value.find_first_of(kInvalidChars) != absl::string_view::npos) {
    return HEADER_FIELD_INVALID;
  }
  if (key[0] != ':') {
    return HEADER_OK;
  }
  if (key == ":status") {
    status_ = std::string(value);
  } else if (key == ":method") {
    has_method_ = true;
  } else if (key == ":scheme") {
    has_scheme_ = true;
  } else if (key == ":path") {
    has_path_ = true;
  }
  return HEADER_OK;
}

bool MinimalHeaderValidator::FinishHeaderBlock(HeaderType type) {
  if (type == HeaderType::REQUEST) {
    return has_method_ && has_scheme_ && has_path_;
  } else if (type == HeaderType::RESPONSE || type == HeaderType::RESPONSE_100) {
    return !status_.empty();
  }
  return true;
}

}  // namespace adapter
}  // namespace http2
