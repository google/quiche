#include "http2/adapter/header_validator.h"

#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "common/platform/api/quiche_logging.h"

namespace http2 {
namespace adapter {

namespace {

const absl::string_view kHttp2HeaderNameAllowedChars =
    "!#$%&\'*+-.0123456789"
    "^_`abcdefghijklmnopqrstuvwxyz|~";

const absl::string_view kHttp2HeaderValueAllowedChars =
    "\t "
    "!\"#$%&'()*+,-./"
    "0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`"
    "abcdefghijklmnopqrstuvwxyz{|}~";

const absl::string_view kHttp2StatusValueAllowedChars = "0123456789";

const absl::string_view kValidAuthorityChars =
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~%!$&'()["
    "]*+,;=:";

// Returns whether `authority` contains only characters from the `host` ABNF
// from RFC 3986 section 3.2.2.
bool IsValidAuthority(absl::string_view authority) {
  static const bool* valid_chars = []() {
    using ValidCharArray = bool[256];
    bool* chars = new ValidCharArray;
    memset(chars, 0, sizeof(ValidCharArray));
    for (char c : kValidAuthorityChars) {
      chars[static_cast<uint8_t>(c)] = true;
    }
    return chars;
  }();
  for (char c : authority) {
    if (!valid_chars[static_cast<uint8_t>(c)]) {
      return false;
    }
  }
  return true;
}

bool ValidateRequestHeaders(const std::vector<std::string>& pseudo_headers,
                            absl::string_view method, absl::string_view path,
                            bool allow_connect) {
  QUICHE_VLOG(2) << "Request pseudo-headers: ["
                 << absl::StrJoin(pseudo_headers, ", ")
                 << "], allow_connect: " << allow_connect
                 << ", method: " << method << ", path: " << path;
  if (allow_connect && method == "CONNECT") {
    static const std::vector<std::string>* kConnectHeaders =
        new std::vector<std::string>(
            {":authority", ":method", ":path", ":protocol", ":scheme"});
    return pseudo_headers == *kConnectHeaders;
  }

  if (path.empty()) {
    return false;
  }
  if (path == "*") {
    if (method != "OPTIONS") {
      return false;
    }
  } else if (path[0] != '/') {
    return false;
  }

  static const std::vector<std::string>* kRequiredHeaders =
      new std::vector<std::string>(
          {":authority", ":method", ":path", ":scheme"});
  return pseudo_headers == *kRequiredHeaders;
}

bool ValidateRequestTrailers(const std::vector<std::string>& pseudo_headers) {
  return pseudo_headers.empty();
}

bool ValidateResponseHeaders(const std::vector<std::string>& pseudo_headers) {
  static const std::vector<std::string>* kRequiredHeaders =
      new std::vector<std::string>({":status"});
  return pseudo_headers == *kRequiredHeaders;
}

bool ValidateResponseTrailers(const std::vector<std::string>& pseudo_headers) {
  return pseudo_headers.empty();
}

}  // namespace

void HeaderValidator::StartHeaderBlock() {
  pseudo_headers_.clear();
  status_.clear();
  method_.clear();
  path_.clear();
  content_length_.reset();
}

HeaderValidator::HeaderStatus HeaderValidator::ValidateSingleHeader(
    absl::string_view key, absl::string_view value) {
  if (key.empty()) {
    return HEADER_FIELD_INVALID;
  }
  if (max_field_size_.has_value() &&
      key.size() + value.size() > max_field_size_.value()) {
    QUICHE_VLOG(2) << "Header field size is " << key.size() + value.size()
                   << ", exceeds max size of " << max_field_size_.value();
    return HEADER_FIELD_TOO_LONG;
  }
  const absl::string_view validated_key = key[0] == ':' ? key.substr(1) : key;
  if (validated_key.find_first_not_of(kHttp2HeaderNameAllowedChars) !=
      absl::string_view::npos) {
    QUICHE_VLOG(2) << "invalid chars in header name: ["
                   << absl::CEscape(validated_key) << "]";
    return HEADER_FIELD_INVALID;
  }
  if (value.find_first_not_of(kHttp2HeaderValueAllowedChars) !=
      absl::string_view::npos) {
    QUICHE_VLOG(2) << "invalid chars in header value: [" << absl::CEscape(value)
                   << "]";
    return HEADER_FIELD_INVALID;
  }
  if (key[0] == ':') {
    if (key == ":status") {
      if (value.size() != 3 ||
          value.find_first_not_of(kHttp2StatusValueAllowedChars) !=
              absl::string_view::npos) {
        QUICHE_VLOG(2) << "malformed status value: [" << absl::CEscape(value)
                       << "]";
        return HEADER_FIELD_INVALID;
      }
      if (value == "101") {
        // Switching protocols is not allowed on a HTTP/2 stream.
        return HEADER_FIELD_INVALID;
      }
      status_ = std::string(value);
    } else if (key == ":method") {
      method_ = std::string(value);
    } else if (key == ":authority" && !IsValidAuthority(value)) {
      return HEADER_FIELD_INVALID;
    } else if (key == ":path") {
      if (value.empty()) {
        // For now, reject an empty path regardless of scheme.
        return HEADER_FIELD_INVALID;
      }
      path_ = std::string(value);
    }
    pseudo_headers_.push_back(std::string(key));
  } else if (key == "content-length") {
    const bool success = HandleContentLength(value);
    if (!success) {
      return HEADER_FIELD_INVALID;
    }
  } else if (key == "te" && value != "trailers") {
    return HEADER_FIELD_INVALID;
  }
  return HEADER_OK;
}

// Returns true if all required pseudoheaders and no extra pseudoheaders are
// present for the given header type.
bool HeaderValidator::FinishHeaderBlock(HeaderType type) {
  std::sort(pseudo_headers_.begin(), pseudo_headers_.end());
  switch (type) {
    case HeaderType::REQUEST:
      return ValidateRequestHeaders(pseudo_headers_, method_, path_,
                                    allow_connect_);
    case HeaderType::REQUEST_TRAILER:
      return ValidateRequestTrailers(pseudo_headers_);
    case HeaderType::RESPONSE_100:
    case HeaderType::RESPONSE:
      return ValidateResponseHeaders(pseudo_headers_);
    case HeaderType::RESPONSE_TRAILER:
      return ValidateResponseTrailers(pseudo_headers_);
  }
  return false;
}

bool HeaderValidator::HandleContentLength(absl::string_view value) {
  if (value.empty()) {
    return false;
  }

  if (status_ == "204" && value != "0") {
    // There should be no body in a "204 No Content" response.
    return false;
  }
  if (!status_.empty() && status_[0] == '1' && value != "0") {
    // There should also be no body in a 1xx response.
    return false;
  }

  size_t content_length = 0;
  const bool valid = absl::SimpleAtoi(value, &content_length);
  if (!valid) {
    return false;
  }

  content_length_ = content_length;
  return true;
}

}  // namespace adapter
}  // namespace http2
