// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/web_transport_http3.h"

#include <cstdint>
#include <limits>

#include "absl/types/optional.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace {

using ::testing::Optional;

TEST(WebTransportHttp3Test, ErrorCodesToHttp3) {
  EXPECT_EQ(0x52e4a40fa8dbu, WebTransportErrorToHttp3(0x00));
  EXPECT_EQ(0x52e4a40fa9e2u, WebTransportErrorToHttp3(0xff));

  EXPECT_EQ(0x52e4a40fa8f7u, WebTransportErrorToHttp3(0x1c));
  EXPECT_EQ(0x52e4a40fa8f8u, WebTransportErrorToHttp3(0x1d));
  //        0x52e4a40fa8f9 is a GREASE codepoint
  EXPECT_EQ(0x52e4a40fa8fau, WebTransportErrorToHttp3(0x1e));
}

TEST(WebTransportHttp3Test, ErrorCodesToWebTransport) {
  EXPECT_THAT(Http3ErrorToWebTransport(0x52e4a40fa8db), Optional(0x00));
  EXPECT_THAT(Http3ErrorToWebTransport(0x52e4a40fa9e2), Optional(0xff));

  EXPECT_THAT(Http3ErrorToWebTransport(0x52e4a40fa8f7), Optional(0x1cu));
  EXPECT_THAT(Http3ErrorToWebTransport(0x52e4a40fa8f8), Optional(0x1du));
  EXPECT_THAT(Http3ErrorToWebTransport(0x52e4a40fa8f9), absl::nullopt);
  EXPECT_THAT(Http3ErrorToWebTransport(0x52e4a40fa8fa), Optional(0x1eu));

  EXPECT_EQ(Http3ErrorToWebTransport(0), absl::nullopt);
  EXPECT_EQ(Http3ErrorToWebTransport(std::numeric_limits<uint64_t>::max()),
            absl::nullopt);
}

TEST(WebTransportHttp3Test, ErrorCodeRoundTrip) {
  for (int error = 0; error < 256; error++) {
    uint64_t http_error = WebTransportErrorToHttp3(error);
    absl::optional<WebTransportStreamError> mapped_back =
        quic::Http3ErrorToWebTransport(http_error);
    EXPECT_THAT(mapped_back, Optional(error));
  }
}

}  // namespace
}  // namespace quic
