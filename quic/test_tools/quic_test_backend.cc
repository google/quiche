// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/test_tools/quic_test_backend.h"

namespace quic {
namespace test {

QuicSimpleServerBackend::WebTransportResponse
QuicTestBackend::ProcessWebTransportRequest(
    const spdy::Http2HeaderBlock& request_headers) {
  if (!SupportsWebTransport()) {
    return QuicSimpleServerBackend::ProcessWebTransportRequest(request_headers);
  }

  WebTransportResponse response;
  response.response_headers[":status"] = "200";
  return response;
}

}  // namespace test
}  // namespace quic
