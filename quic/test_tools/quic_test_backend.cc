// Copyright (c) 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/test_tools/quic_test_backend.h"

#include <cstring>
#include <memory>

#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quic/core/quic_buffer_allocator.h"
#include "quic/core/quic_simple_buffer_allocator.h"
#include "quic/core/web_transport_interface.h"
#include "quic/platform/api/quic_mem_slice.h"
#include "quic/tools/web_transport_test_visitors.h"

namespace quic {
namespace test {

QuicSimpleServerBackend::WebTransportResponse
QuicTestBackend::ProcessWebTransportRequest(
    const spdy::Http2HeaderBlock& request_headers,
    WebTransportSession* session) {
  if (!SupportsWebTransport()) {
    return QuicSimpleServerBackend::ProcessWebTransportRequest(request_headers,
                                                               session);
  }

  auto path_it = request_headers.find(":path");
  if (path_it == request_headers.end()) {
    WebTransportResponse response;
    response.response_headers[":status"] = "400";
    return response;
  }
  absl::string_view path = path_it->second;
  // Match any "/echo.*" pass, e.g. "/echo_foobar"
  if (absl::StartsWith(path, "/echo")) {
    WebTransportResponse response;
    response.response_headers[":status"] = "200";
    // Add response headers if the paramer has "set-header=XXX:YYY" query.
    GURL url = GURL(absl::StrCat("https://localhost", path));
    const std::vector<std::string>& params = absl::StrSplit(url.query(), '&');
    for (const auto& param : params) {
      absl::string_view param_view = param;
      if (absl::ConsumePrefix(&param_view, "set-header=")) {
        const std::vector<absl::string_view> header_value =
            absl::StrSplit(param_view, ':');
        if (header_value.size() == 2 &&
            !absl::StartsWith(header_value[0], ":")) {
          response.response_headers[header_value[0]] = header_value[1];
        }
      }
    }

    response.visitor =
        std::make_unique<EchoWebTransportSessionVisitor>(session);
    return response;
  }

  WebTransportResponse response;
  response.response_headers[":status"] = "404";
  return response;
}

}  // namespace test
}  // namespace quic
