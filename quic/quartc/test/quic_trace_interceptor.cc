// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/quartc/test/quic_trace_interceptor.h"

#include <string>

#include "net/third_party/quiche/src/quic/core/quic_error_codes.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_string_piece.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test_output.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_endpoint.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_session.h"

namespace quic {
namespace test {

QuicTraceInterceptor::QuicTraceInterceptor(QuicStringPiece identifier)
    : identifier_(identifier.data(), identifier.size()), delegate_(nullptr) {}

QuicTraceInterceptor::~QuicTraceInterceptor() {
  if (trace_visitor_) {
    QuicRecordTestOutput(identifier_,
                         trace_visitor_->trace()->SerializeAsString());
  }
}

void QuicTraceInterceptor::OnSessionCreated(QuartcSession* session) {
  trace_visitor_ = QuicMakeUnique<QuicTraceVisitor>(session->connection());
  session->connection()->set_debug_visitor(trace_visitor_.get());

  delegate_->OnSessionCreated(session);
}

void QuicTraceInterceptor::OnConnectError(QuicErrorCode error,
                                          const std::string& details) {
  delegate_->OnConnectError(error, details);
}

void QuicTraceInterceptor::SetDelegate(QuartcEndpoint::Delegate* delegate) {
  DCHECK(delegate != nullptr);
  delegate_ = delegate;
}

}  // namespace test
}  // namespace quic
