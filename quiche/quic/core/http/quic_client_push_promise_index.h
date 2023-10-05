// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_HTTP_QUIC_CLIENT_PUSH_PROMISE_INDEX_H_
#define QUICHE_QUIC_CORE_HTTP_QUIC_CLIENT_PUSH_PROMISE_INDEX_H_

#include "quiche/quic/core/http/quic_spdy_client_session_base.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_export.h"
#include "quiche/spdy/core/http2_header_block.h"

namespace quic {

// TODO(b/171463363): Remove.
class QUICHE_EXPORT QuicClientPushPromiseIndex {};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_QUIC_CLIENT_PUSH_PROMISE_INDEX_H_
