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
class QUICHE_EXPORT QuicClientPushPromiseIndex {
 public:
  // Delegate is used to complete the rendezvous that began with
  // |Try()|.
  class QUICHE_EXPORT Delegate {
   public:
    virtual ~Delegate() {}

    // The primary lookup matched request with push promise by URL.  A
    // secondary match is necessary to ensure Vary (RFC 2616, 14.14)
    // is honored.  If Vary is not present, return true.  If Vary is
    // present, return whether designated header fields of
    // |promise_request| and |client_request| match.
    virtual bool CheckVary(const spdy::Http2HeaderBlock& client_request,
                           const spdy::Http2HeaderBlock& promise_request,
                           const spdy::Http2HeaderBlock& promise_response) = 0;

    // On rendezvous success, provides the promised |stream|.  Callee
    // does not inherit ownership of |stream|.  On rendezvous failure,
    // |stream| is |nullptr| and the client should retry the request.
    // Rendezvous can fail due to promise validation failure or RST on
    // promised stream.  |url| will have been removed from the index
    // before |OnRendezvousResult()| is invoked, so a recursive call to
    // |Try()| will return |QUIC_FAILURE|, which may be convenient for
    // retry purposes.
    virtual void OnRendezvousResult(QuicSpdyStream* stream) = 0;
  };
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_HTTP_QUIC_CLIENT_PUSH_PROMISE_INDEX_H_
