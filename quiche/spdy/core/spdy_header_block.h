// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_SPDY_CORE_SPDY_HEADER_BLOCK_H_
#define QUICHE_SPDY_CORE_SPDY_HEADER_BLOCK_H_

#include "quiche/spdy/core/http2_header_block.h"

namespace spdy {

// TODO(b/156770486): Remove this alias when the rename is complete.
using SpdyHeaderBlock = Http2HeaderBlock;

}  // namespace spdy

#endif  // QUICHE_SPDY_CORE_SPDY_HEADER_BLOCK_H_
