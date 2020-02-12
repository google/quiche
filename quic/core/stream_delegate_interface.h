// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_CORE_STREAM_DELEGATE_INTERFACE_H_
#define QUICHE_QUIC_CORE_STREAM_DELEGATE_INTERFACE_H_

#include "net/third_party/quiche/src/quic/core/quic_types.h"

namespace quic {

class QUIC_EXPORT_PRIVATE StreamDelegateInterface {
 public:
  virtual ~StreamDelegateInterface() {}

  // Called when the stream has encountered errors that it can't handle.
  virtual void OnStreamError(QuicErrorCode error_code,
                             std::string error_details) = 0;
};

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_STREAM_DELEGATE_INTERFACE_H_
