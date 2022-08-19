// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TOOLS_QUIC_NAME_LOOKUP_H_
#define QUICHE_QUIC_TOOLS_QUIC_NAME_LOOKUP_H_

#include <string>

#include "quiche/quic/platform/api/quic_socket_address.h"

namespace quic::tools {

quic::QuicSocketAddress LookupAddress(int address_family_for_lookup,
                                      std::string host, std::string port);

inline QuicSocketAddress LookupAddress(std::string host, std::string port) {
  return LookupAddress(0, host, port);
}

}  // namespace quic::tools

#endif  // QUICHE_QUIC_TOOLS_QUIC_NAME_LOOKUP_H_
