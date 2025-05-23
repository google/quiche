// Copyright (c) 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_PLATFORM_API_QUIC_SOCKET_ADDRESS_H_
#define QUICHE_QUIC_PLATFORM_API_QUIC_SOCKET_ADDRESS_H_

#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/common/quiche_socket_address.h"

namespace quic {

using QuicSocketAddress = ::quiche::QuicheSocketAddress;
using QuicSocketAddressHash = ::quiche::QuicheSocketAddressHash;

}  // namespace quic

#endif  // QUICHE_QUIC_PLATFORM_API_QUIC_SOCKET_ADDRESS_H_
