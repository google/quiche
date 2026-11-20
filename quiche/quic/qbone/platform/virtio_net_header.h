// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_QBONE_PLATFORM_VIRTIO_NET_HEADER_H_
#define QUICHE_QUIC_QBONE_PLATFORM_VIRTIO_NET_HEADER_H_

// Provides `struct virtio_net_hdr`, the header that precedes each packet read
// from or written to a TUN device opened with IFF_VNET_HDR.
//
// <linux/virtio_net.h> can't be included from C++ as it is: it also declares
// `struct virtio_net_ctrl_hdr`, which TUN devices don't use and which has a
// member named `class`. So `class` is renamed for the length of the include.
#define class virtio_net_ctrl_hdr_class
#include <linux/virtio_net.h>  // IWYU pragma: export
#undef class

#endif  // QUICHE_QUIC_QBONE_PLATFORM_VIRTIO_NET_HEADER_H_
