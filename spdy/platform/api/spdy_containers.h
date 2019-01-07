// Copyright (c) 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_SPDY_PLATFORM_API_SPDY_CONTAINERS_H_
#define QUICHE_SPDY_PLATFORM_API_SPDY_CONTAINERS_H_

#include "net/spdy/platform/impl/spdy_containers_impl.h"

namespace spdy {

template <typename KeyType>
using SpdyHash = SpdyHashImpl<KeyType>;

// SpdyHashMap does not guarantee pointer stability.
template <typename KeyType,
          typename ValueType,
          typename Hash = SpdyHash<KeyType>>
using SpdyHashMap = SpdyHashMapImpl<KeyType, ValueType, Hash>;

// SpdyHashSet does not guarantee pointer stability.
template <typename ElementType, typename Hasher, typename Eq>
using SpdyHashSet = SpdyHashSetImpl<ElementType, Hasher, Eq>;

}  // namespace spdy

#endif  // QUICHE_SPDY_PLATFORM_API_SPDY_CONTAINERS_H_
