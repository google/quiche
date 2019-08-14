// Copyright (c) 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Utility methods to convert between absolute indexing (used in the dynamic
// table), relative indexing used on the encoder stream, and relative indexing
// and post-base indexing used on request streams (in header blocks).  See:
// https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#indexing
// https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#relative-indexing
// https://quicwg.org/base-drafts/draft-ietf-quic-qpack.html#post-base

#ifndef QUICHE_QUIC_CORE_QPACK_QPACK_INDEX_CONVERSIONS_H_
#define QUICHE_QUIC_CORE_QPACK_QPACK_INDEX_CONVERSIONS_H_

#include <cstdint>

namespace quic {

// Conversion functions used in the encoder do not check for overflow/underflow.
// Since the maximum index is limited by maximum dynamic table capacity
// (represented on uint64_t) divided by minimum header field size (defined to be
// 32 bytes), overflow is not possible.  The caller is responsible for providing
// input that does not underflow.

uint64_t QpackAbsoluteIndexToEncoderStreamRelativeIndex(
    uint64_t absolute_index,
    uint64_t inserted_entry_count);

uint64_t QpackAbsoluteIndexToRequestStreamRelativeIndex(uint64_t absolute_index,
                                                        uint64_t base);

// Conversion functions used in the decoder operate on input received from the
// network.  These functions return false on overflow or underflow.

// TODO The encoder stream uses relative index (but different from the kind of
// relative index used on a request stream).  This method converts relative
// index to absolute index (zero based).  It returns true on success, or false
// if conversion fails due to overflow/underflow.

bool QpackEncoderStreamRelativeIndexToAbsoluteIndex(
    uint64_t relative_index,
    uint64_t inserted_entry_count,
    uint64_t* absolute_index);

// TODO The request stream can use relative index (but different from the kind
// of relative index used on the encoder stream), and post-base index. These
// methods convert relative index and post-base index to absolute index (one
// based).  They return true on success, or false if conversion fails due to
// overflow/underflow.

// On success, |*absolute_index| is guaranteed to be strictly less than
// std::numeric_limits<uint64_t>::max().
bool QpackRequestStreamRelativeIndexToAbsoluteIndex(uint64_t relative_index,
                                                    uint64_t base,
                                                    uint64_t* absolute_index);

// On success, |*absolute_index| is guaranteed to be strictly less than
// std::numeric_limits<uint64_t>::max().
bool QpackPostBaseIndexToAbsoluteIndex(uint64_t post_base_index,
                                       uint64_t base,
                                       uint64_t* absolute_index);

}  // namespace quic

#endif  // QUICHE_QUIC_CORE_QPACK_QPACK_INDEX_CONVERSIONS_H_
