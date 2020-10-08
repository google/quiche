// Copyright 2016 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_HTTP2_HPACK_HUFFMAN_HPACK_HUFFMAN_ENCODER_H_
#define QUICHE_HTTP2_HPACK_HUFFMAN_HPACK_HUFFMAN_ENCODER_H_

// Functions supporting the encoding of strings using the HPACK-defined Huffman
// table.

#include <cstddef>  // For size_t
#include <string>

#include "net/third_party/quiche/src/common/platform/api/quiche_export.h"
#include "net/third_party/quiche/src/common/platform/api/quiche_string_piece.h"

namespace http2 {

// Returns the size of the Huffman encoding of |plain|, which may be greater
// than plain.size().
QUICHE_EXPORT_PRIVATE size_t HuffmanSize(quiche::QuicheStringPiece plain);

// Encode the plain text string |plain| with the Huffman encoding defined in the
// HPACK RFC, 7541.  |encoded_size| is used to pre-allocate storage and it
// should be the value returned by HuffmanSize().  Appends the result to
// |*huffman|.
QUICHE_EXPORT_PRIVATE void HuffmanEncode(quiche::QuicheStringPiece plain,
                                         size_t encoded_size,
                                         std::string* huffman);

// Encode |input| with the Huffman encoding defined RFC7541, used in HPACK and
// QPACK.  |encoded_size| must be the value returned by HuffmanSize().
// Appends the result to the end of |*output|.
QUICHE_EXPORT_PRIVATE void HuffmanEncodeFast(quiche::QuicheStringPiece input,
                                             size_t encoded_size,
                                             std::string* output);

}  // namespace http2

#endif  // QUICHE_HTTP2_HPACK_HUFFMAN_HPACK_HUFFMAN_ENCODER_H_
