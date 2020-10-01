// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//
// $ blaze run -c opt --dynamic_mode=off \
//     -- //net/third_party/quiche/src/http2/hpack/huffman:hpack_huffman_encoder_benchmark \
//     --benchmarks=all --benchmark_memory_usage --benchmark_repetitions=1
//
// Benchmark                  Time(ns)  CPU(ns) Allocs Iterations
// -----------------------------------------------------------------------------
// BM_EncodeSmallStrings           256       256   0  2614132   0.000B  peak-mem
// BM_EncodeLargeString/1k        4295      4296   1   164072 656.000B  peak-mem
// BM_EncodeLargeString/4k       17077     17078   1    40336   2.516kB peak-mem
// BM_EncodeLargeString/32k     136586    136584   1     5126  20.016kB peak-mem
// BM_EncodeLargeString/256k   1094913   1094867   1      632 160.016kB peak-mem
// BM_EncodeLargeString/2M     8771916   8773555   1       80   1.250MB peak-mem
// BM_EncodeLargeString/16M   72575563  72590767   1       10  10.000MB peak-mem
// BM_EncodeLargeString/128M 602461676 602487805   1        1  80.000MB peak-mem
//

#include <string>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
// This header has multiple DCHECK_* macros with signed-unsigned comparison.
#include "testing/base/public/benchmark.h"
#pragma clang diagnostic pop

#include "net/third_party/quiche/src/http2/hpack/huffman/hpack_huffman_encoder.h"

namespace http2 {
namespace {

void BM_EncodeSmallStrings(benchmark::State& state) {
  const std::vector<const std::string> inputs{
      ":method", ":path", "cookie", "set-cookie", "vary", "accept-encoding"};
  for (auto s : state) {
    for (const auto& input : inputs) {
      size_t encoded_size = ExactHuffmanSize(input);
      std::string result;
      HuffmanEncode(input, encoded_size, &result);
    }
  }
}

void BM_EncodeLargeString(benchmark::State& state) {
  const std::string input(state.range(0), 'a');
  for (auto s : state) {
    size_t encoded_size = ExactHuffmanSize(input);
    std::string result;
    HuffmanEncode(input, encoded_size, &result);
  }
}

BENCHMARK(BM_EncodeSmallStrings);
BENCHMARK(BM_EncodeLargeString)->Range(1024, 128 * 1024 * 1024);

}  // namespace
}  // namespace http2
