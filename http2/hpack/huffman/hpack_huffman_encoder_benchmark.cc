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
// BM_EncodeSmallStrings           255        255  0  2557738    0.000B peak-mem
// BM_E.SmallStringsFast           247        247  0  2849201    0.000B peak-mem
// BM_EncodeLargeString/1k        4270       4271  1   166430  656.000B peak-mem
// BM_EncodeLargeString/4k       16819      16820  1    40483   2.516kB peak-mem
// BM_EncodeLargeString/32k     135426     135416  1     5155  20.016kB peak-mem
// BM_EncodeLargeString/256k   1080893    1080922  1      647 160.016kB peak-mem
// BM_EncodeLargeString/2M     8698878    8699261  1       77   1.250MB peak-mem
// BM_EncodeLargeString/16M   70013626   70009631  1       10  10.000MB peak-mem
// BM_EncodeLargeString/128M 581697663  581739687  1        1  80.000MB peak-mem
// BM_E.LargeStringFast/1k        3820       3820  1   184203  656.000B peak-mem
// BM_E.LargeStringFast/4k       15148      15146  1    46341   2.516kB peak-mem
// BM_E.LargeStringFast/32k     120409     120426  1     5803  20.016kB peak-mem
// BM_E.LargeStringFast/256k    968802     968841  1      725 160.016kB peak-mem
// BM_E.LargeStringFast/2M     7769441    7767875  1       90   1.250MB peak-mem
// BM_E.LargeStringFast/16M   62571561   62581958  1       10  10.000MB peak-mem
// BM_E.LargeStringFast/128M 527393576  527376986  1        1  80.000MB peak-mem
// BM_EncodeLongCode/1k          15197      15200  1    45281   3.766kB peak-mem
// BM_EncodeLongCode/4k          60782      60775  1    10000  15.016kB peak-mem
// BM_EncodeLongCode/32k        489516     489692  1     1441 120.016kB peak-mem
// BM_EncodeLongCode/256k      3902949    3905536  1      179 960.016kB peak-mem
// BM_EncodeLongCode/2M       31275026   31281987  1       23   7.500MB peak-mem
// BM_EncodeLongCode/16M     258391322  258361112  1        3  60.000MB peak-mem
// BM_EncodeLongCode/128M   2098369854 2098398258  1        1 480.000MB peak-mem
// BM_E.LongCodeFast/1k           3915       3915  1   179602   3.766kB peak-mem
// BM_E.LongCodeFast/4k          15433      15435  1    45491  15.016kB peak-mem
// BM_E.LongCodeFast/32k        124756     124750  1     5689 120.016kB peak-mem
// BM_E.LongCodeFast/256k      1007523    1008291  1      700 960.016kB peak-mem
// BM_E.LongCodeFast/2M        8129166    8132764  1       87   7.500MB peak-mem
// BM_E.LongCodeFast/16M      72076964   72079949  1        9  60.000MB peak-mem
// BM_E.LongCodeFast/128M    631963502  631948474  1        1 480.000MB peak-mem
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

void BM_EncodeSmallStringsFast(benchmark::State& state) {
  const std::vector<const std::string> inputs{
      ":method", ":path", "cookie", "set-cookie", "vary", "accept-encoding"};
  for (auto s : state) {
    for (const auto& input : inputs) {
      size_t encoded_size = ExactHuffmanSize(input);
      std::string result;
      HuffmanEncodeFast(input, encoded_size, &result);
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

void BM_EncodeLargeStringFast(benchmark::State& state) {
  const std::string input(state.range(0), 'a');
  for (auto s : state) {
    size_t encoded_size = ExactHuffmanSize(input);
    std::string result;
    HuffmanEncodeFast(input, encoded_size, &result);
  }
}

// 13 is one of the characters with the longest encoding: 30 bits.
// This will never be run in production, because HuffmanEncode is only called on
// strings that become shorter when encoded, but it gives an idea of compression
// speed when many characters in the input are encoded with long codes.
void BM_EncodeLongCode(benchmark::State& state) {
  const std::string input(state.range(0), 13);
  for (auto s : state) {
    size_t encoded_size = ExactHuffmanSize(input);
    std::string result;
    HuffmanEncode(input, encoded_size, &result);
  }
}

void BM_EncodeLongCodeFast(benchmark::State& state) {
  const std::string input(state.range(0), 13);
  for (auto s : state) {
    size_t encoded_size = ExactHuffmanSize(input);
    std::string result;
    HuffmanEncodeFast(input, encoded_size, &result);
  }
}

BENCHMARK(BM_EncodeSmallStrings);
BENCHMARK(BM_EncodeLargeString)->Range(1024, 128 * 1024 * 1024);
BENCHMARK(BM_EncodeLongCode)->Range(1024, 128 * 1024 * 1024);
BENCHMARK(BM_EncodeSmallStringsFast);
BENCHMARK(BM_EncodeLargeStringFast)->Range(1024, 128 * 1024 * 1024);
BENCHMARK(BM_EncodeLongCodeFast)->Range(1024, 128 * 1024 * 1024);

}  // namespace
}  // namespace http2
