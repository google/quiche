// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_BALSA_NOOP_BALSA_VISITOR_H_
#define QUICHE_COMMON_BALSA_NOOP_BALSA_VISITOR_H_

#include <cstddef>

#include "quiche/common/balsa/balsa_visitor_interface.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quiche {

class BalsaHeaders;

// Provides empty BalsaVisitorInterface overrides for convenience.
// Intended to be used as a base class for BalsaVisitorInterface subclasses that
// only need to override a small number of methods.
class QUICHE_EXPORT_PRIVATE NoOpBalsaVisitor : public BalsaVisitorInterface {
 public:
  NoOpBalsaVisitor() = default;

  NoOpBalsaVisitor(const NoOpBalsaVisitor&) = delete;
  NoOpBalsaVisitor& operator=(const NoOpBalsaVisitor&) = delete;

  ~NoOpBalsaVisitor() override {}

  void OnRawBodyInput(const char* /*input*/, size_t /*size*/) override {}
  void OnBodyChunkInput(const char* /*input*/, size_t /*size*/) override {}
  void OnHeaderInput(const char* /*input*/, size_t /*size*/) override {}
  void OnTrailerInput(const char* /*input*/, size_t /*size*/) override {}
  void ProcessHeaders(const BalsaHeaders& /*headers*/) override {}
  void ProcessTrailers(const BalsaHeaders& /*trailer*/) override {}

  void OnRequestFirstLineInput(
      const char* /*line_input*/, size_t /*line_length*/,
      const char* /*method_input*/, size_t /*method_length*/,
      const char* /*request_uri_input*/, size_t /*request_uri_length*/,
      const char* /*version_input*/, size_t /*version_length*/) override {}
  void OnResponseFirstLineInput(
      const char* /*line_input*/, size_t /*line_length*/,
      const char* /*version_input*/, size_t /*version_length*/,
      const char* /*status_input*/, size_t /*status_length*/,
      const char* /*reason_input*/, size_t /*reason_length*/) override {}
  void OnChunkLength(size_t /*chunk_length*/) override {}
  void OnChunkExtensionInput(const char* /*input*/, size_t /*size*/) override {}
  void ContinueHeaderDone() override {}
  void HeaderDone() override {}
  void MessageDone() override {}
  void HandleError(BalsaFrameEnums::ErrorCode /*error_code*/) override {}
  void HandleWarning(BalsaFrameEnums::ErrorCode /*error_code*/) override {}
};

}  // namespace quiche

#endif  // QUICHE_COMMON_BALSA_NOOP_BALSA_VISITOR_H_
