// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche_platform_impl/quiche_default_proof_providers_impl.h"

namespace quiche {

// TODO(vasilvv): implement those in order for the CLI tools to work.
std::unique_ptr<quic::ProofVerifier> CreateDefaultProofVerifierImpl(
    const std::string& /*host*/) {
  return nullptr;
}

std::unique_ptr<quic::ProofSource> CreateDefaultProofSourceImpl() {
  return nullptr;
}

}  // namespace quiche
