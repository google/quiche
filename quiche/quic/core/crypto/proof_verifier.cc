// Copyright (c) 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/crypto/proof_verifier.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/common/platform/api/quiche_logging.h"

namespace quic {

QuicAsyncStatus ProofVerifier::VerifyCertChain(
    const std::string& hostname, uint16_t port,
    const std::vector<absl::string_view>& certs,
    const std::string& ocsp_response, const std::string& cert_sct,
    const ProofVerifyContext* context, std::string* error_details,
    std::unique_ptr<ProofVerifyDetails>* details, uint8_t* out_alert,
    std::unique_ptr<ProofVerifierCallback> callback) {
  // To avoid needing an atomic migration of all quiche consumers to use the new
  // VerifyCertChain function definition, this shim is provided so that old
  // ProofVerifier implementations continue to work.
  //
  // TODO(b/517611362): Remove this once all ProofVerifier implementations
  // have stopped implementing the old VerifyCertChain.
  std::vector<std::string> certs_str;
  certs_str.reserve(certs.size());
  for (absl::string_view cert : certs) {
    certs_str.push_back(std::string(cert));
  }
  return VerifyCertChain(hostname, port, certs_str, ocsp_response, cert_sct,
                         context, error_details, details, out_alert,
                         std::move(callback));
}

QuicAsyncStatus ProofVerifier::VerifyCertChain(
    const std::string&, uint16_t, const std::vector<std::string>&,
    const std::string&, const std::string&, const ProofVerifyContext*,
    std::string*, std::unique_ptr<ProofVerifyDetails>*, uint8_t*,
    std::unique_ptr<ProofVerifierCallback>) {
  // This function exists only for ProofVerifiers that don't implement the new
  // VerifyCertChain (that takes a vector of absl::string_views for the certs).
  // A ProofVerifier needs to implement one of the VerifyCertChain functions
  // (and it should implement the other one). If it implements neither, it will
  // end up here.
  QUICHE_NOTREACHED();
  return QUIC_FAILURE;
}

}  // namespace quic
