// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>
#include <memory>
#include <string>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"

void DoesNotCrash(std::string input) {
  std::unique_ptr<quic::CertificateView> view =
      quic::CertificateView::ParseSingleCertificate(input);
  if (view != nullptr) {
    view->GetHumanReadableSubject();
  }
  quic::CertificatePrivateKey::LoadFromDer(input);
}
FUZZ_TEST(CertificateViewDerFuzzer, DoesNotCrash)
    .WithSeeds(
        fuzztest::ReadFilesFromDirectory(getenv("FUZZER_SEED_CORPUS_DIR")));
