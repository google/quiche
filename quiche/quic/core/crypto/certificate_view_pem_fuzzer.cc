// Copyright 2020 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <cstdlib>
#include <sstream>
#include <string>

#include "quiche/quic/core/crypto/certificate_view.h"
#include "quiche/common/platform/api/quiche_fuzztest.h"

void DoesNotCrash(const std::string& input) {
  std::stringstream stream(input);

  quic::CertificateView::LoadPemFromStream(&stream);
  stream.seekg(0);
  quic::CertificatePrivateKey::LoadPemFromStream(&stream);
}
FUZZ_TEST(CertificateViewPemFuzzer, DoesNotCrash)
    .WithSeeds(
        fuzztest::ReadFilesFromDirectory(getenv("FUZZER_SEED_CORPUS_DIR")));
