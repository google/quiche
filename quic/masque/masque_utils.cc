// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quic/masque/masque_utils.h"

namespace quic {

ParsedQuicVersionVector MasqueSupportedVersions() {
  QuicVersionInitializeSupportForIetfDraft();
  ParsedQuicVersion version = UnsupportedQuicVersion();
  for (const ParsedQuicVersion& vers : AllSupportedVersions()) {
    // Find the first version that supports IETF QUIC.
    if (vers.HasIetfQuicFrames() && vers.UsesTls()) {
      version = vers;
      break;
    }
  }
  QUICHE_CHECK(version.IsKnown());
  QuicEnableVersion(version);
  return {version};
}

QuicConfig MasqueEncapsulatedConfig() {
  QuicConfig config;
  config.SetMaxPacketSizeToSend(kMasqueMaxEncapsulatedPacketSize);
  return config;
}

std::string MasqueModeToString(MasqueMode masque_mode) {
  switch (masque_mode) {
    case MasqueMode::kInvalid:
      return "Invalid";
    case MasqueMode::kLegacy:
      return "Legacy";
    case MasqueMode::kOpen:
      return "Open";
  }
  return absl::StrCat("Unknown(", static_cast<int>(masque_mode), ")");
}

std::ostream& operator<<(std::ostream& os, const MasqueMode& masque_mode) {
  os << MasqueModeToString(masque_mode);
  return os;
}

}  // namespace quic
