// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_FRAMER_UTILS_H_
#define QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_FRAMER_UTILS_H_

#include <cstdint>
#include <string>

#include "absl/strings/str_join.h"
#include "absl/types/variant.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/quiche_data_reader.h"

namespace moqt::test {

// TODO: remove MoqtObject from TestMessageBase::MessageStructuredData and merge
// those two types.
using MoqtGenericFrame = absl::variant<
    MoqtClientSetup, MoqtServerSetup, MoqtSubscribe, MoqtSubscribeOk,
    MoqtSubscribeError, MoqtUnsubscribe, MoqtSubscribeDone, MoqtSubscribeUpdate,
    MoqtAnnounce, MoqtAnnounceOk, MoqtAnnounceError, MoqtAnnounceCancel,
    MoqtTrackStatusRequest, MoqtUnannounce, MoqtTrackStatus, MoqtGoAway,
    MoqtSubscribeAnnounces, MoqtSubscribeAnnouncesOk,
    MoqtSubscribeAnnouncesError, MoqtUnsubscribeAnnounces, MoqtMaxSubscribeId,
    MoqtFetch, MoqtFetchCancel, MoqtFetchOk, MoqtFetchError, MoqtObjectAck>;

MoqtMessageType MessageTypeForGenericMessage(const MoqtGenericFrame& frame);

std::string SerializeGenericMessage(const MoqtGenericFrame& frame,
                                    bool use_webtrans = false);

MATCHER_P(SerializedControlMessage, message,
          "Matches against a specific expected MoQT message") {
  std::string merged_message = absl::StrJoin(arg, "");
  return merged_message == SerializeGenericMessage(message);
}

MATCHER_P(ControlMessageOfType, expected_type,
          "Matches against an MoQT message of a specific type") {
  std::string merged_message = absl::StrJoin(arg, "");
  quiche::QuicheDataReader reader(merged_message);
  uint64_t type_raw;
  if (!reader.ReadVarInt62(&type_raw)) {
    *result_listener << "Failed to extract type from the message";
    return false;
  }
  MoqtMessageType type = static_cast<MoqtMessageType>(type_raw);
  if (type != expected_type) {
    *result_listener << "Expected message of type "
                     << MoqtMessageTypeToString(expected_type) << ", got "
                     << MoqtMessageTypeToString(type);
    return false;
  }
  return true;
}

}  // namespace moqt::test

#endif  // QUICHE_QUIC_MOQT_TEST_TOOLS_MOQT_FRAMER_UTILS_H_
