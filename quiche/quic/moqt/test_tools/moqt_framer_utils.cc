// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"

#include <string>

#include "absl/types/variant.h"
#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/simple_buffer_allocator.h"

namespace moqt::test {

struct TypeVisitor {
  MoqtMessageType operator()(const MoqtClientSetup&) {
    return MoqtMessageType::kClientSetup;
  }
  MoqtMessageType operator()(const MoqtServerSetup&) {
    return MoqtMessageType::kServerSetup;
  }
  MoqtMessageType operator()(const MoqtSubscribe&) {
    return MoqtMessageType::kSubscribe;
  }
  MoqtMessageType operator()(const MoqtSubscribeOk&) {
    return MoqtMessageType::kSubscribeOk;
  }
  MoqtMessageType operator()(const MoqtSubscribeError&) {
    return MoqtMessageType::kSubscribeError;
  }
  MoqtMessageType operator()(const MoqtUnsubscribe&) {
    return MoqtMessageType::kUnsubscribe;
  }
  MoqtMessageType operator()(const MoqtSubscribeDone&) {
    return MoqtMessageType::kSubscribeDone;
  }
  MoqtMessageType operator()(const MoqtSubscribeUpdate&) {
    return MoqtMessageType::kSubscribeUpdate;
  }
  MoqtMessageType operator()(const MoqtAnnounce&) {
    return MoqtMessageType::kAnnounce;
  }
  MoqtMessageType operator()(const MoqtAnnounceOk&) {
    return MoqtMessageType::kAnnounceOk;
  }
  MoqtMessageType operator()(const MoqtAnnounceError&) {
    return MoqtMessageType::kAnnounceError;
  }
  MoqtMessageType operator()(const MoqtAnnounceCancel&) {
    return MoqtMessageType::kAnnounceCancel;
  }
  MoqtMessageType operator()(const MoqtTrackStatusRequest&) {
    return MoqtMessageType::kTrackStatusRequest;
  }
  MoqtMessageType operator()(const MoqtUnannounce&) {
    return MoqtMessageType::kUnannounce;
  }
  MoqtMessageType operator()(const MoqtTrackStatus&) {
    return MoqtMessageType::kTrackStatus;
  }
  MoqtMessageType operator()(const MoqtGoAway&) {
    return MoqtMessageType::kGoAway;
  }
  MoqtMessageType operator()(const MoqtSubscribeAnnounces&) {
    return MoqtMessageType::kSubscribeAnnounces;
  }
  MoqtMessageType operator()(const MoqtSubscribeAnnouncesOk&) {
    return MoqtMessageType::kSubscribeAnnouncesOk;
  }
  MoqtMessageType operator()(const MoqtSubscribeAnnouncesError&) {
    return MoqtMessageType::kSubscribeAnnouncesError;
  }
  MoqtMessageType operator()(const MoqtUnsubscribeAnnounces&) {
    return MoqtMessageType::kUnsubscribeAnnounces;
  }
  MoqtMessageType operator()(const MoqtMaxSubscribeId&) {
    return MoqtMessageType::kMaxSubscribeId;
  }
  MoqtMessageType operator()(const MoqtFetch&) {
    return MoqtMessageType::kFetch;
  }
  MoqtMessageType operator()(const MoqtFetchCancel&) {
    return MoqtMessageType::kFetchCancel;
  }
  MoqtMessageType operator()(const MoqtFetchOk&) {
    return MoqtMessageType::kFetchOk;
  }
  MoqtMessageType operator()(const MoqtFetchError&) {
    return MoqtMessageType::kFetchError;
  }
  MoqtMessageType operator()(const MoqtObjectAck&) {
    return MoqtMessageType::kObjectAck;
  }
};

MoqtMessageType MessageTypeForGenericMessage(const MoqtGenericFrame& frame) {
  return absl::visit(TypeVisitor(), frame);
}

struct FramingVisitor {
  quiche::QuicheBuffer operator()(const MoqtClientSetup& message) {
    return framer.SerializeClientSetup(message);
  }
  quiche::QuicheBuffer operator()(const MoqtServerSetup& message) {
    return framer.SerializeServerSetup(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribe& message) {
    return framer.SerializeSubscribe(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeOk& message) {
    return framer.SerializeSubscribeOk(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeError& message) {
    return framer.SerializeSubscribeError(message);
  }
  quiche::QuicheBuffer operator()(const MoqtUnsubscribe& message) {
    return framer.SerializeUnsubscribe(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeDone& message) {
    return framer.SerializeSubscribeDone(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeUpdate& message) {
    return framer.SerializeSubscribeUpdate(message);
  }
  quiche::QuicheBuffer operator()(const MoqtAnnounce& message) {
    return framer.SerializeAnnounce(message);
  }
  quiche::QuicheBuffer operator()(const MoqtAnnounceOk& message) {
    return framer.SerializeAnnounceOk(message);
  }
  quiche::QuicheBuffer operator()(const MoqtAnnounceError& message) {
    return framer.SerializeAnnounceError(message);
  }
  quiche::QuicheBuffer operator()(const MoqtAnnounceCancel& message) {
    return framer.SerializeAnnounceCancel(message);
  }
  quiche::QuicheBuffer operator()(const MoqtTrackStatusRequest& message) {
    return framer.SerializeTrackStatusRequest(message);
  }
  quiche::QuicheBuffer operator()(const MoqtUnannounce& message) {
    return framer.SerializeUnannounce(message);
  }
  quiche::QuicheBuffer operator()(const MoqtTrackStatus& message) {
    return framer.SerializeTrackStatus(message);
  }
  quiche::QuicheBuffer operator()(const MoqtGoAway& message) {
    return framer.SerializeGoAway(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeAnnounces& message) {
    return framer.SerializeSubscribeAnnounces(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeAnnouncesOk& message) {
    return framer.SerializeSubscribeAnnouncesOk(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeAnnouncesError& message) {
    return framer.SerializeSubscribeAnnouncesError(message);
  }
  quiche::QuicheBuffer operator()(const MoqtUnsubscribeAnnounces& message) {
    return framer.SerializeUnsubscribeAnnounces(message);
  }
  quiche::QuicheBuffer operator()(const MoqtMaxSubscribeId& message) {
    return framer.SerializeMaxSubscribeId(message);
  }
  quiche::QuicheBuffer operator()(const MoqtFetch& message) {
    return framer.SerializeFetch(message);
  }
  quiche::QuicheBuffer operator()(const MoqtFetchCancel& message) {
    return framer.SerializeFetchCancel(message);
  }
  quiche::QuicheBuffer operator()(const MoqtFetchOk& message) {
    return framer.SerializeFetchOk(message);
  }
  quiche::QuicheBuffer operator()(const MoqtFetchError& message) {
    return framer.SerializeFetchError(message);
  }
  quiche::QuicheBuffer operator()(const MoqtObjectAck& message) {
    return framer.SerializeObjectAck(message);
  }

  MoqtFramer& framer;
};

std::string SerializeGenericMessage(const MoqtGenericFrame& frame,
                                    bool use_webtrans) {
  MoqtFramer framer(quiche::SimpleBufferAllocator::Get(), use_webtrans);
  return std::string(absl::visit(FramingVisitor{framer}, frame).AsStringView());
}

}  // namespace moqt::test
