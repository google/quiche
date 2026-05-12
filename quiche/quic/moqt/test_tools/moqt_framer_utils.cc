// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/test_tools/moqt_framer_utils.h"

#include <string>
#include <variant>

#include "quiche/quic/moqt/moqt_framer.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/common/quiche_buffer_allocator.h"

namespace moqt::test {

namespace {

struct FramingVisitor {
  quiche::QuicheBuffer operator()(const MoqtClientSetup& message) {
    return framer.SerializeClientSetup(message);
  }
  quiche::QuicheBuffer operator()(const MoqtServerSetup& message) {
    return framer.SerializeServerSetup(message);
  }
  quiche::QuicheBuffer operator()(const MoqtRequestOk& message) {
    return framer.SerializeRequestOk(message);
  }
  quiche::QuicheBuffer operator()(const MoqtRequestError& message) {
    return framer.SerializeRequestError(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribe& message) {
    return framer.SerializeSubscribe(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeOk& message) {
    return framer.SerializeSubscribeOk(message);
  }
  quiche::QuicheBuffer operator()(const MoqtUnsubscribe& message) {
    return framer.SerializeUnsubscribe(message);
  }
  quiche::QuicheBuffer operator()(const MoqtPublishDone& message) {
    return framer.SerializePublishDone(message);
  }
  quiche::QuicheBuffer operator()(const MoqtRequestUpdate& message) {
    return framer.SerializeRequestUpdate(message);
  }
  quiche::QuicheBuffer operator()(const MoqtPublishNamespace& message) {
    return framer.SerializePublishNamespace(message);
  }
  quiche::QuicheBuffer operator()(const MoqtPublishNamespaceDone& message) {
    return framer.SerializePublishNamespaceDone(message);
  }
  quiche::QuicheBuffer operator()(const MoqtNamespace& message) {
    return framer.SerializeNamespace(message);
  }
  quiche::QuicheBuffer operator()(const MoqtNamespaceDone& message) {
    return framer.SerializeNamespaceDone(message);
  }
  quiche::QuicheBuffer operator()(const MoqtPublishNamespaceCancel& message) {
    return framer.SerializePublishNamespaceCancel(message);
  }
  quiche::QuicheBuffer operator()(const MoqtTrackStatus& message) {
    return framer.SerializeTrackStatus(message);
  }
  quiche::QuicheBuffer operator()(const MoqtGoAway& message) {
    return framer.SerializeGoAway(message);
  }
  quiche::QuicheBuffer operator()(const MoqtSubscribeNamespace& message) {
    return framer.SerializeSubscribeNamespace(message);
  }
  quiche::QuicheBuffer operator()(const MoqtMaxRequestId& message) {
    return framer.SerializeMaxRequestId(message);
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
  quiche::QuicheBuffer operator()(const MoqtRequestsBlocked& message) {
    return framer.SerializeRequestsBlocked(message);
  }
  quiche::QuicheBuffer operator()(const MoqtPublish& message) {
    return framer.SerializePublish(message);
  }
  quiche::QuicheBuffer operator()(const MoqtObjectAck& message) {
    return framer.SerializeObjectAck(message);
  }

  MoqtFramer& framer;
  bool is_track_status;
};

}  // namespace

std::string SerializeGenericMessage(const AnyMoqtControlMessage& frame,
                                    bool use_webtrans) {
  MoqtFramer framer(use_webtrans);
  return std::string(std::visit(FramingVisitor{framer}, frame).AsStringView());
}

}  // namespace moqt::test
