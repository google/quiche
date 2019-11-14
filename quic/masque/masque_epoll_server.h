// Copyright 2019 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MASQUE_MASQUE_EPOLL_SERVER_H_
#define QUICHE_QUIC_MASQUE_MASQUE_EPOLL_SERVER_H_

#include "net/third_party/quiche/src/quic/masque/masque_server_backend.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_export.h"
#include "net/third_party/quiche/src/quic/tools/quic_server.h"

namespace quic {

// QUIC server that implements MASQUE.
class QUIC_EXPORT_PRIVATE MasqueEpollServer : public QuicServer {
 public:
  explicit MasqueEpollServer(MasqueServerBackend* masque_server_backend);

  // From QuicServer.
  QuicDispatcher* CreateQuicDispatcher() override;

  // Disallow default constructor, copy, and assign.
  MasqueEpollServer() = delete;
  MasqueEpollServer(const MasqueEpollServer&) = delete;
  MasqueEpollServer& operator=(const MasqueEpollServer&) = delete;

 private:
  MasqueServerBackend* masque_server_backend_;  // Unowned.
};

}  // namespace quic

#endif  // QUICHE_QUIC_MASQUE_MASQUE_EPOLL_SERVER_H_
