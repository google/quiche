// Copyright 2013 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_TEST_TOOLS_QUIC_SERVER_PEER_H_
#define QUICHE_QUIC_TEST_TOOLS_QUIC_SERVER_PEER_H_

namespace quic {

class QuicConfig;
class QuicDispatcher;
class QuicPacketReader;
class QuicServer;

namespace test {

class QuicServerPeer {
 public:
  QuicServerPeer() = delete;

  static bool SetSmallSocket(QuicServer* server);
  static QuicConfig* GetConfig(QuicServer* server);
  static QuicDispatcher* GetDispatcher(QuicServer* server);
  static void SetReader(QuicServer* server, QuicPacketReader* reader);
};

}  // namespace test
}  // namespace quic

#endif  // QUICHE_QUIC_TEST_TOOLS_QUIC_SERVER_PEER_H_
