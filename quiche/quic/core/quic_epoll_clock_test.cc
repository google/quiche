// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/quic_epoll_clock.h"

#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/common/platform/api/quiche_epoll_test_tools.h"

namespace quic {
namespace test {

class QuicEpollClockTest : public QuicTest {};

TEST_F(QuicEpollClockTest, ApproximateNowInUsec) {
  quiche::QuicheFakeEpollServer epoll_server;
  QuicEpollClock clock(&epoll_server);

  epoll_server.set_now_in_usec(1000000);
  EXPECT_EQ(1000000,
            (clock.ApproximateNow() - QuicTime::Zero()).ToMicroseconds());
  EXPECT_EQ(1u, clock.WallNow().ToUNIXSeconds());
  EXPECT_EQ(1000000u, clock.WallNow().ToUNIXMicroseconds());

  epoll_server.AdvanceBy(5);
  EXPECT_EQ(1000005,
            (clock.ApproximateNow() - QuicTime::Zero()).ToMicroseconds());
  EXPECT_EQ(1u, clock.WallNow().ToUNIXSeconds());
  EXPECT_EQ(1000005u, clock.WallNow().ToUNIXMicroseconds());

  epoll_server.AdvanceBy(10 * 1000000);
  EXPECT_EQ(11u, clock.WallNow().ToUNIXSeconds());
  EXPECT_EQ(11000005u, clock.WallNow().ToUNIXMicroseconds());
}

TEST_F(QuicEpollClockTest, NowInUsec) {
  quiche::QuicheFakeEpollServer epoll_server;
  QuicEpollClock clock(&epoll_server);

  epoll_server.set_now_in_usec(1000000);
  EXPECT_EQ(1000000, (clock.Now() - QuicTime::Zero()).ToMicroseconds());

  epoll_server.AdvanceBy(5);
  EXPECT_EQ(1000005, (clock.Now() - QuicTime::Zero()).ToMicroseconds());
}

TEST_F(QuicEpollClockTest, MonotonicityWithRealEpollClock) {
  QuicEpollServer epoll_server;
  QuicEpollClock clock(&epoll_server);

  QuicTime last_now = clock.Now();
  for (int i = 0; i < 1e5; ++i) {
    QuicTime now = clock.Now();

    ASSERT_LE(last_now, now);

    last_now = now;
  }
}

TEST_F(QuicEpollClockTest, MonotonicityWithFakeEpollClock) {
  quiche::QuicheFakeEpollServer epoll_server;
  QuicEpollClock clock(&epoll_server);

  epoll_server.set_now_in_usec(100);
  QuicTime last_now = clock.Now();

  epoll_server.set_now_in_usec(90);
  QuicTime now = clock.Now();

  ASSERT_EQ(last_now, now);
}

}  // namespace test
}  // namespace quic
