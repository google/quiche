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

TEST_F(QuicEpollClockTest, CalibrateRealEpollClock) {
  QuicEpollServer epoll_server;

  QuicEpollClock uncalibrated_clock(&epoll_server);
  QuicEpollClock calibrated_clock(&epoll_server);
  EXPECT_TRUE(calibrated_clock.ComputeCalibrationOffset().IsZero());

  for (int i = 0; i < 100; ++i) {
    QuicWallTime wallnow = uncalibrated_clock.WallNow();
    EXPECT_EQ(uncalibrated_clock.ConvertWallTimeToQuicTime(wallnow),
              calibrated_clock.ConvertWallTimeToQuicTime(wallnow));
  }
}

// ClockWithOffset is a clock whose offset(WallNow() - Now() at any instant) is
// given at construction time.
class ClockWithOffset : public QuicEpollClock {
 public:
  ClockWithOffset(QuicEpollServer* epoll_server, QuicTime::Delta offset)
      : QuicEpollClock(epoll_server), offset_(offset) {}

  QuicTime Now() const override { return QuicEpollClock::Now() - offset_; }

  // QuicEpollClock disables ConvertWallTimeToQuicTime since it always have a
  // zero offset. We need to re-enable it here in order to test the calibration
  // and conversion code in QuicClock.
  QuicTime ConvertWallTimeToQuicTime(
      const QuicWallTime& walltime) const override {
    return QuicClock::ConvertWallTimeToQuicTime(walltime);
  }

 private:
  QuicTime::Delta offset_;
};

TEST_F(QuicEpollClockTest, CalibrateClockWithOffset) {
  QuicEpollServer epoll_server;

  for (const QuicTime::Delta& offset : {QuicTime::Delta::FromSeconds(5000),
                                        QuicTime::Delta::FromSeconds(-8000)}) {
    ClockWithOffset clock(&epoll_server, offset);
    ASSERT_EQ(offset, clock.ComputeCalibrationOffset())
        << "offset (us): " << offset.ToMicroseconds();
    // Test fails without this.
    clock.SetCalibrationOffset(offset);

    QuicWallTime last_walltime = clock.WallNow();
    QuicTime last_time = clock.ConvertWallTimeToQuicTime(last_walltime);

    for (int i = 0; i < 1e5; ++i) {
      QuicWallTime wallnow = clock.WallNow();
      QuicTime now = clock.ConvertWallTimeToQuicTime(wallnow);

      if (wallnow.IsAfter(last_walltime)) {
        ASSERT_LT(0, (now - last_time).ToMicroseconds())
            << "offset (us): " << offset.ToMicroseconds();

        last_walltime = wallnow;
        last_time = now;
      }
    }
  }
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
