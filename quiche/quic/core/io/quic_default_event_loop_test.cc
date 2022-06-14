// Copyright 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/io/quic_default_event_loop.h"

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <vector>

#include "absl/memory/memory.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_alarm_factory.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/test_tools/mock_clock.h"

namespace quic {

class QuicDefaultEventLoopPeer {
 public:
  static QuicTime::Delta ComputePollTimeout(const QuicDefaultEventLoop& loop,
                                            QuicTime now,
                                            QuicTime::Delta default_timeout) {
    return loop.ComputePollTimeout(now, default_timeout);
  }
};

}  // namespace quic

namespace quic::test {
namespace {

using testing::_;
using testing::AtMost;
using testing::ElementsAre;

constexpr QuicSocketEventMask kAllEvents =
    kSocketEventReadable | kSocketEventWritable | kSocketEventError;
constexpr QuicTime::Delta kDefaultTimeout = QuicTime::Delta::FromSeconds(100);

class MockQuicSocketEventListener : public QuicSocketEventListener {
 public:
  MOCK_METHOD(void, OnSocketEvent,
              (QuicEventLoop* /*event_loop*/, QuicUdpSocketFd /*fd*/,
               QuicSocketEventMask /*events*/),
              (override));
};

class MockDelegate : public QuicAlarm::Delegate {
 public:
  QuicConnectionContext* GetConnectionContext() override { return nullptr; }
  MOCK_METHOD(void, OnAlarm, (), (override));
};

class QuicDefaultEventLoopForTest : public QuicDefaultEventLoop {
 public:
  QuicDefaultEventLoopForTest(MockClock* clock)
      : QuicDefaultEventLoop(clock), clock_(clock) {}

  int PollSyscall(pollfd* fds, nfds_t nfds, int timeout) override {
    timeouts_.push_back(timeout);
    if (eintr_after_ != QuicTime::Delta::Infinite()) {
      errno = EINTR;
      clock_->AdvanceTime(eintr_after_);
      eintr_after_ = QuicTime::Delta::Infinite();
      return -1;
    }
    clock_->AdvanceTime(QuicTime::Delta::FromMilliseconds(timeout));
    return QuicDefaultEventLoop::PollSyscall(fds, nfds, timeout);
  }

  void TriggerEintrAfter(QuicTime::Delta time) { eintr_after_ = time; }

  const std::vector<int>& timeouts() const { return timeouts_; }

 private:
  MockClock* clock_;
  QuicTime::Delta eintr_after_ = QuicTime::Delta::Infinite();
  std::vector<int> timeouts_;
};

class QuicDefaultEventLoopTest : public QuicTest {
 public:
  QuicDefaultEventLoopTest()
      : loop_(&clock_), factory_(loop_.GetAlarmFactory()) {
    int fds[2];
    int result = ::pipe(fds);
    QUICHE_CHECK(result >= 0) << "Failed to create a pipe, errno: " << errno;
    read_fd_ = fds[0];
    write_fd_ = fds[1];

    QUICHE_CHECK(::fcntl(read_fd_, F_SETFL,
                         ::fcntl(read_fd_, F_GETFL) | O_NONBLOCK) == 0)
        << "Failed to mark pipe FD non-blocking, errno: " << errno;
    QUICHE_CHECK(::fcntl(write_fd_, F_SETFL,
                         ::fcntl(write_fd_, F_GETFL) | O_NONBLOCK) == 0)
        << "Failed to mark pipe FD non-blocking, errno: " << errno;

    clock_.AdvanceTime(10 * kDefaultTimeout);
  }

  ~QuicDefaultEventLoopTest() {
    close(read_fd_);
    close(write_fd_);
  }

  QuicTime::Delta ComputePollTimeout() {
    return QuicDefaultEventLoopPeer::ComputePollTimeout(loop_, clock_.Now(),
                                                        kDefaultTimeout);
  }

  std::pair<std::unique_ptr<QuicAlarm>, MockDelegate*> CreateAlarm() {
    auto delegate = std::make_unique<testing::StrictMock<MockDelegate>>();
    MockDelegate* delegate_unowned = delegate.get();
    auto alarm = absl::WrapUnique(factory_->CreateAlarm(delegate.release()));
    return std::make_pair(std::move(alarm), delegate_unowned);
  }

 protected:
  MockClock clock_;
  QuicDefaultEventLoopForTest loop_;
  QuicAlarmFactory* factory_;
  int read_fd_;
  int write_fd_;
};

TEST_F(QuicDefaultEventLoopTest, NothingHappens) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  // Attempt double-registration.
  EXPECT_FALSE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(4));
  // Expect no further calls.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(5));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(4, 5));
}

TEST_F(QuicDefaultEventLoopTest, RearmWriter) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
      .Times(2);
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  ASSERT_TRUE(loop_.RearmSocket(write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicDefaultEventLoopTest, Readable) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  ASSERT_EQ(4, write(write_fd_, "test", 4));
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  // Expect no further calls.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicDefaultEventLoopTest, RearmReader) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  ASSERT_EQ(4, write(write_fd_, "test", 4));
  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  // Expect no further calls.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicDefaultEventLoopTest, WriterUnblocked) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  int io_result;
  std::string data(2048, 'a');
  do {
    io_result = write(write_fd_, data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);

  // Rearm and expect no immediate calls.
  ASSERT_TRUE(loop_.RearmSocket(write_fd_, kSocketEventWritable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  do {
    io_result = read(read_fd_, data.data(), data.size());
  } while (io_result > 0);
  ASSERT_EQ(errno, EAGAIN);
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicDefaultEventLoopTest, ArtificialEvent) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
  ASSERT_TRUE(loop_.ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
  EXPECT_EQ(ComputePollTimeout(), QuicTime::Delta::Zero());

  {
    testing::InSequence s;
    EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable));
    EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable));
  }
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

TEST_F(QuicDefaultEventLoopTest, Unregister) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.UnregisterSocket(write_fd_));

  // Expect nothing to happen.
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));

  EXPECT_FALSE(loop_.UnregisterSocket(write_fd_));
  EXPECT_FALSE(loop_.RearmSocket(write_fd_, kSocketEventWritable));
  EXPECT_FALSE(loop_.ArtificiallyNotifyEvent(write_fd_, kSocketEventWritable));
}

TEST_F(QuicDefaultEventLoopTest, UnregisterInsideEventHandler) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));
  ASSERT_TRUE(loop_.RegisterSocket(write_fd_, kAllEvents, &listener));

  EXPECT_CALL(listener, OnSocketEvent(_, read_fd_, kSocketEventReadable))
      .WillOnce([this]() { ASSERT_TRUE(loop_.UnregisterSocket(write_fd_)); });
  EXPECT_CALL(listener, OnSocketEvent(_, write_fd_, kSocketEventWritable))
      .Times(0);
  ASSERT_TRUE(loop_.ArtificiallyNotifyEvent(read_fd_, kSocketEventReadable));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(1));
}

TEST_F(QuicDefaultEventLoopTest, EintrHandler) {
  testing::StrictMock<MockQuicSocketEventListener> listener;
  ASSERT_TRUE(loop_.RegisterSocket(read_fd_, kAllEvents, &listener));

  loop_.TriggerEintrAfter(QuicTime::Delta::FromMilliseconds(25));
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(100, 75));
}

TEST_F(QuicDefaultEventLoopTest, AlarmInFuture) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  alarm->Set(clock_.Now() + kAlarmTimeout);
  EXPECT_EQ(ComputePollTimeout(), kAlarmTimeout);

  EXPECT_CALL(*delegate, OnAlarm());
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

TEST_F(QuicDefaultEventLoopTest, AlarmsInPast) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm1, delegate1] = CreateAlarm();
  auto [alarm2, delegate2] = CreateAlarm();

  alarm1->Set(clock_.Now() - 2 * kAlarmTimeout);
  alarm2->Set(clock_.Now() - kAlarmTimeout);

  {
    testing::InSequence s;
    EXPECT_CALL(*delegate1, OnAlarm());
    EXPECT_CALL(*delegate2, OnAlarm());
  }
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
}

TEST_F(QuicDefaultEventLoopTest, AlarmCancelled) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm, delegate] = CreateAlarm();
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  alarm->Set(clock_.Now() + kAlarmTimeout);
  alarm->Cancel();
  alarm->Set(clock_.Now() + 2 * kAlarmTimeout);
  EXPECT_EQ(ComputePollTimeout(), kAlarmTimeout);

  EXPECT_CALL(*delegate, OnAlarm());
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_THAT(loop_.timeouts(), ElementsAre(10));
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

TEST_F(QuicDefaultEventLoopTest, AlarmCancelsAnotherAlarm) {
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);

  constexpr auto kAlarmTimeout = QuicTime::Delta::FromMilliseconds(5);
  auto [alarm1_ptr, delegate1] = CreateAlarm();
  auto [alarm2_ptr, delegate2] = CreateAlarm();

  QuicAlarm& alarm1 = *alarm1_ptr;
  QuicAlarm& alarm2 = *alarm2_ptr;
  alarm1.Set(clock_.Now() - kAlarmTimeout);
  alarm2.Set(clock_.Now() - kAlarmTimeout);

  int alarms_called = 0;
  // Since the order in which alarms are cancelled is not well-determined, make
  // each one cancel another.
  EXPECT_CALL(*delegate1, OnAlarm()).Times(AtMost(1)).WillOnce([&]() {
    alarm2.Cancel();
    ++alarms_called;
  });
  EXPECT_CALL(*delegate2, OnAlarm()).Times(AtMost(1)).WillOnce([&]() {
    alarm1.Cancel();
    ++alarms_called;
  });
  loop_.RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(100));
  EXPECT_EQ(alarms_called, 1);
  EXPECT_EQ(ComputePollTimeout(), kDefaultTimeout);
}

}  // namespace
}  // namespace quic::test
