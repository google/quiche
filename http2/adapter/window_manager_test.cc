#include "http2/adapter/window_manager.h"

#include <list>

#include "absl/functional/bind_front.h"
#include "http2/test_tools/http2_random.h"
#include "common/platform/api/quiche_test.h"
#include "common/platform/api/quiche_test_helpers.h"

namespace http2 {
namespace adapter {
namespace test {

// Use the peer to access private vars of WindowManager.
class WindowManagerPeer {
 public:
  explicit WindowManagerPeer(const WindowManager& wm) : wm_(wm) {}

  size_t buffered() {
    return wm_.buffered_;
  }

 private:
  const WindowManager& wm_;
};

namespace {

class WindowManagerTest : public ::testing::Test {
 protected:
  WindowManagerTest()
      : wm_(kDefaultLimit, absl::bind_front(&WindowManagerTest::OnCall, this)),
        peer_(wm_) {}

  void OnCall(size_t s) {
    call_sequence_.push_back(s);
  }

  const size_t kDefaultLimit = 32 * 1024 * 3;
  std::list<size_t> call_sequence_;
  WindowManager wm_;
  WindowManagerPeer peer_;
  ::http2::test::Http2Random random_;
};

// A few no-op calls.
TEST_F(WindowManagerTest, NoOps) {
  wm_.SetWindowSizeLimit(kDefaultLimit);
  wm_.SetWindowSizeLimit(0);
  wm_.SetWindowSizeLimit(kDefaultLimit);
  wm_.MarkDataBuffered(0);
  wm_.MarkDataFlushed(0);
  EXPECT_TRUE(call_sequence_.empty());
}

// This test verifies that WindowManager does not notify its listener when data
// is only buffered, and never flushed.
TEST_F(WindowManagerTest, DataOnlyBuffered) {
  size_t total = 0;
  while (total < kDefaultLimit) {
    size_t s = std::min<size_t>(kDefaultLimit - total, random_.Uniform(1024));
    total += s;
    wm_.MarkDataBuffered(s);
  }
  EXPECT_THAT(call_sequence_, ::testing::IsEmpty());
}

// This test verifies that WindowManager does notify its listener when data is
// buffered and subsequently flushed.
TEST_F(WindowManagerTest, DataBufferedAndFlushed) {
  size_t total_buffered = 0;
  size_t total_flushed = 0;
  while (call_sequence_.empty()) {
    size_t buffered =
        std::min<size_t>(kDefaultLimit - total_buffered, random_.Uniform(1024));
    wm_.MarkDataBuffered(buffered);
    total_buffered += buffered;
    EXPECT_TRUE(call_sequence_.empty());
    size_t flushed = random_.Uniform(total_buffered - total_flushed);
    wm_.MarkDataFlushed(flushed);
    total_flushed += flushed;
  }
  // If WindowManager decided to send an update, at least one third of the
  // window must have been consumed by buffered data.
  EXPECT_GE(total_buffered, kDefaultLimit / 3);
}

// Window manager should avoid window underflow.
TEST_F(WindowManagerTest, AvoidWindowUnderflow) {
  EXPECT_EQ(wm_.CurrentWindowSize(), wm_.WindowSizeLimit());
  // Don't buffer more than the total window!
  wm_.MarkDataBuffered(wm_.WindowSizeLimit() + 1);
  EXPECT_EQ(wm_.CurrentWindowSize(), 0u);
}

// Window manager should GFE_BUG and avoid buffered underflow.
TEST_F(WindowManagerTest, AvoidBufferedUnderflow) {
  EXPECT_EQ(peer_.buffered(), 0u);
  // Don't flush more than has been buffered!
  EXPECT_QUICHE_BUG(wm_.MarkDataFlushed(1), "buffered underflow");
  EXPECT_EQ(peer_.buffered(), 0u);

  wm_.MarkDataBuffered(42);
  EXPECT_EQ(peer_.buffered(), 42u);
  // Don't flush more than has been buffered!
  EXPECT_QUICHE_BUG(wm_.MarkDataFlushed(43), "buffered underflow");
  EXPECT_EQ(peer_.buffered(), 0u);
}

// This test verifies that WindowManager notifies its listener when window is
// consumed (data is ignored or immediately dropped).
TEST_F(WindowManagerTest, WindowConsumed) {
  size_t consumed = kDefaultLimit / 3 - 1;
  wm_.MarkWindowConsumed(consumed);
  EXPECT_TRUE(call_sequence_.empty());
  const size_t extra = 1;
  wm_.MarkWindowConsumed(extra);
  EXPECT_THAT(call_sequence_, testing::ElementsAre(consumed + extra));
}

// This test verifies that WindowManager notifies its listener when the window
// size limit is increased.
TEST_F(WindowManagerTest, ListenerCalledOnSizeUpdate) {
  wm_.SetWindowSizeLimit(kDefaultLimit - 1024);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.SetWindowSizeLimit(kDefaultLimit * 5);
  // Because max(outstanding window, previous limit) is kDefaultLimit, it is
  // only appropriate to increase the window by kDefaultLimit * 4.
  EXPECT_THAT(call_sequence_, testing::ElementsAre(kDefaultLimit * 4));
}

// This test verifies that when data is buffered and then the limit is
// decreased, WindowManager only notifies the listener once any outstanding
// window has been consumed.
TEST_F(WindowManagerTest, WindowUpdateAfterLimitDecreased) {
  wm_.MarkDataBuffered(kDefaultLimit - 1024);
  wm_.SetWindowSizeLimit(kDefaultLimit - 2048);

  // Now there are 2048 bytes of window outstanding beyond the current limit,
  // and we have 1024 bytes of data buffered beyond the current limit. This is
  // intentional, to be sure that WindowManager works properly if the limit is
  // decreased at runtime.

  wm_.MarkDataFlushed(512);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.MarkDataFlushed(512);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.MarkDataFlushed(512);
  EXPECT_TRUE(call_sequence_.empty());
  wm_.MarkDataFlushed(1024);
  EXPECT_THAT(call_sequence_, testing::ElementsAre(512));
}

// For normal behavior, we only call MaybeNotifyListener() when data is
// flushed. But if window runs out entirely, we still need to call
// MaybeNotifyListener() to avoid becoming artificially blocked when data isn't
// being flushed.
TEST_F(WindowManagerTest, ZeroWindowNotification) {
  // Consume a byte of window, but not enough to trigger an update.
  wm_.MarkWindowConsumed(1);

  // Buffer the remaining window.
  wm_.MarkDataBuffered(kDefaultLimit - 1);
  // Listener is notified of the remaining byte of possible window.
  EXPECT_THAT(call_sequence_, testing::ElementsAre(1));
}

}  // namespace
}  // namespace test
}  // namespace adapter
}  // namespace http2
