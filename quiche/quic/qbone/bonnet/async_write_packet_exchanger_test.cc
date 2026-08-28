// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/qbone/bonnet/async_write_packet_exchanger.h"

#include <netinet/icmp6.h>
#include <netinet/ip6.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <thread>  // NOLINT (for open-sourceable thread ID)
#include <utility>
#include <vector>

#include "absl/base/thread_annotations.h"
#include "absl/status/status.h"
#include "absl/strings/string_view.h"
#include "absl/synchronization/mutex.h"
#include "absl/time/time.h"
#include "absl/types/span.h"
#include "quiche/quic/platform/api/quic_test.h"
#include "quiche/quic/qbone/bonnet/mock_qbone_client_packet_exchanger.h"
#include "quiche/quic/qbone/bonnet/qbone_client_packet_exchanger.h"
#include "quiche/quic/qbone/platform/mock_kernel.h"
#include "quiche/quic/qbone/platform/mock_netlink.h"
#include "quiche/quic/qbone/qbone_constants.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_callbacks.h"
#include "quiche/common/quiche_endian.h"

namespace quic::test {
namespace {

constexpr size_t kMtu = 1000;
constexpr int kReadFd = 15;
constexpr int kWriteFd = 16;
constexpr int64_t kMaxBufferSizeBytes = 1024 * 1024;
constexpr int64_t kMaxResultsBufferSizeBytes = kMaxBufferSizeBytes;

using ::absl_testing::IsOkAndHolds;
using ::absl_testing::StatusIs;
using ::quiche::QuicheEndian;
using ::testing::_;
using ::testing::ElementsAre;
using ::testing::ElementsAreArray;
using ::testing::Field;
using ::testing::Mock;
using ::testing::Ne;
using ::testing::NiceMock;
using ::testing::SizeIs;
using ::testing::StrictMock;

// Executor that collects callbacks and only runs them when released via
// RunCallbacks().
class TestExecutor : public AsyncWritePacketExchanger::SiloExecutor {
 public:
  TestExecutor() = default;
  ~TestExecutor() override = default;

  void Stop() override {
    QUICHE_CHECK(IsOnSiloThread());

    absl::MutexLock lock(mutex_);
    stopped_ = true;

    // While a real executor is expected to be able to handle the case of
    // stopping with pending callbacks, it's an error here because it means the
    // executor received unexpected callbacks.
    QUICHE_CHECK(callbacks_.empty());
  }

  void ExecuteInSilo(quiche::SingleUseCallback<void()> callback) override {
    absl::MutexLock lock(mutex_);
    QUICHE_CHECK(!stopped_);
    callbacks_.push_back(std::move(callback));
  }

  void WaitForCallback() { WaitForNCallbacks(1); }

  void WaitForNCallbacks(int n) {
    absl::MutexLock lock(mutex_);
    QUICHE_CHECK_LE(num_expected_callbacks_, 0);
    num_expected_callbacks_ = n;

    QUICHE_CHECK(mutex_.AwaitWithTimeout(
        absl::Condition(this, &TestExecutor::HasExpectedCallbacks),
        absl::Seconds(5)));
    QUICHE_CHECK(!stopped_);

    num_expected_callbacks_ = 0;
  }

  void RunCallbacks() {
    QUICHE_CHECK(IsOnSiloThread());

    std::vector<quiche::SingleUseCallback<void()>> to_run;
    {
      absl::MutexLock lock(mutex_);
      QUICHE_CHECK(!stopped_);
      to_run.swap(callbacks_);
    }
    for (auto& cb : to_run) {
      std::move(cb)();
    }
  }

 private:
  bool HasExpectedCallbacks() const ABSL_SHARED_LOCKS_REQUIRED(mutex_) {
    return stopped_ || callbacks_.size() >= num_expected_callbacks_;
  }

  bool IsOnSiloThread() const override {
    return std::this_thread::get_id() == thread_id_;
  }

  const std::thread::id thread_id_ = std::this_thread::get_id();

  mutable absl::Mutex mutex_;
  bool stopped_ ABSL_GUARDED_BY(mutex_) = false;
  std::vector<quiche::SingleUseCallback<void()>> callbacks_
      ABSL_GUARDED_BY(mutex_);
  int num_expected_callbacks_ ABSL_GUARDED_BY(mutex_) = 0;
};

class AsyncWritePacketExchangerTest : public QuicTest {
 protected:
  AsyncWritePacketExchangerTest() {
    auto executor = std::make_unique<TestExecutor>();
    executor_ = executor.get();
    exchanger_ = std::make_unique<AsyncWritePacketExchanger>(
        kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, /*is_tap=*/false,
        "ifname", kMaxBufferSizeBytes, kMaxResultsBufferSizeBytes,
        std::move(executor));
  }

  ~AsyncWritePacketExchangerTest() override = default;

  void ValidateOnMainThread() {
    QUICHE_CHECK_EQ(std::this_thread::get_id(), thread_id_);
  }

  void ValidateOffThread() {
    QUICHE_CHECK_NE(std::this_thread::get_id(), thread_id_);
  }

  const std::thread::id thread_id_ = std::this_thread::get_id();

  StrictMock<MockKernel> mock_kernel_;
  NiceMock<MockNetlink> mock_netlink_;
  StrictMock<MockQboneClientPacketExchanger::MockVisitor> mock_visitor_;
  TestExecutor* executor_;
  std::unique_ptr<AsyncWritePacketExchanger> exchanger_;
};

TEST_F(AsyncWritePacketExchangerTest, WritePacket) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake packet";

  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([this, &packet](int /*fd*/, const struct iovec* iov,
                                int /*iovcnt*/) -> ssize_t {
        ValidateOffThread();
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(absl::string_view(static_cast<const char*>(iov[1].iov_base),
                                    iov[1].iov_len),
                  packet);
        EXPECT_EQ(iov[1].iov_len, packet.size());
        return packet.size();
      });
  exchanger_->WritePacketToNetwork(absl::MakeConstSpan(
      reinterpret_cast<const std::byte*>(packet.data()), packet.size()));

  executor_->WaitForCallback();
  EXPECT_TRUE(Mock::VerifyAndClear(&mock_visitor_));

  EXPECT_CALL(
      mock_visitor_,
      OnWrite(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::WriteResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))));
  executor_->RunCallbacks();

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, WritePacketError) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake packet";

  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([this, &packet](int /*fd*/, const struct iovec* iov,
                                int /*iovcnt*/) -> ssize_t {
        ValidateOffThread();
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(absl::string_view(static_cast<const char*>(iov[1].iov_base),
                                    iov[1].iov_len),
                  packet);
        EXPECT_EQ(iov[1].iov_len, packet.size());
        errno = EAGAIN;
        return -1;
      });

  exchanger_->WritePacketToNetwork(absl::MakeConstSpan(
      reinterpret_cast<const std::byte*>(packet.data()), packet.size()));

  executor_->WaitForCallback();
  EXPECT_TRUE(Mock::VerifyAndClear(&mock_visitor_));

  EXPECT_CALL(mock_visitor_, OnWrite(StatusIs(Ne(absl::StatusCode::kOk))));

  executor_->RunCallbacks();

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, RestartExchanger) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);
  exchanger_->Stop();

  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake packet";

  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([this, &packet](int /*fd*/, const struct iovec* iov,
                                int /*iovcnt*/) -> ssize_t {
        ValidateOffThread();
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(absl::string_view(static_cast<const char*>(iov[1].iov_base),
                                    iov[1].iov_len),
                  packet);
        EXPECT_EQ(iov[1].iov_len, packet.size());
        return packet.size();
      });

  exchanger_->WritePacketToNetwork(absl::MakeConstSpan(
      reinterpret_cast<const std::byte*>(packet.data()), packet.size()));

  executor_->WaitForCallback();
  EXPECT_TRUE(Mock::VerifyAndClear(&mock_visitor_));

  EXPECT_CALL(
      mock_visitor_,
      OnWrite(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::WriteResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))));

  executor_->RunCallbacks();

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, ReadPacket) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake_packet";
  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce(
          [this, packet](int /*fd*/, const struct iovec* iov, int /*iovcnt*/) {
            ValidateOnMainThread();
            EXPECT_EQ(iov[0].iov_len, 0);
            EXPECT_EQ(iov[1].iov_len, kMtu);
            ::memcpy(iov[1].iov_base, packet.data(), packet.size());
            return packet.size();
          });
  EXPECT_CALL(
      mock_visitor_,
      OnRead(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::ReadResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))));
  EXPECT_EQ(exchanger_->OnReadFromNetworkReady(/*max_packets_to_read=*/1), 1);

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, ReadPacketError) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce(
          [this](int /*fd*/, const struct iovec* /*iov*/, int /*iovcnt*/) {
            ValidateOnMainThread();
            errno = ECOMM;
            return -1;
          });
  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(Ne(absl::StatusCode::kOk))));
  EXPECT_EQ(exchanger_->OnReadFromNetworkReady(/*max_packets_to_read=*/1), 0);

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, ReadPacketBlocked) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce(
          [this](int /*fd*/, const struct iovec* /*iov*/, int /*iovcnt*/) {
            ValidateOnMainThread();
            errno = EAGAIN;
            return -1;
          });
  EXPECT_CALL(mock_visitor_, OnRead(StatusIs(Ne(absl::StatusCode::kOk))));
  EXPECT_EQ(exchanger_->OnReadFromNetworkReady(/*max_packets_to_read=*/1), 0);

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, WriteBufferFull) {
  auto executor = std::make_unique<TestExecutor>();
  executor_ = executor.get();

  // Create an exchanger with a very small buffer.
  exchanger_ = std::make_unique<AsyncWritePacketExchanger>(
      kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, false,
      absl::string_view(), /*max_buffer_size_bytes=*/5,
      kMaxResultsBufferSizeBytes, std::move(executor));
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake packet";  // size 11

  // Write should immediately fail and call OnWrite because buffer is full (max
  // size 5, packet is 11)
  EXPECT_CALL(mock_visitor_,
              OnWrite(StatusIs(absl::StatusCode::kResourceExhausted)));

  exchanger_->WritePacketToNetwork(absl::MakeConstSpan(
      reinterpret_cast<const std::byte*>(packet.data()), packet.size()));

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, WriteResultBufferFull) {
  auto executor = std::make_unique<TestExecutor>();
  executor_ = executor.get();

  // Create an exchanger with a very small response buffer.
  exchanger_ = std::make_unique<AsyncWritePacketExchanger>(
      kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, false,
      absl::string_view(), kMaxBufferSizeBytes,
      /*max_result_buffer_size_bytes=*/5, std::move(executor));
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake packet";  // size 11

  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([this, &packet](int /*fd*/, const struct iovec* iov,
                                int /*iovcnt*/) -> ssize_t {
        ValidateOffThread();
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(absl::string_view(static_cast<const char*>(iov[1].iov_base),
                                    iov[1].iov_len),
                  packet);
        EXPECT_EQ(iov[1].iov_len, packet.size());
        return packet.size();
      });
  exchanger_->WritePacketToNetwork(absl::MakeConstSpan(
      reinterpret_cast<const std::byte*>(packet.data()), packet.size()));

  executor_->WaitForCallback();
  EXPECT_TRUE(Mock::VerifyAndClear(&mock_visitor_));

  // Expect no interaction with the visitor as no results were added to the
  // result buffer.

  executor_->RunCallbacks();

  exchanger_->Stop();
}

TEST_F(AsyncWritePacketExchangerTest, StopWithPendingWrites) {
  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  std::string packet = "fake packet";
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([this, &packet](int /*fd*/, const struct iovec* iov,
                                int /*iovcnt*/) -> ssize_t {
        ValidateOffThread();
        EXPECT_EQ(iov[0].iov_base, nullptr);
        EXPECT_EQ(iov[0].iov_len, 0);
        EXPECT_EQ(absl::string_view(static_cast<const char*>(iov[1].iov_base),
                                    iov[1].iov_len),
                  packet);
        EXPECT_EQ(iov[1].iov_len, packet.size());
        return packet.size();
      });

  EXPECT_CALL(
      mock_visitor_,
      OnWrite(IsOkAndHolds(ElementsAre(Field(
          &QboneClientPacketExchanger::WriteResult::packet,
          ElementsAreArray(reinterpret_cast<const std::byte*>(packet.data()),
                           packet.size()))))));

  exchanger_->WritePacketToNetwork(absl::MakeConstSpan(
      reinterpret_cast<const std::byte*>(packet.data()), packet.size()));

  // Immediately call Stop() without waiting for completion/callbacks. Expect to
  // cleanly block on completion and run visitor callbacks.
  exchanger_->Stop();

  // Executor may have stale callbacks queued up, but visitor callbacks should
  // already have been made.
  EXPECT_TRUE(Mock::VerifyAndClear(&mock_visitor_));
  executor_->RunCallbacks();
}

// Neighbor solicitation packets over a TAP interface are expected to be
// immediately responded to. Ensure that response is correctly handled
// off-thread.
TEST_F(AsyncWritePacketExchangerTest, ReadNeighborSolicitationPacket) {
  auto executor = std::make_unique<TestExecutor>();
  executor_ = executor.get();

  // Create an exchanger with TAP enabled.
  exchanger_ = std::make_unique<AsyncWritePacketExchanger>(
      kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, /*is_tap=*/true,
      absl::string_view(), kMaxBufferSizeBytes, kMaxResultsBufferSizeBytes,
      std::move(executor));

  exchanger_->Start(kReadFd, kWriteFd, /*exchanger=*/nullptr);

  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = IPPROTO_ICMPV6;
  inet_pton(AF_INET6, "fe80::2", &ip_hdr.ip6_src);
  inet_pton(AF_INET6, "fe80::1", &ip_hdr.ip6_dst);

  icmp6_hdr icmp_hdr{};
  icmp_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;

  in6_addr target_address = QboneConstants::GatewayAddress()->GetIPv6();

  std::vector<std::byte> l3_packet(sizeof(ip_hdr) + sizeof(icmp_hdr) +
                                   sizeof(target_address));
  ::memcpy(l3_packet.data(), &ip_hdr, sizeof(ip_hdr));
  ::memcpy(l3_packet.data() + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));
  ::memcpy(l3_packet.data() + sizeof(ip_hdr) + sizeof(icmp_hdr),
           &target_address, sizeof(target_address));

  ethhdr eth_hdr{};
  eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([this, l3_packet, eth_hdr](int /*fd*/, const struct iovec* iov,
                                           int /*iovcnt*/) {
        ValidateOnMainThread();
        EXPECT_EQ(iov[0].iov_len, ETH_HLEN);
        ::memcpy(iov[0].iov_base, &eth_hdr, ETH_HLEN);
        EXPECT_EQ(iov[1].iov_len, kMtu);
        ::memcpy(iov[1].iov_base, l3_packet.data(), l3_packet.size());
        return ETH_HLEN + l3_packet.size();
      });

  // Expect neighbor solicitation response to be written out asynchronously.
  EXPECT_CALL(mock_kernel_, writev(kWriteFd, _, 2))
      .WillOnce([this](int fd, const struct iovec* iov, int iovcnt) -> ssize_t {
        ValidateOffThread();
        return iov[0].iov_len + iov[1].iov_len;
      });

  EXPECT_EQ(exchanger_->OnReadFromNetworkReady(/*max_packets_to_read=*/1), 1);

  executor_->WaitForCallback();
  EXPECT_TRUE(Mock::VerifyAndClear(&mock_visitor_));

  // Because the read packet is link-local and immediately responded to, expect
  // the visitor to be called with a *write* result.
  EXPECT_CALL(mock_visitor_, OnWrite(IsOkAndHolds(SizeIs(1))));
  executor_->RunCallbacks();

  exchanger_->Stop();
}

// Ensure that if an outer exchanger is provided, it is used for internal
// writes, e.g. neighbor solicitation responses.
TEST_F(AsyncWritePacketExchangerTest,
       ReadNeighborSolicitationPacketWithOuterExchanger) {
  auto executor = std::make_unique<TestExecutor>();
  executor_ = executor.get();

  // Create an exchanger with TAP enabled.
  exchanger_ = std::make_unique<AsyncWritePacketExchanger>(
      kMtu, &mock_kernel_, &mock_netlink_, &mock_visitor_, /*is_tap=*/true,
      absl::string_view(), kMaxBufferSizeBytes, kMaxResultsBufferSizeBytes,
      std::move(executor));

  StrictMock<MockQboneClientPacketExchanger> mock_outer_exchanger;
  exchanger_->Start(kReadFd, kWriteFd, &mock_outer_exchanger);

  ip6_hdr ip_hdr{};
  ip_hdr.ip6_vfc = 0x60;  // Version 6
  ip_hdr.ip6_nxt = IPPROTO_ICMPV6;
  inet_pton(AF_INET6, "fe80::2", &ip_hdr.ip6_src);
  inet_pton(AF_INET6, "fe80::1", &ip_hdr.ip6_dst);

  icmp6_hdr icmp_hdr{};
  icmp_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;

  in6_addr target_address = QboneConstants::GatewayAddress()->GetIPv6();

  std::vector<std::byte> l3_packet(sizeof(ip_hdr) + sizeof(icmp_hdr) +
                                   sizeof(target_address));
  ::memcpy(l3_packet.data(), &ip_hdr, sizeof(ip_hdr));
  ::memcpy(l3_packet.data() + sizeof(ip_hdr), &icmp_hdr, sizeof(icmp_hdr));
  ::memcpy(l3_packet.data() + sizeof(ip_hdr) + sizeof(icmp_hdr),
           &target_address, sizeof(target_address));

  ethhdr eth_hdr{};
  eth_hdr.h_proto = QuicheEndian::HostToNet16(ETH_P_IPV6);

  EXPECT_CALL(mock_kernel_, readv(kReadFd, _, 2))
      .WillOnce([this, l3_packet, eth_hdr](int /*fd*/, const struct iovec* iov,
                                           int /*iovcnt*/) {
        ValidateOnMainThread();
        EXPECT_EQ(iov[0].iov_len, ETH_HLEN);
        ::memcpy(iov[0].iov_base, &eth_hdr, ETH_HLEN);
        EXPECT_EQ(iov[1].iov_len, kMtu);
        ::memcpy(iov[1].iov_base, l3_packet.data(), l3_packet.size());
        return ETH_HLEN + l3_packet.size();
      });

  // Expect neighbor solicitation response to be written via the outer
  // exchanger.
  EXPECT_CALL(mock_outer_exchanger, WritePacketToNetwork(_));

  // No visitor callback expected because that is handled by the outer
  // exchanger, here a mock that doesn't actually do it.

  EXPECT_EQ(exchanger_->OnReadFromNetworkReady(/*max_packets_to_read=*/1), 1);

  exchanger_->Stop();
}

}  // namespace
}  // namespace quic::test
