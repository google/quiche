// Copyright (c) 2025 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/tools/moqt_relay.h"

#include <cstdint>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <utility>


#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_publisher.h"
#include "quiche/quic/moqt/moqt_relay_publisher.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_session_interface.h"
#include "quiche/quic/moqt/test_tools/mock_moqt_session.h"
#include "quiche/quic/moqt/test_tools/moqt_mock_visitor.h"
#include "quiche/quic/moqt/tools/moqt_client.h"
#include "quiche/quic/moqt/tools/moqt_server.h"
#include "quiche/quic/test_tools/crypto_test_utils.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_weak_ptr.h"

namespace moqt {
namespace test {

using testing::ElementsAre;

constexpr quic::QuicTime::Delta kEventLoopDuration =
    quic::QuicTime::Delta::FromMilliseconds(50);

class TestMoqtRelay : public MoqtRelay {
 public:
  TestMoqtRelay(std::string bind_address, uint16_t bind_port,
                absl::string_view default_upstream, bool ignore_certificate,
                quic::QuicEventLoop* event_loop)
      : MoqtRelay(quic::test::crypto_test_utils::ProofSourceForTesting(),
                  bind_address, bind_port, default_upstream, ignore_certificate,
                  event_loop) {}

  quic::QuicEventLoop* server_event_loop() { return server()->event_loop(); }

  void RunOneEvent() {
    server_event_loop()->RunEventLoopOnce(kEventLoopDuration);
  }

  MoqtSession* client_session() {
    return (client() == nullptr) ? nullptr : client()->session();
  }

  MoqtRelayPublisher* publisher() { return MoqtRelay::publisher(); }

  virtual void SetNamespaceCallbacks(MoqtSessionInterface* session) override {
    last_server_session = session;
    MoqtRelay::SetNamespaceCallbacks(session);
  }

  MoqtSessionInterface* last_server_session;
};

class MoqtRelayTest : public quiche::test::QuicheTest {
 public:
  MoqtRelayTest()
      : upstream_("127.0.0.1", 9991, "", true, nullptr),  // no client.
        relay_("127.0.0.1", 9992, "https://127.0.0.1:9991", true,
               upstream_.server_event_loop()),
        downstream_("127.0.0.1", 9993, "https://127.0.0.1:9992", true,
                    relay_.server_event_loop()) {
    RunUntilConnected(relay_, upstream_);
    RunUntilConnected(downstream_, relay_);
  }

  inline bool ClientFullyConnected(TestMoqtRelay& client) {
    return client.publisher()->GetDefaultUpstreamSession().IsValid() &&
           client.publisher()->GetDefaultUpstreamSession().GetIfAvailable() ==
               client.client_session();
  }

  void RunUntilConnected(TestMoqtRelay& client, TestMoqtRelay& server) {
    int iterations_remaining = 20;
    while (!ClientFullyConnected(client) && iterations_remaining-- > 0) {
      server.RunOneEvent();
    }
    ASSERT_GT(iterations_remaining, 0);
  }

  TestMoqtRelay upstream_, relay_, downstream_;
};

TEST_F(MoqtRelayTest, NodeChainEstablished) {
  // relay_ and downstream_ have a default session.
  ASSERT_NE(downstream_.client_session(), nullptr);
  EXPECT_EQ(downstream_.client_session()->publisher(), downstream_.publisher());
  ASSERT_NE(downstream_.publisher(), nullptr);
  EXPECT_EQ(
      downstream_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
      downstream_.client_session()->GetWeakPtr().GetIfAvailable());

  ASSERT_NE(relay_.client_session(), nullptr);
  EXPECT_EQ(relay_.client_session()->publisher(), relay_.publisher());
  ASSERT_NE(relay_.publisher(), nullptr);
  EXPECT_EQ(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            relay_.client_session()->GetWeakPtr().GetIfAvailable());

  EXPECT_EQ(upstream_.client_session(), nullptr);
  ASSERT_NE(upstream_.publisher(), nullptr);
  EXPECT_EQ(upstream_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            nullptr);
}

TEST_F(MoqtRelayTest, CloseSession) {
  ASSERT_NE(relay_.client_session(), nullptr);
  std::move(relay_.client_session()->callbacks().session_terminated_callback)(
      "");
  EXPECT_FALSE(relay_.publisher()->GetDefaultUpstreamSession().IsValid());
}

TEST_F(MoqtRelayTest, PublishNamespace) {
  MockMoqtObjectListener object_listener;
  // No path to a subscribe. Test the upstream_ publisher because it doesn't
  // have a default upstream.
  EXPECT_EQ(upstream_.publisher()->GetTrack(FullTrackName("foo", "bar")),
            nullptr);
  // relay_ publishes a namespace, so upstream_ will route to relay_.
  relay_.client_session()->PublishNamespace(
      TrackNamespace({"foo"}),
      [](TrackNamespace, std::optional<MoqtErrorPair>) {},
      VersionSpecificParameters());
  upstream_.RunOneEvent();
  // There is now an upstream session for "Foo".
  std::shared_ptr<MoqtTrackPublisher> track =
      upstream_.publisher()->GetTrack(FullTrackName("foo", "bar"));
  EXPECT_NE(track, nullptr);
  track->AddObjectListener(&object_listener);
  track->RemoveObjectListener(&object_listener);
  // Track should have been destroyed.

  // Send PUBLISH_NAMESPACE_DONE
  relay_.client_session()->PublishNamespaceDone(TrackNamespace({"foo"}));
  upstream_.RunOneEvent();
  // Now there's nowhere to route for "foo".
  EXPECT_EQ(upstream_.publisher()->GetTrack(FullTrackName("foo", "bar")),
            nullptr);
}

TEST_F(MoqtRelayTest, SubscribeNamespace) {
  TrackNamespace foo({"foo"}), foobar({"foo", "bar"}), foobaz({"foo", "baz"});
  // These will be used to ascertain the namespace state.
  MockMoqtSession relay_probe, upstream_probe;
  std::set<TrackNamespace> relay_published_namespaces,
      upstream_published_namespaces;
  EXPECT_CALL(relay_probe, PublishNamespace)
      .WillRepeatedly([&](TrackNamespace track_namespace,
                          MoqtOutgoingPublishNamespaceCallback callback,
                          VersionSpecificParameters) {
        relay_published_namespaces.insert(track_namespace);
        (callback)(track_namespace, std::nullopt);
      });
  EXPECT_CALL(relay_probe, PublishNamespaceDone)
      .WillRepeatedly([&](TrackNamespace track_namespace) {
        relay_published_namespaces.erase(track_namespace);
        return true;
      });
  EXPECT_CALL(upstream_probe, PublishNamespace)
      .WillRepeatedly([&](TrackNamespace track_namespace,
                          MoqtOutgoingPublishNamespaceCallback callback,
                          VersionSpecificParameters) {
        upstream_published_namespaces.insert(track_namespace);
        (callback)(track_namespace, std::nullopt);
      });
  EXPECT_CALL(upstream_probe, PublishNamespaceDone)
      .WillRepeatedly([&](TrackNamespace track_namespace) {
        upstream_published_namespaces.erase(track_namespace);
        return true;
      });
  relay_.publisher()->AddNamespaceSubscriber(foo, &relay_probe);
  upstream_.publisher()->AddNamespaceSubscriber(foo, &upstream_probe);
  MoqtSession* upstream_session =
      static_cast<MoqtSession*>(upstream_.last_server_session);
  // Downstream publishes a namespace. It's stored in relay_ but upstream_
  // hasn't been notified.
  downstream_.client_session()->PublishNamespace(
      foobar, [](TrackNamespace, std::optional<MoqtErrorPair>) {},
      VersionSpecificParameters());
  relay_.RunOneEvent();
  upstream_.RunOneEvent();
  EXPECT_THAT(relay_published_namespaces, ElementsAre(foobar));
  EXPECT_TRUE(upstream_published_namespaces.empty());

  // Upstream subscribes. Now it's notified and forwards it to the probe.
  upstream_session->SubscribeNamespace(
      foo,
      [](TrackNamespace, std::optional<RequestErrorCode>, absl::string_view) {},
      VersionSpecificParameters());
  upstream_.RunOneEvent();
  upstream_.RunOneEvent();
  EXPECT_THAT(upstream_published_namespaces, ElementsAre(foobar));

  // Downstream publishes another namespace. Everyone is notified.
  downstream_.client_session()->PublishNamespace(
      foobaz, [](TrackNamespace, std::optional<MoqtErrorPair>) {},
      VersionSpecificParameters());
  relay_.RunOneEvent();
  upstream_.RunOneEvent();
  EXPECT_THAT(relay_published_namespaces, ElementsAre(foobar, foobaz));
  EXPECT_THAT(upstream_published_namespaces, ElementsAre(foobar, foobaz));

  // Unpublish the namespace.
  downstream_.client_session()->PublishNamespaceDone(foobar);
  relay_.RunOneEvent();
  upstream_.RunOneEvent();
  EXPECT_THAT(relay_published_namespaces, ElementsAre(foobaz));
  EXPECT_THAT(upstream_published_namespaces, ElementsAre(foobaz));

  // upstream_ unsubscribes. New PUBLISH_NAMESPACE_DONE doesn't arrive.
  upstream_session->UnsubscribeNamespace(foo);
  downstream_.client_session()->PublishNamespaceDone(foobaz);
  upstream_.RunOneEvent();
  relay_.RunOneEvent();
  EXPECT_TRUE(relay_published_namespaces.empty());
  EXPECT_THAT(upstream_published_namespaces, ElementsAre(foobaz));

  // Remove the probes to avoid accessing an invalid WeakPtr on teardown.
  relay_.publisher()->RemoveNamespaceSubscriber(foo, &relay_probe);
  upstream_.publisher()->RemoveNamespaceSubscriber(foo, &upstream_probe);
}

#if 0  // TODO(martinduke): Re-enable these tests when GOAWAY support exists.
TEST_F(MoqtRelayTest, GoAwayAtClient) {
  ASSERT_NE(relay_.client_session(), nullptr);
  // Provide the same URI again.
  MoqtSessionInterface* original_default_session =
      relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable();
  EXPECT_NE(original_default_session, nullptr);
  std::move(relay_.client_session()->callbacks().goaway_received_callback)(
      "https://127.0.0.1:9991");
  RunUntilConnected(relay_, upstream_);
  EXPECT_TRUE(relay_.publisher()->GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            relay_.client_session());
  EXPECT_NE(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            original_default_session);

  // Terminating the original session does nothing.
  std::move(original_default_session->callbacks().session_terminated_callback)(
      "test");
  EXPECT_TRUE(relay_.publisher()->GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            relay_.client_session());
}

TEST_F(MoqtRelayTest, TwoGoAwaysAtClient) {
  ASSERT_NE(relay_.client_session(), nullptr);
  // Provide the same URI again.
  MoqtSessionInterface* original_default_session =
      relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable();
  EXPECT_NE(original_default_session, nullptr);
  std::move(relay_.client_session()->callbacks().goaway_received_callback)(
      "https://127.0.0.1:9991");
  RunUntilConnected(relay_, upstream_);
  EXPECT_TRUE(relay_.publisher()->GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            relay_.client_session());
  EXPECT_NE(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            original_default_session);

  // The original session still exists, but the second session also receives
  // a GOAWAY.
  MoqtSessionInterface* second_default_session =
      relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable();
  EXPECT_NE(second_default_session, nullptr);
  EXPECT_NE(second_default_session, original_default_session);
  std::move(second_default_session->callbacks().goaway_received_callback)(
      "https://127.0.0.1:9991");
  RunUntilConnected(relay_, upstream_);
  EXPECT_TRUE(relay_.publisher()->GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            relay_.client_session());
  EXPECT_NE(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            second_default_session);

  // The original session is now been destroyed, along with its client. The test
  // might reuse original_session's address for the third session,
  // unfortunately, so comparing a pointer to original_default_session is
  // dangerous.
  // second_default_session still exists, so this call doesn't segfault.
  std::move(second_default_session->callbacks().session_terminated_callback)(
      "test");
  // Third session is still connected.
  EXPECT_TRUE(relay_.publisher()->GetDefaultUpstreamSession().IsValid());
  EXPECT_EQ(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            relay_.client_session());
  EXPECT_NE(relay_.publisher()->GetDefaultUpstreamSession().GetIfAvailable(),
            second_default_session);
}
#endif

// TODO(martinduke): Write tests for server sessions once there is related state
// that we can access.

}  // namespace test
}  // namespace moqt
