// Copyright (c) 2017 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "net/third_party/quiche/src/quic/quartc/quartc_endpoint.h"
#include "net/third_party/quiche/src/quic/core/quic_version_manager.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_ptr_util.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_connection_helper.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_crypto_helpers.h"
#include "net/third_party/quiche/src/quic/quartc/quartc_dispatcher.h"

namespace quic {

namespace {

// Wrapper around a QuicAlarmFactory which delegates to the wrapped factory.
// Usee to convert an unowned pointer into an owned pointer, so that the new
// "owner" does not delete the underlying factory.  Note that this is only valid
// when the unowned pointer is already guaranteed to outlive the new "owner".
class QuartcAlarmFactoryWrapper : public QuicAlarmFactory {
 public:
  explicit QuartcAlarmFactoryWrapper(QuicAlarmFactory* impl) : impl_(impl) {}

  QuicAlarm* CreateAlarm(QuicAlarm::Delegate* delegate) override;
  QuicArenaScopedPtr<QuicAlarm> CreateAlarm(
      QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
      QuicConnectionArena* arena) override;

 private:
  QuicAlarmFactory* impl_;
};

QuicAlarm* QuartcAlarmFactoryWrapper::CreateAlarm(
    QuicAlarm::Delegate* delegate) {
  return impl_->CreateAlarm(delegate);
}

QuicArenaScopedPtr<QuicAlarm> QuartcAlarmFactoryWrapper::CreateAlarm(
    QuicArenaScopedPtr<QuicAlarm::Delegate> delegate,
    QuicConnectionArena* arena) {
  return impl_->CreateAlarm(std::move(delegate), arena);
}

QuartcFactoryConfig CreateFactoryConfig(QuicAlarmFactory* alarm_factory,
                                        const QuicClock* clock) {
  QuartcFactoryConfig config;
  config.alarm_factory = alarm_factory;
  config.clock = clock;
  return config;
}

}  // namespace

QuartcClientEndpoint::QuartcClientEndpoint(
    QuicAlarmFactory* alarm_factory,
    const QuicClock* clock,
    QuartcEndpoint::Delegate* delegate,
    QuicStringPiece serialized_server_config)
    : alarm_factory_(alarm_factory),
      clock_(clock),
      delegate_(delegate),
      serialized_server_config_(serialized_server_config),
      create_session_alarm_(QuicWrapUnique(
          alarm_factory_->CreateAlarm(new CreateSessionDelegate(this)))),
      factory_(QuicMakeUnique<QuartcFactory>(
          CreateFactoryConfig(alarm_factory, clock))) {}

void QuartcClientEndpoint::Connect(const QuartcSessionConfig& config) {
  config_ = config;
  create_session_alarm_->Set(clock_->Now());
}

void QuartcClientEndpoint::OnCreateSessionAlarm() {
  session_ =
      factory_->CreateQuartcClientSession(config_, serialized_server_config_);
  delegate_->OnSessionCreated(session_.get());
}

QuartcServerEndpoint::QuartcServerEndpoint(QuicAlarmFactory* alarm_factory,
                                           const QuicClock* clock,
                                           QuartcEndpoint::Delegate* delegate)
    : alarm_factory_(alarm_factory), clock_(clock), delegate_(delegate) {}

void QuartcServerEndpoint::Connect(const QuartcSessionConfig& config) {
  auto connection_helper = QuicMakeUnique<QuartcConnectionHelper>(clock_);
  auto crypto_config = CreateCryptoServerConfig(
      connection_helper->GetRandomGenerator(), clock_, config.pre_shared_key);
  dispatcher_ = QuicMakeUnique<QuartcDispatcher>(
      QuicMakeUnique<QuicConfig>(CreateQuicConfig(config)),
      std::move(crypto_config.config), crypto_config.serialized_crypto_config,
      QuicMakeUnique<QuicVersionManager>(AllSupportedVersions()),
      std::move(connection_helper),
      QuicMakeUnique<QuartcCryptoServerStreamHelper>(),
      QuicMakeUnique<QuartcAlarmFactoryWrapper>(alarm_factory_),
      QuicMakeUnique<QuartcPacketWriter>(config.packet_transport,
                                         config.max_packet_size),
      this);
  // The dispatcher requires at least one call to |ProcessBufferedChlos| to
  // set the number of connections it is allowed to create.
  dispatcher_->ProcessBufferedChlos(/*max_connections_to_create=*/1);
}

void QuartcServerEndpoint::OnSessionCreated(QuartcSession* session) {
  delegate_->OnSessionCreated(session);
}

}  // namespace quic
