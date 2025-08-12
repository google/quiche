// Copyright 2025 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/core/http/quic_connection_migration_manager.h"

#include <cstddef>
#include <list>
#include <memory>
#include <optional>
#include <string>
#include <utility>

#include "absl/base/nullability.h"
#include "absl/strings/str_format.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/http/quic_spdy_client_session_with_migration.h"
#include "quiche/quic/core/quic_alarm.h"
#include "quiche/quic/core/quic_clock.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_connection_context.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_force_blockable_packet_writer.h"
#include "quiche/quic/core/quic_packet_writer.h"
#include "quiche/quic/core/quic_path_context_factory.h"
#include "quiche/quic/core/quic_path_validator.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/platform/api/quic_client_stats.h"
#include "quiche/quic/platform/api/quic_logging.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/common/platform/api/quiche_client_stats.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_callbacks.h"

namespace quic {

namespace {
// Time to wait (in seconds) when no networks are available and
// migrating sessions need to wait for a new network to connect.
const size_t kWaitTimeForNewNetworkSecs = 10;

class WaitForMigrationDelegate : public QuicAlarm::Delegate {
 public:
  explicit WaitForMigrationDelegate(
      QuicConnectionMigrationManager* absl_nonnull migration_manager,
      QuicConnectionContext* absl_nullable context)
      : migration_manager_(migration_manager), context_(context) {}
  WaitForMigrationDelegate(const WaitForMigrationDelegate&) = delete;
  WaitForMigrationDelegate& operator=(const WaitForMigrationDelegate&) = delete;
  QuicConnectionContext* GetConnectionContext() override { return context_; }
  void OnAlarm() override { migration_manager_->OnMigrationTimeout(); }

 private:
  QuicConnectionMigrationManager* absl_nonnull migration_manager_;
  QuicConnectionContext* absl_nullable context_;
};

std::string MigrationCauseToString(MigrationCause cause) {
  switch (cause) {
    case MigrationCause::UNKNOWN_CAUSE:
      return "Unknown";
    case MigrationCause::ON_NETWORK_CONNECTED:
      return "OnNetworkConnected";
    case MigrationCause::ON_NETWORK_DISCONNECTED:
      return "OnNetworkDisconnected";
    case MigrationCause::ON_WRITE_ERROR:
      return "OnWriteError";
    case MigrationCause::ON_NETWORK_MADE_DEFAULT:
      return "OnNetworkMadeDefault";
    case MigrationCause::ON_MIGRATE_BACK_TO_DEFAULT_NETWORK:
      return "OnMigrateBackToDefaultNetwork";
    case MigrationCause::CHANGE_NETWORK_ON_PATH_DEGRADING:
      return "OnPathDegrading";
    case MigrationCause::CHANGE_PORT_ON_PATH_DEGRADING:
      return "ChangePortOnPathDegrading";
    case MigrationCause::NEW_NETWORK_CONNECTED_POST_PATH_DEGRADING:
      return "NewNetworkConnectedPostPathDegrading";
    case MigrationCause::ON_SERVER_PREFERRED_ADDRESS_AVAILABLE:
      return "OnServerPreferredAddressAvailable";
    default:
      QUICHE_NOTREACHED();
      break;
  }
  return "InvalidCause";
}

}  // namespace

QuicConnectionMigrationManager::QuicConnectionMigrationManager(
    QuicSpdyClientSessionWithMigration* absl_nonnull session,
    const quic::QuicClock* absl_nonnull clock,
    QuicNetworkHandle /*default_network*/, QuicNetworkHandle current_network,
    QuicPathContextFactory* absl_nonnull path_context_factory,
    const QuicConnectionMigrationConfig& config)
    : session_(session),
      connection_(session->connection()),
      clock_(clock),
      current_network_(current_network),
      path_context_factory_(path_context_factory),
      config_(config),
      wait_for_migration_alarm_(connection_->alarm_factory()->CreateAlarm(
          new WaitForMigrationDelegate(this, connection_->context()))) {}

QuicConnectionMigrationManager::~QuicConnectionMigrationManager() {
  wait_for_migration_alarm_->PermanentCancel();
}

void QuicConnectionMigrationManager::OnNetworkDisconnected(
    QuicNetworkHandle disconnected_network) {
  LogMetricsOnNetworkDisconnected();
  if (debug_visitor_) {
    debug_visitor_->OnNetworkDisconnected(disconnected_network);
  }
  if (!session_->version().HasIetfQuicFrames()) {
    return;
  }
  if (!config_.migrate_session_on_network_change) {
    return;
  }
  if (debug_visitor_) {
    debug_visitor_->OnConnectionMigrationAfterNetworkDisconnected(
        disconnected_network);
  }
  // Stop probing the disconnected network if there is one.
  QuicPathValidationContext* context = connection_->GetPathValidationContext();
  if (context && context->network() == disconnected_network &&
      context->peer_address() == connection_->peer_address()) {
    connection_->CancelPathValidation();
  }

  // Ignore the signal if the current active network is not affected.
  if (current_network() != disconnected_network) {
    QUIC_DVLOG(1) << "Client's current default network is not affected by the "
                  << "disconnected one.";
    return;
  }
  current_migration_cause_ = MigrationCause::ON_NETWORK_DISCONNECTED;
  LogHandshakeStatusOnMigrationSignal();
  if (!session_->OneRttKeysAvailable()) {
    // Close the connection if handshake has not completed. Migration before
    // that is not allowed.
    // TODO(danzh): the current behavior aligns with Chrome. But according to
    // IETF spec, check handshake confirmed instead.
    session_->OnConnectionToBeClosedDueToMigrationError(
        current_migration_cause_,
        QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED);
    connection_->CloseConnection(
        QUIC_CONNECTION_MIGRATION_HANDSHAKE_UNCONFIRMED,
        "Network disconnected before handshake complete.",
        ConnectionCloseBehavior::SILENT_CLOSE);
    return;
  }
  // Attempt to find alternative network.
  QuicNetworkHandle new_network =
      session_->FindAlternateNetwork(disconnected_network);
  if (new_network == kInvalidNetworkHandle) {
    OnNoNewNetwork();
    return;
  }
  // Current network is being disconnected, migrate immediately to the
  // alternative network.
  MigrateNetworkImmediately(new_network);
}
void QuicConnectionMigrationManager::MigrateNetworkImmediately(
    QuicNetworkHandle network) {
  // There is no choice but to migrate to |network|. If any error encountered,
  // close the session. When migration succeeds:
  // - if no longer on the default network, start timer to migrate back;
  // - otherwise, it's brought to default network, cancel the running timer to
  //   migrate back.
  QUICHE_DCHECK(config_.migrate_session_on_network_change);
  if (MaybeCloseIdleSession(/*has_write_error=*/false,
                            ConnectionCloseBehavior::SILENT_CLOSE)) {
    return;
  }
  // Do not migrate if connection migration is disabled.
  if (migration_disabled_) {
    session_->OnConnectionToBeClosedDueToMigrationError(
        current_migration_cause_, QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG);
    connection_->CloseConnection(QUIC_CONNECTION_MIGRATION_DISABLED_BY_CONFIG,
                                 "Migration disabled by config",
                                 ConnectionCloseBehavior::SILENT_CLOSE);
    OnMigrationFailure(
        QuicConnectionMigrationStatus::MIGRATION_STATUS_DISABLED_BY_CONFIG,
        "Migration disabled by config");
    return;
  }
  if (network == current_network()) {
    OnMigrationFailure(
        QuicConnectionMigrationStatus::MIGRATION_STATUS_ALREADY_MIGRATED,
        "Already bound to new network");
    return;
  }
  // Cancel probing on |network| if there is any.
  QuicPathValidationContext* context = connection_->GetPathValidationContext();
  if (context && context->network() == network &&
      context->peer_address() == connection_->peer_address()) {
    connection_->CancelPathValidation();
  }
  pending_migrate_network_immediately_ = true;
  Migrate(network, connection_->peer_address(),
          /*close_session_on_error=*/true,
          [this](QuicNetworkHandle network, MigrationResult result) {
            FinishMigrateNetworkImmediately(network, result);
          });
}

QuicConnectionMigrationManager::
    PathContextCreationResultDelegateForImmediateMigration::
        PathContextCreationResultDelegateForImmediateMigration(
            QuicConnectionMigrationManager* absl_nonnull migration_manager,
            bool close_session_on_error, MigrationCallback migration_callback)
    : migration_manager_(migration_manager),
      close_session_on_error_(close_session_on_error),
      migration_callback_(std::move(migration_callback)) {}

void QuicConnectionMigrationManager::
    PathContextCreationResultDelegateForImmediateMigration::OnCreationSucceeded(
        std::unique_ptr<QuicPathValidationContext> context) {
  migration_manager_->FinishMigrate(std::move(context), close_session_on_error_,
                                    std::move(migration_callback_));
}

void QuicConnectionMigrationManager::
    PathContextCreationResultDelegateForImmediateMigration::OnCreationFailed(
        QuicNetworkHandle network, absl::string_view error) {
  static_cast<QuicForceBlockablePacketWriter*>(
      migration_manager_->connection_->writer())
      ->ForceWriteBlocked(false);
  std::move(migration_callback_)(network, MigrationResult::FAILURE);
  if (close_session_on_error_) {
    migration_manager_->session_->OnConnectionToBeClosedDueToMigrationError(
        migration_manager_->current_migration_cause_,
        QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR);
    migration_manager_->session_->connection()->CloseConnection(
        QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR,
        "Failed to create a path context",
        ConnectionCloseBehavior::SILENT_CLOSE);
  }
  migration_manager_->OnMigrationFailure(
      QuicConnectionMigrationStatus::MIGRATION_STATUS_INTERNAL_ERROR, error);
}

void QuicConnectionMigrationManager::Migrate(
    QuicNetworkHandle network, QuicSocketAddress peer_address,
    bool close_session_on_error, MigrationCallback migration_callback) {
  migration_attempted_ = true;
  migration_successful_ = false;
  if (!path_context_factory_) {
    std::move(migration_callback)(network, MigrationResult::FAILURE);
    return;
  }
  if (network != kInvalidNetworkHandle) {
    // This is a migration attempt from connection migration.
    session_->ResetNonMigratableStreams();
    if (!config_.migrate_idle_session && !session_->HasActiveRequestStreams()) {
      std::move(migration_callback)(network, MigrationResult::FAILURE);
      // If idle sessions can not be migrated, close the session if needed.
      if (close_session_on_error) {
        session_->OnConnectionToBeClosedDueToMigrationError(
            current_migration_cause_,
            QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS);
        connection_->CloseConnection(
            QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
            "Migrating idle session is disabled.",
            ConnectionCloseBehavior::SILENT_CLOSE);
      }
      return;
    }
  } else {
    // TODO(b/430345640): remove the if condition if the historgram is not hit
    // at all in production.
    QUIC_CLIENT_HISTOGRAM_BOOL(
        "Net.QuicSession.MigratingToInvalidNetwork", true,
        "Connection is migrating with an invalid network handle.");
  }
  QUIC_DVLOG(1) << "Force blocking the current packet writer";
  static_cast<QuicForceBlockablePacketWriter*>(connection_->writer())
      ->ForceWriteBlocked(true);
  if (config_.disable_blackhole_detection_on_immediate_migrate) {
    // Turn off the black hole detector since the writer is blocked.
    // Blackhole will be re-enabled once a packet is sent again.
    connection_->blackhole_detector().StopDetection(false);
  }
  path_context_factory_->CreatePathValidationContext(
      network, peer_address,
      std::make_unique<PathContextCreationResultDelegateForImmediateMigration>(
          this, close_session_on_error, std::move(migration_callback)));
}

void QuicConnectionMigrationManager::FinishMigrateNetworkImmediately(
    QuicNetworkHandle /*network*/, MigrationResult /*result*/) {
  pending_migrate_network_immediately_ = false;
  // TODO(danzh): check whether the session is on the default network or not. If
  // not, set timer to migrate back to default network.
}

void QuicConnectionMigrationManager::FinishMigrate(
    std::unique_ptr<QuicPathValidationContext> path_context,
    bool close_session_on_error, MigrationCallback callback) {
  // Migrate to the new socket.
  MigrationCause current_migration_cause = current_migration_cause_;
  QuicNetworkHandle network = path_context->network();
  if (!session_->MigrateToNewPath(std::move(path_context))) {
    static_cast<QuicForceBlockablePacketWriter*>(connection_->writer())
        ->ForceWriteBlocked(false);
    std::move(callback)(network, MigrationResult::FAILURE);
    if (close_session_on_error) {
      session_->OnConnectionToBeClosedDueToMigrationError(
          current_migration_cause, QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR);
      connection_->CloseConnection(QUIC_CONNECTION_MIGRATION_INTERNAL_ERROR,
                                   "Session failed to migrate to new path.",
                                   ConnectionCloseBehavior::SILENT_CLOSE);
    }
    return;
  }
  current_network_ = network;
  wait_for_migration_alarm_->Cancel();
  migration_successful_ = true;
  OnMigrationSuccess();
  std::move(callback)(network, MigrationResult::SUCCESS);
}

void QuicConnectionMigrationManager::OnNoNewNetwork() {
  QUICHE_DCHECK(session_->OneRttKeysAvailable());
  wait_for_new_network_ = true;
  if (debug_visitor_) {
    debug_visitor_->OnWaitingForNewNetworkToMigrate();
  }
  QUIC_DVLOG(1) << "Force blocking the packet writer while waiting for new "
                   "netowrk for migraion cause "
                << MigrationCauseToString(current_migration_cause_);
  // Force blocking the packet writer to avoid any writes since there is no
  // alternate network available.
  static_cast<QuicForceBlockablePacketWriter*>(connection_->writer())
      ->ForceWriteBlocked(true);
  if (config_.disable_blackhole_detection_on_immediate_migrate) {
    // Turn off the black hole detector since the writer is blocked.
    // Blackhole will be re-enabled once a packet is sent again.
    connection_->blackhole_detector().StopDetection(false);
  }
  session_->OnNoNewNetworkForMigration();
  // Set an alarm to close the session if not being able to migrate to a new
  // network soon.
  if (!wait_for_migration_alarm_->IsSet()) {
    wait_for_migration_alarm_->Set(
        clock_->ApproximateNow() +
        QuicTimeDelta::FromSeconds(kWaitTimeForNewNetworkSecs));
  }
}

void QuicConnectionMigrationManager::OnMigrationTimeout() {
  if (debug_visitor_) {
    debug_visitor_->OnWaitForNetworkFailed();
  }
  MigrationCause current_migration_cause = current_migration_cause_;
  // |current_migration_cause_| will be reset after logging.
  ResetMigrationCauseAndLogResult(
      QuicConnectionMigrationStatus::MIGRATION_STATUS_TIMEOUT);
  session_->OnConnectionToBeClosedDueToMigrationError(
      current_migration_cause, QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK);
  connection_->CloseConnection(
      QUIC_CONNECTION_MIGRATION_NO_NEW_NETWORK,
      absl::StrFormat("Migration for cause %s timed out",
                      MigrationCauseToString(current_migration_cause)),
      ConnectionCloseBehavior::SILENT_CLOSE);
}

void QuicConnectionMigrationManager::LogMetricsOnNetworkDisconnected() {
  most_recent_network_disconnected_timestamp_ = clock_->ApproximateNow();
}

bool QuicConnectionMigrationManager::MaybeCloseIdleSession(
    bool has_write_error, ConnectionCloseBehavior close_behavior) {
  if (session_->HasActiveRequestStreams()) {
    return false;
  }
  if (!config_.migrate_idle_session) {
    // Close the idle session.
    if (!has_write_error) {
      session_->OnConnectionToBeClosedDueToMigrationError(
          current_migration_cause_,
          QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS);
      connection_->CloseConnection(
          QUIC_CONNECTION_MIGRATION_NO_MIGRATABLE_STREAMS,
          "Migrating idle session is disabled.", close_behavior);
    } else {
      connection_->CloseConnection(QUIC_PACKET_WRITE_ERROR,
                                   "Write error for non-migratable session",
                                   close_behavior);
    }
    OnMigrationFailure(
        QuicConnectionMigrationStatus::MIGRATION_STATUS_NO_MIGRATABLE_STREAMS,
        "No active streams");
    return true;
  }
  // There are no active/drainning streams, check the last stream's finish time.
  if (session_->TimeSinceLastStreamClose() < config_.idle_migration_period) {
    // Still within the idle migration period.
    return false;
  }
  if (!has_write_error) {
    session_->OnConnectionToBeClosedDueToMigrationError(
        current_migration_cause_, QUIC_NETWORK_IDLE_TIMEOUT);
    connection_->CloseConnection(
        QUIC_NETWORK_IDLE_TIMEOUT,
        "Idle session exceeds configured idle migration period",
        ConnectionCloseBehavior::SILENT_CLOSE);
  } else {
    connection_->CloseConnection(QUIC_PACKET_WRITE_ERROR,
                                 "Write error for idle session",
                                 close_behavior);
  }
  OnMigrationFailure(
      QuicConnectionMigrationStatus::MIGRATION_STATUS_IDLE_MIGRATION_TIMEOUT,
      "Idle migration period exceeded");
  return true;
}

void QuicConnectionMigrationManager::OnHandshakeCompleted(
    const QuicConfig& negotiated_config) {
  migration_disabled_ = negotiated_config.DisableConnectionMigration();
  // TODO(danzh): attempt to migrate back to the default network after handshake
  // has been completed if the session is not created on the default network.
}

void QuicConnectionMigrationManager::ResetMigrationCauseAndLogResult(
    QuicConnectionMigrationStatus status) {
  if (current_migration_cause_ ==
      MigrationCause::CHANGE_PORT_ON_PATH_DEGRADING) {
    QUIC_CLIENT_HISTOGRAM_ENUM("Net.QuicSession.PortMigration", status,
                               MIGRATION_STATUS_MAX, "");
    current_migration_cause_ = MigrationCause::UNKNOWN_CAUSE;
    return;
  }
  if (current_migration_cause_ ==
      MigrationCause::ON_SERVER_PREFERRED_ADDRESS_AVAILABLE) {
    QUIC_CLIENT_HISTOGRAM_ENUM(
        "Net.QuicSession.OnServerPreferredAddressAvailable", status,
        MIGRATION_STATUS_MAX, "");
    current_migration_cause_ = MigrationCause::UNKNOWN_CAUSE;
    return;
  }
  QUIC_CLIENT_HISTOGRAM_ENUM("Net.QuicSession.ConnectionMigration", status,
                             MIGRATION_STATUS_MAX, "");
  // Log the connection migraiton result to different histograms based on the
  // cause of the connection migration.
  switch (current_migration_cause_) {
    case MigrationCause::UNKNOWN_CAUSE:
      QUIC_CLIENT_HISTOGRAM_ENUM("Net.QuicSession.ConnectionMigration.Unknown",
                                 status, MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::ON_NETWORK_CONNECTED:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration.OnNetworkConnected", status,
          MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::ON_NETWORK_DISCONNECTED:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration.OnNetworkDisconnected", status,
          MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::ON_WRITE_ERROR:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration.OnWriteError", status,
          MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::ON_NETWORK_MADE_DEFAULT:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration.OnNetworkMadeDefault", status,
          MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::ON_MIGRATE_BACK_TO_DEFAULT_NETWORK:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration.OnMigrateBackToDefaultNetwork",
          status, MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::CHANGE_NETWORK_ON_PATH_DEGRADING:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration.OnPathDegrading", status,
          MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::NEW_NETWORK_CONNECTED_POST_PATH_DEGRADING:
      QUIC_CLIENT_HISTOGRAM_ENUM(
          "Net.QuicSession.ConnectionMigration."
          "NewNetworkConnectedPostPathDegrading",
          status, MIGRATION_STATUS_MAX, "");
      break;
    case MigrationCause::CHANGE_PORT_ON_PATH_DEGRADING:
    case MigrationCause::ON_SERVER_PREFERRED_ADDRESS_AVAILABLE:
      // Already has been handled above.
      break;
  }
  current_migration_cause_ = MigrationCause::UNKNOWN_CAUSE;
}

void QuicConnectionMigrationManager::LogHandshakeStatusOnMigrationSignal()
    const {
  const bool handshake_confirmed = session_->OneRttKeysAvailable();
  if (current_migration_cause_ ==
      MigrationCause::CHANGE_PORT_ON_PATH_DEGRADING) {
    QUIC_CLIENT_HISTOGRAM_BOOL("Net.QuicSession.HandshakeStatusOnPortMigration",
                               handshake_confirmed, "");
    return;
  }
  if (current_migration_cause_ ==
      MigrationCause::ON_SERVER_PREFERRED_ADDRESS_AVAILABLE) {
    QUIC_CLIENT_HISTOGRAM_BOOL(
        "Net.QuicSession.HandshakeStatusOnMigratingToServerPreferredAddress",
        handshake_confirmed, "");
    return;
  }
  QUIC_CLIENT_HISTOGRAM_BOOL(
      "Net.QuicSession.HandshakeStatusOnConnectionMigration",
      handshake_confirmed, "");
  switch (current_migration_cause_) {
    case MigrationCause::UNKNOWN_CAUSE:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration.Unknown",
          handshake_confirmed, "");
      break;
    case MigrationCause::ON_NETWORK_CONNECTED:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration."
          "OnNetworkConnected",
          handshake_confirmed, "");
      break;
    case MigrationCause::ON_NETWORK_DISCONNECTED:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration."
          "OnNetworkDisconnected",
          handshake_confirmed, "");
      break;
    case MigrationCause::ON_WRITE_ERROR:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration.OnWriteError",
          handshake_confirmed, "");
      break;
    case MigrationCause::ON_NETWORK_MADE_DEFAULT:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration."
          "OnNetworkMadeDefault",
          handshake_confirmed, "");
      break;
    case MigrationCause::ON_MIGRATE_BACK_TO_DEFAULT_NETWORK:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration."
          "OnMigrateBackToDefaultNetwork",
          handshake_confirmed, "");
      break;
    case MigrationCause::CHANGE_NETWORK_ON_PATH_DEGRADING:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration."
          "OnPathDegrading",
          handshake_confirmed, "");
      break;
    case MigrationCause::NEW_NETWORK_CONNECTED_POST_PATH_DEGRADING:
      QUIC_CLIENT_HISTOGRAM_BOOL(
          "Net.QuicSession.HandshakeStatusOnConnectionMigration."
          "NewNetworkConnectedPostPathDegrading",
          handshake_confirmed, "");
      break;
    case MigrationCause::CHANGE_PORT_ON_PATH_DEGRADING:
    case MigrationCause::ON_SERVER_PREFERRED_ADDRESS_AVAILABLE:
      // Already has been handled above.
      break;
  }
}

void QuicConnectionMigrationManager::OnMigrationFailure(
    QuicConnectionMigrationStatus status, absl::string_view reason) {
  if (debug_visitor_) {
    debug_visitor_->OnConnectionMigrationFailed(
        current_migration_cause_, connection_->connection_id(), reason);
  }
  // |current_migration_cause_| will be reset afterwards.
  ResetMigrationCauseAndLogResult(status);
}

void QuicConnectionMigrationManager::OnMigrationSuccess() {
  if (debug_visitor_) {
    debug_visitor_->OnConnectionMigrationSuccess(current_migration_cause_,
                                                 connection_->connection_id());
  }
  // |current_migration_cause_| will be reset afterwards.
  ResetMigrationCauseAndLogResult(
      QuicConnectionMigrationStatus::MIGRATION_STATUS_SUCCESS);
}

}  // namespace quic
