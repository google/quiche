// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/moqt/tools/chat_client.h"

#include <poll.h>
#include <unistd.h>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/bind_front.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/proof_verifier.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_outgoing_queue.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moq_chat.h"
#include "quiche/quic/moqt/tools/moqt_client.h"
#include "quiche/quic/platform/api/quic_default_proof_providers.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/interactive_cli.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/common/platform/api/quiche_mem_slice.h"
#include "quiche/common/quiche_buffer_allocator.h"
#include "quiche/common/simple_buffer_allocator.h"

moqt::ChatClient::ChatClient(const quic::QuicServerId& server_id,
                             absl::string_view path, absl::string_view username,
                             absl::string_view chat_id, bool ignore_certificate,
                             absl::string_view output_file)
    : username_(username), chat_strings_(chat_id) {
  quic::QuicDefaultClock* clock = quic::QuicDefaultClock::Get();
  std::cout << "Connecting to host " << server_id.host() << " port "
            << server_id.port() << " path " << path << "\n";
  event_loop_ = quic::GetDefaultEventLoop()->Create(clock);
  quic::QuicSocketAddress peer_address =
      quic::tools::LookupAddress(AF_UNSPEC, server_id);
  std::unique_ptr<quic::ProofVerifier> verifier;
  output_filename_ = output_file;
  if (!output_filename_.empty()) {
    output_file_.open(output_filename_);
    output_file_ << "Chat transcript:\n";
    output_file_.flush();
  }
  if (ignore_certificate) {
    verifier = std::make_unique<quic::FakeProofVerifier>();
  } else {
    verifier = quic::CreateDefaultProofVerifier(server_id.host());
  }
  client_ = std::make_unique<moqt::MoqtClient>(
      peer_address, server_id, std::move(verifier), event_loop_.get());
  session_callbacks_.session_established_callback = [this]() {
    std::cout << "Session established\n";
    session_is_open_ = true;
    if (output_filename_.empty()) {  // Use the CLI.
      cli_ = std::make_unique<quic::InteractiveCli>(
          event_loop_.get(),
          absl::bind_front(&ChatClient::OnTerminalLineInput, this));
      cli_->PrintLine("Fully connected. Enter '/exit' to exit the chat.\n");
    }
  };
  session_callbacks_.session_terminated_callback =
      [this](absl::string_view error_message) {
        std::cerr << "Closed session, reason = " << error_message << "\n";
        session_is_open_ = false;
      };
  session_callbacks_.session_deleted_callback = [this]() {
    session_ = nullptr;
  };
  client_->Connect(std::string(path), std::move(session_callbacks_));
}

void moqt::ChatClient::OnTerminalLineInput(absl::string_view input_message) {
  if (input_message.empty()) {
    return;
  }
  if (input_message == "/exit") {
    session_is_open_ = false;
    return;
  }
  quiche::QuicheMemSlice message_slice(quiche::QuicheBuffer::Copy(
      quiche::SimpleBufferAllocator::Get(), input_message));
  queue_->AddObject(std::move(message_slice), /*key=*/true);
}

void moqt::ChatClient::RemoteTrackVisitor::OnReply(
    const moqt::FullTrackName& full_track_name,
    std::optional<absl::string_view> reason_phrase) {
  client_->subscribes_to_make_--;
  if (full_track_name == client_->chat_strings_.GetCatalogName()) {
    std::cout << "Subscription to catalog ";
  } else {
    std::cout << "Subscription to user " << full_track_name.track_namespace
              << " ";
  }
  if (reason_phrase.has_value()) {
    std::cout << "REJECTED, reason = " << *reason_phrase << "\n";
  } else {
    std::cout << "ACCEPTED\n";
  }
}

void moqt::ChatClient::RemoteTrackVisitor::OnObjectFragment(
    const moqt::FullTrackName& full_track_name, uint64_t group_sequence,
    uint64_t object_sequence, moqt::MoqtPriority /*publisher_priority*/,
    moqt::MoqtObjectStatus /*status*/,
    moqt::MoqtForwardingPreference /*forwarding_preference*/,
    absl::string_view object, bool end_of_message) {
  if (!end_of_message) {
    std::cerr << "Error: received partial message despite requesting "
                 "buffering\n";
  }
  if (full_track_name == client_->chat_strings_.GetCatalogName()) {
    if (group_sequence < client_->catalog_group_) {
      std::cout << "Ignoring old catalog";
      return;
    }
    client_->ProcessCatalog(object, this, group_sequence, object_sequence);
    return;
  }
  std::string username = full_track_name.track_namespace;
  username = username.substr(username.find_last_of('/') + 1);
  if (!client_->other_users_.contains(username)) {
    std::cout << "Username " << username << "doesn't exist\n";
    return;
  }
  if (client_->has_output_file()) {
    client_->WriteToFile(username, object);
    return;
  }
  if (cli_ != nullptr) {
    std::string full_output = absl::StrCat(username, ": ", object);
    cli_->PrintLine(full_output);
  }
}

bool moqt::ChatClient::AnnounceAndSubscribe() {
  session_ = client_->session();
  if (session_ == nullptr) {
    std::cout << "Failed to connect.\n";
    return false;
  }
  FullTrackName my_track_name =
      chat_strings_.GetFullTrackNameFromUsername(username_);
  queue_ = std::make_shared<moqt::MoqtOutgoingQueue>(
      my_track_name, moqt::MoqtForwardingPreference::kObject);
  publisher_.Add(queue_);
  session_->set_publisher(&publisher_);
  moqt::MoqtOutgoingAnnounceCallback announce_callback =
      [this](absl::string_view track_namespace,
             std::optional<moqt::MoqtAnnounceErrorReason> reason) {
        if (reason.has_value()) {
          std::cout << "ANNOUNCE rejected, " << reason->reason_phrase << "\n";
          session_->Error(moqt::MoqtError::kInternalError,
                          "Local ANNOUNCE rejected");
          return;
        }
        std::cout << "ANNOUNCE for " << track_namespace << " accepted\n";
        return;
      };
  std::cout << "Announcing " << my_track_name.track_namespace << "\n";
  session_->Announce(my_track_name.track_namespace,
                     std::move(announce_callback));
  remote_track_visitor_ = std::make_unique<RemoteTrackVisitor>(this);
  FullTrackName catalog_name = chat_strings_.GetCatalogName();
  if (!session_->SubscribeCurrentGroup(
          catalog_name.track_namespace, catalog_name.track_name,
          remote_track_visitor_.get(), username_)) {
    std::cout << "Failed to get catalog\n";
    return false;
  }
  return true;
}

void moqt::ChatClient::ProcessCatalog(absl::string_view object,
                                      moqt::RemoteTrack::Visitor* visitor,
                                      uint64_t group_sequence,
                                      uint64_t object_sequence) {
  std::string message(object);
  std::istringstream f(message);
  // std::string line;
  bool got_version = true;
  if (object_sequence == 0) {
    std::cout << "Received new Catalog. Users:\n";
    got_version = false;
  }
  std::vector<absl::string_view> lines =
      absl::StrSplit(object, '\n', absl::SkipEmpty());
  for (absl::string_view line : lines) {
    if (!got_version) {
      if (line != "version=1") {
        session_->Error(moqt::MoqtError::kProtocolViolation,
                        "Catalog does not begin with version");
        return;
      }
      got_version = true;
      continue;
    }
    std::string user;
    bool add = true;
    if (object_sequence > 0) {
      switch (line[0]) {
        case '-':
          add = false;
          break;
        case '+':
          break;
        default:
          std::cerr << "Catalog update with neither + nor -\n";
          return;
      }
      user = line.substr(1, line.size() - 1);
    } else {
      user = line;
    }
    if (username_ == user) {
      std::cout << user << "\n";
      continue;
    }
    if (!add) {
      // TODO: Unsubscribe from the user that's leaving
      std::cout << user << "left the chat\n";
      other_users_.erase(user);
      continue;
    }
    if (object_sequence == 0) {
      std::cout << user << "\n";
    } else {
      std::cout << user << " joined the chat\n";
    }
    auto it = other_users_.find(user);
    if (it == other_users_.end()) {
      moqt::FullTrackName to_subscribe =
          chat_strings_.GetFullTrackNameFromUsername(user);
      auto new_user = other_users_.emplace(
          std::make_pair(user, ChatUser(to_subscribe, group_sequence)));
      ChatUser& user_record = new_user.first->second;
      session_->SubscribeCurrentGroup(
          user_record.full_track_name.track_namespace,
          user_record.full_track_name.track_name, visitor);
      subscribes_to_make_++;
    } else {
      if (it->second.from_group == group_sequence) {
        session_->Error(moqt::MoqtError::kProtocolViolation,
                        "User listed twice in Catalog");
        return;
      }
      it->second.from_group = group_sequence;
    }
  }
  if (object_sequence == 0) {  // Eliminate users that are no longer present
    absl::erase_if(other_users_, [&](const auto& kv) {
      return kv.second.from_group != group_sequence;
    });
  }
  catalog_group_ = group_sequence;
}
