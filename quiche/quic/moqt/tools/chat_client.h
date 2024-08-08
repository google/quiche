// Copyright (c) 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_MOQT_TOOLS_CHAT_CLIENT_H
#define QUICHE_QUIC_MOQT_TOOLS_CHAT_CLIENT_H

#include <cstdint>
#include <fstream>
#include <memory>
#include <optional>
#include <string>

#include "absl/container/flat_hash_map.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/moqt/moqt_known_track_publisher.h"
#include "quiche/quic/moqt/moqt_messages.h"
#include "quiche/quic/moqt/moqt_outgoing_queue.h"
#include "quiche/quic/moqt/moqt_priority.h"
#include "quiche/quic/moqt/moqt_session.h"
#include "quiche/quic/moqt/moqt_track.h"
#include "quiche/quic/moqt/tools/moq_chat.h"
#include "quiche/quic/moqt/tools/moqt_client.h"
#include "quiche/quic/tools/interactive_cli.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace moqt {

class ChatClient {
 public:
  ChatClient(const quic::QuicServerId& server_id, absl::string_view path,
             absl::string_view username, absl::string_view chat_id,
             bool ignore_certificate, absl::string_view output_file);

  void OnTerminalLineInput(absl::string_view input_message);

  bool session_is_open() const { return session_is_open_; }

  // Returns true if the client is still doing initial sync: retrieving the
  // catalog, subscribing to all the users in it, and waiting for the server
  // to subscribe to the local track.
  bool is_syncing() const {
    return !catalog_group_.has_value() || subscribes_to_make_ > 0 ||
           (queue_ == nullptr || !queue_->HasSubscribers());
  }

  void RunEventLoop() {
    event_loop_->RunEventLoopOnce(quic::QuicTime::Delta::FromMilliseconds(500));
  }

  bool has_output_file() { return !output_filename_.empty(); }

  void WriteToFile(absl::string_view user, absl::string_view message) {
    output_file_ << user << ": " << message << "\n\n";
    output_file_.flush();
  }

  class QUICHE_EXPORT RemoteTrackVisitor : public moqt::RemoteTrack::Visitor {
   public:
    RemoteTrackVisitor(ChatClient* client) : client_(client) {
      cli_ = client->cli_.get();
    }

    void OnReply(const moqt::FullTrackName& full_track_name,
                 std::optional<absl::string_view> reason_phrase) override;

    void OnObjectFragment(const moqt::FullTrackName& full_track_name,
                          uint64_t group_sequence, uint64_t object_sequence,
                          moqt::MoqtPriority publisher_priority,
                          moqt::MoqtObjectStatus status,
                          moqt::MoqtForwardingPreference forwarding_preference,
                          absl::string_view object,
                          bool end_of_message) override;

    void set_cli(quic::InteractiveCli* cli) { cli_ = cli; }

   private:
    ChatClient* client_;
    quic::InteractiveCli* cli_;
  };

  // Returns false on error.
  bool AnnounceAndSubscribe();

 private:
  // Objects from the same catalog group arrive on the same stream, and in
  // object sequence order.
  void ProcessCatalog(absl::string_view object,
                      moqt::RemoteTrack::Visitor* visitor,
                      uint64_t group_sequence, uint64_t object_sequence);

  struct ChatUser {
    moqt::FullTrackName full_track_name;
    uint64_t from_group;
    ChatUser(const moqt::FullTrackName& ftn, uint64_t group)
        : full_track_name(ftn), from_group(group) {}
  };

  // Basic session information
  const std::string username_;
  moqt::MoqChatStrings chat_strings_;

  // General state variables
  std::unique_ptr<quic::QuicEventLoop> event_loop_;
  bool session_is_open_ = false;
  moqt::MoqtSession* session_ = nullptr;
  moqt::MoqtKnownTrackPublisher publisher_;
  std::unique_ptr<moqt::MoqtClient> client_;
  moqt::MoqtSessionCallbacks session_callbacks_;

  // Related to syncing.
  std::optional<uint64_t> catalog_group_;
  absl::flat_hash_map<std::string, ChatUser> other_users_;
  int subscribes_to_make_ = 1;

  // Related to subscriptions/announces
  // TODO: One for each subscribe
  std::unique_ptr<RemoteTrackVisitor> remote_track_visitor_;

  // Handling outgoing messages
  std::shared_ptr<moqt::MoqtOutgoingQueue> queue_;

  // Used when chat output goes to file.
  std::ofstream output_file_;
  std::string output_filename_;

  // Used when there is no output file, and both input and output are in the
  // terminal.
  std::unique_ptr<quic::InteractiveCli> cli_;
};

}  // namespace moqt

#endif  // QUICHE_QUIC_MOQT_TOOLS_CHAT_CLIENT_H
