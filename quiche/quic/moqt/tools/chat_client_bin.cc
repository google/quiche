// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include <poll.h>
#include <unistd.h>

#include <iostream>
#include <string>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/moqt/tools/chat_client.h"
#include "quiche/quic/tools/quic_name_lookup.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, disable_certificate_verification, false,
    "If true, don't verify the server certificate.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, output_file, "",
    "chat messages will stream to a file instead of stdout");

// A client for MoQT over chat, used for interop testing. See
// https://afrind.github.io/draft-frindell-moq-chat/draft-frindell-moq-chat.html
int main(int argc, char* argv[]) {
  const char* usage = "Usage: chat_client [options] <url> <username> <chat-id>";
  std::vector<std::string> args =
      quiche::QuicheParseCommandLineFlags(usage, argc, argv);
  if (args.size() != 3) {
    quiche::QuichePrintCommandLineFlagHelp(usage);
    return 1;
  }
  quic::QuicUrl url(args[0], "https");
  quic::QuicServerId server_id(url.host(), url.port());
  std::string path = url.PathParamsQuery();
  const std::string& username = args[1];
  const std::string& chat_id = args[2];
  moqt::ChatClient client(
      server_id, path, username, chat_id,
      quiche::GetQuicheCommandLineFlag(FLAGS_disable_certificate_verification),
      quiche::GetQuicheCommandLineFlag(FLAGS_output_file));

  while (!client.session_is_open()) {
    client.RunEventLoop();
  }

  if (!client.AnnounceAndSubscribe()) {
    return 1;
  }
  while (client.is_syncing()) {
    client.RunEventLoop();
  }
  if (!client.session_is_open()) {
    return 1;  // Something went wrong in connecting.
  }
  if (!client.has_output_file()) {
    while (client.session_is_open()) {
      client.RunEventLoop();
    }
    return 0;
  }
  // There is an output file.
  std::cout << "Fully connected. Messages are in the output file. Exit the "
            << "session by entering /exit\n";
  struct pollfd poll_settings = {
      0,
      POLLIN,
      POLLIN,
  };
  while (client.session_is_open()) {
    std::string message_to_send;
    while (poll(&poll_settings, 1, 0) <= 0) {
      client.RunEventLoop();
    }
    std::getline(std::cin, message_to_send);
    client.OnTerminalLineInput(message_to_send);
    client.WriteToFile(username, message_to_send);
  }
  return 0;
}
