// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/tools/quic_name_lookup.h"

#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "quiche/quic/platform/api/quic_logging.h"

namespace quic::tools {

QuicSocketAddress LookupAddress(int address_family_for_lookup, std::string host,
                                std::string port) {
  addrinfo hint;
  memset(&hint, 0, sizeof(hint));
  hint.ai_family = address_family_for_lookup;
  hint.ai_protocol = IPPROTO_UDP;

  addrinfo* info_list = nullptr;
  int result = getaddrinfo(host.c_str(), port.c_str(), &hint, &info_list);
  if (result != 0) {
    QUIC_LOG(ERROR) << "Failed to look up " << host << ": "
                    << gai_strerror(result);
    return QuicSocketAddress();
  }

  QUICHE_CHECK(info_list != nullptr);
  std::unique_ptr<addrinfo, void (*)(addrinfo*)> info_list_owned(info_list,
                                                                 freeaddrinfo);
  return QuicSocketAddress(info_list->ai_addr, info_list->ai_addrlen);
}

}  // namespace quic::tools
