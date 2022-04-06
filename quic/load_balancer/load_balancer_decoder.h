// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_QUIC_LOAD_BALANCER_LOAD_BALANCER_DECODER_H_
#define QUICHE_QUIC_LOAD_BALANCER_LOAD_BALANCER_DECODER_H_

#include "quic/load_balancer/load_balancer_config.h"
#include "quic/load_balancer/load_balancer_server_id.h"

namespace quic {

// Manages QUIC-LB configurations to extract a server ID from a properly
// encoded connection ID, usually on behalf of a load balancer.
class QUIC_EXPORT_PRIVATE LoadBalancerDecoder {
 public:
  // Returns false if the config_id codepoint is already occupied.
  bool AddConfig(const LoadBalancerConfig& config);

  // Remove support for a config
  void DeleteConfig(const uint8_t config_id);

  // For these "Get" functions, the calling code might not know the length of
  // the connection ID. That's OK; if not, just send at least
  // kQuicMaxConnectionIdWithLengthPrefixLength bytes in a QuicConnectionId.

  // Extract a server ID from a connection ID. If there is no config for the
  // codepoint, the connection ID is too short, or there's a decrypt error,
  // returns empty.
  absl::optional<LoadBalancerServerId> GetServerId(
      const QuicConnectionId& connection_id) const;

  // Returns the config ID stored in the first two bits of |connection_id|, or
  // empty if |connection_id| is empty.
  static absl::optional<uint8_t> GetConfigId(
      const QuicConnectionId& connection_id);

 private:
  // Decoders can support up to 3 configs at once.
  absl::optional<LoadBalancerConfig> config_[3];
};

}  // namespace quic

#endif  // QUICHE_QUIC_LOAD_BALANCER_LOAD_BALANCER_DECODER_H_
