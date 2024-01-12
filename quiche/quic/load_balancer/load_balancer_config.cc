// Copyright (c) 2022 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/load_balancer/load_balancer_config.h"

#include <cstdint>
#include <cstring>
#include <optional>

#include "absl/numeric/int128.h"
#include "absl/strings/string_view.h"
#include "absl/types/span.h"
#include "openssl/aes.h"
#include "quiche/quic/core/quic_connection_id.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/load_balancer/load_balancer_server_id.h"
#include "quiche/quic/platform/api/quic_bug_tracker.h"

namespace quic {

namespace {

// Validates all non-key parts of the input.
bool CommonValidation(const uint8_t config_id, const uint8_t server_id_len,
                      const uint8_t nonce_len) {
  if (config_id >= kNumLoadBalancerConfigs || server_id_len == 0 ||
      nonce_len < kLoadBalancerMinNonceLen ||
      nonce_len > kLoadBalancerMaxNonceLen ||
      server_id_len >
          (kQuicMaxConnectionIdWithLengthPrefixLength - nonce_len - 1)) {
    QUIC_BUG(quic_bug_433862549_01)
        << "Invalid LoadBalancerConfig "
        << "Config ID " << static_cast<int>(config_id) << " Server ID Length "
        << static_cast<int>(server_id_len) << " Nonce Length "
        << static_cast<int>(nonce_len);
    return false;
  }
  return true;
}

// Initialize the key in the constructor
std::optional<AES_KEY> BuildKey(absl::string_view key, bool encrypt) {
  if (key.empty()) {
    return std::optional<AES_KEY>();
  }
  AES_KEY raw_key;
  if (encrypt) {
    if (AES_set_encrypt_key(reinterpret_cast<const uint8_t *>(key.data()),
                            key.size() * 8, &raw_key) < 0) {
      return std::optional<AES_KEY>();
    }
  } else if (AES_set_decrypt_key(reinterpret_cast<const uint8_t *>(key.data()),
                                 key.size() * 8, &raw_key) < 0) {
    return std::optional<AES_KEY>();
  }
  return raw_key;
}

}  // namespace

std::optional<LoadBalancerConfig> LoadBalancerConfig::Create(
    const uint8_t config_id, const uint8_t server_id_len,
    const uint8_t nonce_len, const absl::string_view key) {
  //  Check for valid parameters.
  if (key.size() != kLoadBalancerKeyLen) {
    QUIC_BUG(quic_bug_433862549_02)
        << "Invalid LoadBalancerConfig Key Length: " << key.size();
    return std::optional<LoadBalancerConfig>();
  }
  if (!CommonValidation(config_id, server_id_len, nonce_len)) {
    return std::optional<LoadBalancerConfig>();
  }
  auto new_config =
      LoadBalancerConfig(config_id, server_id_len, nonce_len, key);
  if (!new_config.IsEncrypted()) {
    // Something went wrong in assigning the key!
    QUIC_BUG(quic_bug_433862549_03) << "Something went wrong in initializing "
                                       "the load balancing key.";
    return std::optional<LoadBalancerConfig>();
  }
  return new_config;
}

// Creates an unencrypted config.
std::optional<LoadBalancerConfig> LoadBalancerConfig::CreateUnencrypted(
    const uint8_t config_id, const uint8_t server_id_len,
    const uint8_t nonce_len) {
  return CommonValidation(config_id, server_id_len, nonce_len)
             ? LoadBalancerConfig(config_id, server_id_len, nonce_len, "")
             : std::optional<LoadBalancerConfig>();
}

LoadBalancerServerId LoadBalancerConfig::Decrypt(
    absl::Span<const uint8_t> ciphertext) const {
  if (ciphertext.length() < total_len()) {
    return LoadBalancerServerId();
  }
  if (!key_.has_value()) {
    return LoadBalancerServerId(
        absl::Span<const uint8_t>(ciphertext.data() + 1, server_id_len_));
  }
  if (plaintext_len() == kLoadBalancerBlockSize) {
    if (!block_decrypt_key_.has_value()) {
      QUIC_BUG(quic_bug_596735037_01) << "Block decrypt key is not set.";
      return LoadBalancerServerId();
    }
    uint8_t plaintext[kLoadBalancerBlockSize];
    AES_decrypt(ciphertext.subspan(1, kLoadBalancerBlockSize).data(), plaintext,
                &*block_decrypt_key_);
    return LoadBalancerServerId(
        absl::Span<const uint8_t>(plaintext, server_id_len_));
  }
  // Do 3 or 4 passes. Only 3 are necessary if the server_id is short enough
  // to fit in the first half of the connection ID (the decoder doesn't need
  // to extract the nonce).
  uint8_t left[kLoadBalancerBlockSize];
  uint8_t right[kLoadBalancerBlockSize];
  uint8_t half_len;  // half the length of the plaintext, rounded up
  bool is_length_odd =
      InitializeFourPass(ciphertext.data(), left, right, &half_len);
  uint8_t end_index = (server_id_len_ > nonce_len_) ? 1 : 2;
  for (uint8_t index = kNumLoadBalancerCryptoPasses; index >= end_index;
       --index) {
    // Encrypt left/right and xor the result with right/left, respectively.
    EncryptionPass(index, half_len, is_length_odd, left, right);
  }
  // Consolidate left and right into a server ID with minimum copying.
  if (server_id_len_ < half_len ||
      (server_id_len_ == half_len && !is_length_odd)) {
    // There is no half-byte to handle
    return LoadBalancerServerId(absl::Span<uint8_t>(&left[2], server_id_len_));
  }
  if (is_length_odd) {
    right[2] |= left[half_len-- + 1];  // Combine the halves of the odd byte.
  }
  return LoadBalancerServerId(
      absl::Span<uint8_t>(&left[2], half_len),
      absl::Span<uint8_t>(&right[2], server_id_len_ - half_len));
}

QuicConnectionId LoadBalancerConfig::Encrypt(
    absl::Span<uint8_t> connection_id) const {
  if (connection_id.length() < total_len()) {
    return QuicConnectionId();
  }
  if (!key_.has_value()) {  // Plaintext connection ID
    // Fill the nonce field with a hash of the Connection ID to avoid the nonce
    // visibly increasing by one. This would allow observers to correlate
    // connection IDs as being sequential and likely from the same connection,
    // not just the same server.
    absl::uint128 nonce_hash = QuicUtils::FNV1a_128_Hash(absl::string_view(
        reinterpret_cast<char*>(connection_id.data()), connection_id.length()));
    const uint64_t lo = absl::Uint128Low64(nonce_hash);
    if (nonce_len_ <= sizeof(uint64_t)) {
      memcpy(connection_id.data() + 1 + server_id_len_, &lo, nonce_len_);
      return QuicConnectionId(connection_id);
    }
    memcpy(connection_id.data() + 1 + server_id_len_, &lo, sizeof(uint64_t));
    const uint64_t hi = absl::Uint128High64(nonce_hash);
    memcpy(connection_id.data() + 1 + server_id_len_ + sizeof(uint64_t), &hi,
           nonce_len_ - sizeof(uint64_t));
    return QuicConnectionId(connection_id);
  }
  if (plaintext_len() == kLoadBalancerBlockSize) {
    AES_encrypt(connection_id.subspan(1, plaintext_len()).data(),
                connection_id.data() + 1, &*key_);
    return QuicConnectionId(connection_id);
  }
  // 4 Pass Encryption
  uint8_t left[kLoadBalancerBlockSize];
  uint8_t right[kLoadBalancerBlockSize];
  uint8_t half_len;  // half the length of the plaintext, rounded up
  bool is_length_odd =
      InitializeFourPass(connection_id.data(), left, right, &half_len);
  for (uint8_t index = 1; index <= kNumLoadBalancerCryptoPasses; ++index) {
    EncryptionPass(index, half_len, is_length_odd, left, right);
  }
  // Consolidate left and right into a server ID with minimum copying.
  if (is_length_odd) {
    // Combine the halves of the odd byte.
    left[half_len + 1] |= right[2];
  }
  memcpy(connection_id.data() + 1, &left[2], half_len);
  if (is_length_odd) {
    memcpy(connection_id.data() + 1 + half_len, &right[3], half_len - 1);
  } else {
    memcpy(connection_id.data() + 1 + half_len, &right[2], half_len);
  }
  return QuicConnectionId(connection_id);
}

LoadBalancerConfig::LoadBalancerConfig(const uint8_t config_id,
                                       const uint8_t server_id_len,
                                       const uint8_t nonce_len,
                                       const absl::string_view key)
    : config_id_(config_id),
      server_id_len_(server_id_len),
      nonce_len_(nonce_len),
      key_(BuildKey(key, /* encrypt = */ true)),
      block_decrypt_key_((server_id_len + nonce_len == kLoadBalancerBlockSize)
                             ? BuildKey(key, /* encrypt = */ false)
                             : std::optional<AES_KEY>()) {}

bool LoadBalancerConfig::InitializeFourPass(const uint8_t* input, uint8_t* left,
                                            uint8_t* right,
                                            uint8_t* half_len) const {
  *half_len = plaintext_len() / 2;
  bool is_length_odd;
  if (plaintext_len() % 2 == 1) {
    ++(*half_len);
    is_length_odd = true;
  } else {
    is_length_odd = false;
  }
  memset(left, 0, kLoadBalancerBlockSize);
  memset(right, 0, kLoadBalancerBlockSize);
  // The first byte is the plaintext/ciphertext length, the second byte will be
  // the index of the pass. Half the plaintext or ciphertext follows.
  left[0] = plaintext_len();
  right[0] = plaintext_len();
  // Leave left_[1], right_[1] as zero. It will be set for each pass.
  memcpy(&left[2], input + 1, *half_len);
  // If is_length_odd, then both left and right will have part of the middle
  // byte. Then that middle byte will be split in half via the bitmask in the
  // next step.
  memcpy(&right[2], input + (plaintext_len() / 2) + 1, *half_len);
  if (is_length_odd) {
    left[*half_len + 1] &= 0xf0;
    right[2] &= 0x0f;
  }
  return is_length_odd;
}

void LoadBalancerConfig::EncryptionPass(uint8_t index, uint8_t half_len,
                                        bool is_length_odd, uint8_t* left,
                                        uint8_t* right) const {
  uint8_t ciphertext[kLoadBalancerBlockSize];
  if (index % 2 == 0) {  // Go right to left.
    right[1] = index;
    AES_encrypt(right, ciphertext, &*key_);
    for (int i = 0; i < half_len; ++i) {
      // Skip over the first two bytes, which have the plaintext_len and the
      // index. The CID bits are in [2, half_len - 1].
      left[2 + i] ^= ciphertext[i];
    }
    if (is_length_odd) {
      left[half_len + 1] &= 0xf0;
    }
    return;
  }
  // Go left to right.
  left[1] = index;
  AES_encrypt(left, ciphertext, &*key_);
  for (int i = 0; i < half_len; ++i) {
    right[2 + i] ^= ciphertext[i];
  }
  if (is_length_odd) {
    right[2] &= 0x0f;
  }
}

}  // namespace quic
