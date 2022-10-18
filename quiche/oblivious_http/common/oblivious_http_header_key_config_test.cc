#include "quiche/oblivious_http/common/oblivious_http_header_key_config.h"

#include <cstdint>

#include "absl/strings/escaping.h"
#include "openssl/hpke.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/quiche_data_writer.h"

namespace quiche {
namespace {
using ::testing::AllOf;
using ::testing::Property;
using ::testing::StrEq;

/**
 * Build Request header.
 */
std::string BuildHeader(uint8_t key_id, uint16_t kem_id, uint16_t kdf_id,
                        uint16_t aead_id) {
  int buf_len =
      sizeof(key_id) + sizeof(kem_id) + sizeof(kdf_id) + sizeof(aead_id);
  std::string hdr(buf_len, '\0');
  QuicheDataWriter writer(hdr.size(), hdr.data());
  EXPECT_TRUE(writer.WriteUInt8(key_id));
  EXPECT_TRUE(writer.WriteUInt16(kem_id));   // kemID
  EXPECT_TRUE(writer.WriteUInt16(kdf_id));   // kdfID
  EXPECT_TRUE(writer.WriteUInt16(aead_id));  // aeadID
  return hdr;
}

TEST(ObliviousHttpHeaderKeyConfig, TestSerializeRecipientContextInfo) {
  uint8_t key_id = 3;
  uint16_t kem_id = EVP_HPKE_DHKEM_X25519_HKDF_SHA256;
  uint16_t kdf_id = EVP_HPKE_HKDF_SHA256;
  uint16_t aead_id = EVP_HPKE_AES_256_GCM;
  absl::string_view ohttp_req_label = "message/bhttp request";
  std::string expected(ohttp_req_label);
  uint8_t zero_byte = 0x00;
  int buf_len = ohttp_req_label.size() + sizeof(zero_byte) + sizeof(key_id) +
                sizeof(kem_id) + sizeof(kdf_id) + sizeof(aead_id);
  expected.reserve(buf_len);
  expected.push_back(zero_byte);
  std::string ohttp_cfg(BuildHeader(key_id, kem_id, kdf_id, aead_id));
  expected.insert(expected.end(), ohttp_cfg.begin(), ohttp_cfg.end());
  auto instance =
      ObliviousHttpHeaderKeyConfig::Create(key_id, kem_id, kdf_id, aead_id);
  ASSERT_TRUE(instance.ok());
  EXPECT_EQ(instance.value().SerializeRecipientContextInfo(), expected);
}

TEST(ObliviousHttpHeaderKeyConfig, TestValidKeyConfig) {
  auto valid_key_config = ObliviousHttpHeaderKeyConfig::Create(
      2, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(valid_key_config.ok());
}

TEST(ObliviousHttpHeaderKeyConfig, TestInvalidKeyConfig) {
  auto invalid_kem = ObliviousHttpHeaderKeyConfig::Create(
      3, 0, EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM);
  EXPECT_EQ(invalid_kem.status().code(), absl::StatusCode::kInvalidArgument);
  auto invalid_kdf = ObliviousHttpHeaderKeyConfig::Create(
      3, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, 0, EVP_HPKE_AES_256_GCM);
  EXPECT_EQ(invalid_kdf.status().code(), absl::StatusCode::kInvalidArgument);
  auto invalid_aead = ObliviousHttpHeaderKeyConfig::Create(
      3, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256, 0);
  EXPECT_EQ(invalid_kdf.status().code(), absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpHeaderKeyConfig, TestParsingValidHeader) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(instance.ok());
  std::string good_hdr(BuildHeader(5, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                                   EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_256_GCM));
  ASSERT_TRUE(instance.value().ParseOhttpPayloadHeader(good_hdr).ok());
}

TEST(ObliviousHttpHeaderKeyConfig, TestParsingInvalidHeader) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      8, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(instance.ok());
  std::string keyid_mismatch_hdr(
      BuildHeader(0, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
                  EVP_HPKE_AES_256_GCM));
  EXPECT_EQ(instance.value().ParseOhttpPayloadHeader(keyid_mismatch_hdr).code(),
            absl::StatusCode::kInvalidArgument);
  std::string invalid_hpke_hdr(BuildHeader(8, 0, 0, 0));
  EXPECT_EQ(instance.value().ParseOhttpPayloadHeader(invalid_hpke_hdr).code(),
            absl::StatusCode::kInvalidArgument);
}

TEST(ObliviousHttpHeaderKeyConfig, TestParsingKeyIdFromObliviousHttpRequest) {
  std::string key_id(sizeof(uint8_t), '\0');
  QuicheDataWriter writer(key_id.size(), key_id.data());
  EXPECT_TRUE(writer.WriteUInt8(99));
  auto parsed_key_id =
      ObliviousHttpHeaderKeyConfig::ParseKeyIdFromObliviousHttpRequestPayload(
          key_id);
  ASSERT_TRUE(parsed_key_id.ok());
  EXPECT_EQ(parsed_key_id.value(), 99);
}

TEST(ObliviousHttpHeaderKeyConfig, TestCopyable) {
  auto obj1 = ObliviousHttpHeaderKeyConfig::Create(
      4, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_256_GCM);
  ASSERT_TRUE(obj1.ok());
  auto copy_obj1_to_obj2 = obj1.value();
  EXPECT_EQ(copy_obj1_to_obj2.kHeaderLength, obj1->kHeaderLength);
  EXPECT_EQ(copy_obj1_to_obj2.SerializeRecipientContextInfo(),
            obj1->SerializeRecipientContextInfo());
}

TEST(ObliviousHttpHeaderKeyConfig, TestSerializeOhttpPayloadHeader) {
  auto instance = ObliviousHttpHeaderKeyConfig::Create(
      7, EVP_HPKE_DHKEM_X25519_HKDF_SHA256, EVP_HPKE_HKDF_SHA256,
      EVP_HPKE_AES_128_GCM);
  ASSERT_TRUE(instance.ok());
  EXPECT_EQ(instance->SerializeOhttpPayloadHeader(),
            BuildHeader(7, EVP_HPKE_DHKEM_X25519_HKDF_SHA256,
                        EVP_HPKE_HKDF_SHA256, EVP_HPKE_AES_128_GCM));
}

MATCHER_P(HasKeyId, id, "") {
  *result_listener << "has key_id=" << arg.GetKeyId();
  return arg.GetKeyId() == id;
}
MATCHER_P(HasKemId, id, "") {
  *result_listener << "has kem_id=" << arg.GetHpkeKemId();
  return arg.GetHpkeKemId() == id;
}
MATCHER_P(HasKdfId, id, "") {
  *result_listener << "has kdf_id=" << arg.GetHpkeKdfId();
  return arg.GetHpkeKdfId() == id;
}
MATCHER_P(HasAeadId, id, "") {
  *result_listener << "has aead_id=" << arg.GetHpkeAeadId();
  return arg.GetHpkeAeadId() == id;
}

TEST(ObliviousHttpKeyConfigs, SingleKeyConfig) {
  std::string key = absl::HexStringToBytes(
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010002");
  auto configs = ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).value();
  EXPECT_THAT(configs, Property(&ObliviousHttpKeyConfigs::NumKeys, 1));
  EXPECT_THAT(
      configs.PreferredConfig(),
      AllOf(HasKeyId(0x4b), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
            HasKdfId(EVP_HPKE_HKDF_SHA256), HasAeadId(EVP_HPKE_AES_256_GCM)));
  EXPECT_THAT(
      configs.GetPublicKeyForId(configs.PreferredConfig().GetKeyId()).value(),
      StrEq(absl::HexStringToBytes(
          "f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b")));
}

TEST(ObliviousHttpKeyConfigs, TwoSimilarKeyConfigs) {
  std::string key = absl::HexStringToBytes(
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010002"  // Intentional concatenation
      "4f0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010001");
  EXPECT_THAT(ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).value(),
              Property(&ObliviousHttpKeyConfigs::NumKeys, 2));
  EXPECT_THAT(
      ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key)->PreferredConfig(),
      AllOf(HasKeyId(0x4f), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
            HasKdfId(EVP_HPKE_HKDF_SHA256), HasAeadId(EVP_HPKE_AES_128_GCM)));
}

TEST(ObliviousHttpKeyConfigs, RFCExample) {
  std::string key = absl::HexStringToBytes(
      "01002031e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e79815500"
      "080001000100010003");
  auto configs = ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).value();
  EXPECT_THAT(configs, Property(&ObliviousHttpKeyConfigs::NumKeys, 1));
  EXPECT_THAT(
      configs.PreferredConfig(),
      AllOf(HasKeyId(0x01), HasKemId(EVP_HPKE_DHKEM_X25519_HKDF_SHA256),
            HasKdfId(EVP_HPKE_HKDF_SHA256), HasAeadId(EVP_HPKE_AES_128_GCM)));
  EXPECT_THAT(
      configs.GetPublicKeyForId(configs.PreferredConfig().GetKeyId()).value(),
      StrEq(absl::HexStringToBytes(
          "31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155")));
}

TEST(ObliviousHttpKeyConfigs, DuplicateKeyId) {
  std::string key = absl::HexStringToBytes(
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fa27a049bc746a6e97a1e0244b00"
      "0400010002"  // Intentional concatenation
      "4b0020f83e0a17cbdb18d2684dd2a9b087a43e5f3fa3fb27a049bc746a6e97a1e0244b00"
      "0400010001");
  EXPECT_FALSE(ObliviousHttpKeyConfigs::ParseConcatenatedKeys(key).ok());
}

}  // namespace
}  // namespace quiche
