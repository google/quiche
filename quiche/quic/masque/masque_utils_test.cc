// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/quic/masque/masque_utils.h"

#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/strings/string_view.h"
#include "quiche/quic/platform/api/quic_expect_bug.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_test.h"

namespace quic {
namespace test {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::IsEmpty;
using ::testing::Not;
using ::testing::Optional;

TEST(MasqueUtilsTest, DnsAssignCapsuleRoundTrip) {
  DnsAssignCapsule original;

  DnsConfiguration config1;
  DnsNameserver ns1;
  ns1.service_priority = 10;
  QuicIpAddress ipv4_1;
  ASSERT_TRUE(ipv4_1.FromString("192.0.2.33"));
  ns1.ipv4_addresses.push_back(ipv4_1);
  QuicIpAddress ipv6_1;
  ASSERT_TRUE(ipv6_1.FromString("2001:db8::1"));
  ns1.ipv6_addresses.push_back(ipv6_1);
  ns1.authentication_domain_name.domain_name = "dns.corp.example";
  std::optional<std::string> encoded_params =
      EncodeSvcParams("alpn=h2,h3\ndohpath=/dns-query{?dns}");
  ASSERT_THAT(encoded_params, Optional(_));
  ns1.service_parameters = *std::move(encoded_params);
  config1.nameservers.push_back(ns1);

  DnsDomain int_dom1;
  int_dom1.domain_name = "internal.corp.example";
  config1.internal_domains.push_back(int_dom1);
  DnsDomain search_dom1;
  search_dom1.domain_name = "corp.example";
  config1.search_domains.push_back(search_dom1);

  original.dns_configurations.push_back(config1);

  DnsConfiguration config2;
  config2.internal_domains.push_back(DnsDomain{""});  // Root domain
  original.dns_configurations.push_back(config2);

  std::string serialized = SerializeDnsAssignCapsulePayload(original);
  ASSERT_FALSE(serialized.empty());

  DnsAssignCapsule parsed;
  ASSERT_TRUE(ParseDnsAssignCapsulePayload(serialized, &parsed));
  EXPECT_EQ(parsed, original);
  EXPECT_EQ(
      parsed.ToString(),
      "DNS_ASSIGN[{nameservers:[(priority:10,ipv4:192.0.2.33,ipv6:2001:db8::1,"
      "auth_domain:dns.corp.example,service_params:alpn=h2,h3 dohpath=/dns-"
      "query{?dns})],internal_domains:[internal.corp.example],search_domains:["
      "corp.example]}{nameservers:[],internal_domains:[/root],search_domains:["
      "]}]");
}

TEST(MasqueUtilsTest, DnsAssignCapsuleZeroPriorityIsMalformed) {
  DnsAssignCapsule original;
  DnsConfiguration config;
  DnsNameserver ns;
  ns.service_priority = 0;  // Priority 0 is forbidden by spec.
  QuicIpAddress ipv4;
  ASSERT_TRUE(ipv4.FromString("192.0.2.1"));
  ns.ipv4_addresses.push_back(ipv4);
  config.nameservers.push_back(ns);
  original.dns_configurations.push_back(config);

  std::string serialized = SerializeDnsAssignCapsulePayload(original);
  ASSERT_FALSE(serialized.empty());

  DnsAssignCapsule parsed;
  EXPECT_FALSE(ParseDnsAssignCapsulePayload(serialized, &parsed));
}

TEST(MasqueUtilsTest, DnsAssignCapsuleTrailingJunkIsMalformed) {
  DnsAssignCapsule original;
  DnsConfiguration config;
  original.dns_configurations.push_back(config);

  std::string serialized = SerializeDnsAssignCapsulePayload(original);
  serialized += "junk";

  DnsAssignCapsule parsed;
  EXPECT_FALSE(ParseDnsAssignCapsulePayload(serialized, &parsed));
}

TEST(MasqueUtilsTest, Pref64CapsuleRoundTrip) {
  Pref64Capsule original;

  Pref64Prefix prefix1;
  prefix1.prefix_length = 96;
  ASSERT_TRUE(prefix1.prefix.FromString("64:ff9b::"));
  original.nat64_prefixes.push_back(prefix1);

  Pref64Prefix prefix2;
  prefix2.prefix_length = 64;
  ASSERT_TRUE(prefix2.prefix.FromString("2001:db8:64::"));
  original.nat64_prefixes.push_back(prefix2);

  std::string serialized = SerializePref64CapsulePayload(original);
  ASSERT_EQ(serialized.size(), 26u);  // 2 prefixes * 13 bytes each.

  Pref64Capsule parsed;
  ASSERT_TRUE(ParsePref64CapsulePayload(serialized, &parsed));
  EXPECT_EQ(parsed, original);
  EXPECT_EQ(parsed.ToString(), "PREF64[(64:ff9b::/96)(2001:db8:64::/64)]");
}

TEST(MasqueUtilsTest, Pref64CapsuleInvalidLengthIsMalformed) {
  Pref64Capsule original;
  Pref64Prefix prefix;
  prefix.prefix_length = 96;
  ASSERT_TRUE(prefix.prefix.FromString("64:ff9b::"));
  original.nat64_prefixes.push_back(prefix);

  std::string serialized = SerializePref64CapsulePayload(original);
  // Remove one byte so length is not a multiple of 13.
  serialized.pop_back();

  Pref64Capsule parsed;
  EXPECT_FALSE(ParsePref64CapsulePayload(serialized, &parsed));
}

TEST(MasqueUtilsTest, Pref64CapsuleInvalidPrefixLengthIsMalformed) {
  Pref64Capsule original;
  Pref64Prefix prefix;
  prefix.prefix_length = 60;  // 60 is not in {32, 40, 48, 56, 64, 96}.
  ASSERT_TRUE(prefix.prefix.FromString("64:ff9b::"));
  original.nat64_prefixes.push_back(prefix);

  std::string serialized = SerializePref64CapsulePayload(original);
  ASSERT_EQ(serialized.size(), 13u);

  Pref64Capsule parsed;
  EXPECT_FALSE(ParsePref64CapsulePayload(serialized, &parsed));
}

TEST(MasqueUtilsTest, SvcParamsRoundTrip) {
  EXPECT_THAT(EncodeSvcParams(""), Optional(Eq("")));
  EXPECT_THAT(DecodeSvcParams(""), Optional(Eq("")));

  std::optional<std::string> encoded1 =
      EncodeSvcParams("alpn=h2,h3 dohpath=/dns-query{?dns}");
  ASSERT_THAT(encoded1, Optional(Not(IsEmpty())));
  EXPECT_THAT(DecodeSvcParams(*encoded1),
              Optional(Eq("alpn=h2,h3 dohpath=/dns-query{?dns}")));

  // Test out-of-order presentation strings are sorted by SvcParamKey in wire
  // format.
  std::optional<std::string> encoded2 =
      EncodeSvcParams("dohpath=/dns-query{?dns} alpn=h2,h3");
  ASSERT_THAT(encoded2, Optional(Not(IsEmpty())));
  EXPECT_EQ(*encoded1, *encoded2);

  // Test port, no-default-alpn, and ip hints.
  std::optional<std::string> encoded3 = EncodeSvcParams(
      "port=8080 no-default-alpn ipv4hint=192.0.2.1,10.0.0.1 "
      "ipv6hint=2001:db8::1");
  ASSERT_THAT(encoded3, Optional(Not(IsEmpty())));
  EXPECT_THAT(
      DecodeSvcParams(*encoded3),
      Optional(Eq("no-default-alpn port=8080 ipv4hint=192.0.2.1,10.0.0.1 "
                  "ipv6hint=2001:db8::1")));

  // Test malformed presentation format.
  EXPECT_EQ(EncodeSvcParams("unknown_key_format"), std::nullopt);
  EXPECT_EQ(EncodeSvcParams("port=not_an_int"), std::nullopt);
  EXPECT_EQ(EncodeSvcParams("ipv4hint=not_an_ip"), std::nullopt);
  EXPECT_EQ(EncodeSvcParams("alpn=h2 alpn=h3"), std::nullopt);  // Duplicate key

  // Test malformed wire format (out-of-order keys).
  char bad_wire_bytes[] = {0x00, 0x07, 0x00, 0x01, 'x', 0x00,
                           0x01, 0x00, 0x02, 'h',  '2'};
  EXPECT_EQ(
      DecodeSvcParams(std::string(bad_wire_bytes, sizeof(bad_wire_bytes))),
      std::nullopt);
}

TEST(MasqueUtilsTest, DnsAssignCapsuleMalformedSvcParams) {
  DnsAssignCapsule original;
  DnsConfiguration config;
  DnsNameserver ns;
  ns.service_priority = 10;
  QuicIpAddress ipv4;
  ASSERT_TRUE(ipv4.FromString("192.0.2.1"));
  ns.ipv4_addresses.push_back(ipv4);
  char bad_wire_bytes[] = {0x00, 0x07, 0x00, 0x01, 'x', 0x00,
                           0x01, 0x00, 0x02, 'h',  '2'};
  ns.service_parameters = std::string(bad_wire_bytes, sizeof(bad_wire_bytes));
  config.nameservers.push_back(ns);
  original.dns_configurations.push_back(config);

  std::string serialized;
  EXPECT_QUIC_BUG(serialized = SerializeDnsAssignCapsulePayload(original),
                  "Invalid service parameters wire format");
  EXPECT_TRUE(serialized.empty());
}

TEST(MasqueUtilsTest, NullPointerParsing) {
  EXPECT_FALSE(ParseDnsAssignCapsulePayload("any", nullptr));
  EXPECT_FALSE(ParsePref64CapsulePayload("any", nullptr));
}

}  // namespace
}  // namespace test
}  // namespace quic
