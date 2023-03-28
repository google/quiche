// Copyright 2023 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/shared/proto_utils.h"

#include "quiche/blind_sign_auth/proto/timestamp.pb.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/time/time.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

TEST(ProtoUtilsTest, EmptyUseCase) {
  EXPECT_THAT(ParseUseCase("").status().code(),
              absl::StatusCode::kInvalidArgument);
}

TEST(ProtoUtilsTest, InvalidUseCase) {
  EXPECT_THAT(ParseUseCase("NOT_A_USE_CASE").status().code(),
              absl::StatusCode::kInvalidArgument);
}

TEST(ProtoUtilsTest, UndefinedUseCase) {
  EXPECT_THAT(
      ParseUseCase("ANONYMOUS_TOKENS_USE_CASE_UNDEFINED").status().code(),
      absl::StatusCode::kInvalidArgument);
}

TEST(ProtoUtilsTest, ValidUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensUseCase use_case,
                                   ParseUseCase("TEST_USE_CASE"));
  EXPECT_EQ(use_case, AnonymousTokensUseCase::TEST_USE_CASE);
}

TEST(ProtoUtilsTest, TimeFromProtoGood) {
  quiche::protobuf::Timestamp timestamp;
  timestamp.set_seconds(1234567890);
  timestamp.set_nanos(12345);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(absl::Time time, TimeFromProto(timestamp));
  ASSERT_EQ(time, absl::FromUnixNanos(1234567890000012345));
}

TEST(ProtoUtilsTest, TimeFromProtoBad) {
  quiche::protobuf::Timestamp proto;
  proto.set_nanos(-1);
  EXPECT_THAT(TimeFromProto(proto).status().code(),
              absl::StatusCode::kInvalidArgument);

  proto.set_nanos(0);
  proto.set_seconds(253402300800);
  EXPECT_THAT(TimeFromProto(proto).status().code(),
              absl::StatusCode::kInvalidArgument);
}

TEST(ProtoUtilsTest, TimeToProtoGood) {
  quiche::protobuf::Timestamp proto;
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      proto, TimeToProto(absl::FromUnixSeconds(1596762373)));
  EXPECT_EQ(proto.seconds(), 1596762373);
  EXPECT_EQ(proto.nanos(), 0);

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      proto, TimeToProto(absl::FromUnixMillis(1596762373123L)));
  EXPECT_EQ(proto.seconds(), 1596762373);
  EXPECT_EQ(proto.nanos(), 123000000);
}

TEST(ProtoUtilsTest, TimeToProtoBad) {
  absl::StatusOr<quiche::protobuf::Timestamp> proto;
  proto = TimeToProto(absl::FromUnixSeconds(253402300800));
  EXPECT_THAT(proto.status().code(), absl::StatusCode::kInvalidArgument);
}

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
