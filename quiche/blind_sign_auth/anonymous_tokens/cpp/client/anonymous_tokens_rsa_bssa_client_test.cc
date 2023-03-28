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

#include "quiche/blind_sign_auth/anonymous_tokens/cpp/client/anonymous_tokens_rsa_bssa_client.h"

#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"
#include "absl/time/time.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/shared/proto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/shared/status_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

using quiche::test::StatusIs;

absl::StatusOr<std::pair<bssl::UniquePtr<RSA>, RSABlindSignaturePublicKey>>
CreateClientTestKey(absl::string_view use_case = "TEST_USE_CASE",
                    int key_version = 1,
                    MessageMaskType mask_type = AT_MESSAGE_MASK_CONCAT,
                    int message_mask_size = 32) {
  ANON_TOKENS_ASSIGN_OR_RETURN(auto key, CreateTestKey());
  key.second.set_use_case(std::string(use_case));
  key.second.set_key_version(key_version);
  key.second.set_message_mask_type(mask_type);
  key.second.set_message_mask_size(message_mask_size);
  absl::Time start_time = absl::Now() - absl::Minutes(100);
  ANON_TOKENS_ASSIGN_OR_RETURN(*key.second.mutable_key_validity_start_time(),
                               TimeToProto(start_time));
  return key;
}

TEST(CreateAnonymousTokensRsaBssaClientTest, Success) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key, CreateClientTestKey());
  QUICHE_EXPECT_OK(AnonymousTokensRsaBssaClient::Create(rsa_key.second));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key,
                                   CreateClientTestKey("INVALID_USE_CASE"));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.second),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, NotAUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key,
                                   CreateClientTestKey("NOT_A_USE_CASE"));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.second),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidKeyVersion) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key,
                                   CreateClientTestKey("TEST_USE_CASE", 0));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.second),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidMessageMaskType) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto rsa_key,
      CreateClientTestKey("TEST_USE_CASE", 0, AT_MESSAGE_MASK_TYPE_UNDEFINED));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.second),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidMessageMaskSize) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto rsa_key,
      CreateClientTestKey("TEST_USE_CASE", 0, AT_MESSAGE_MASK_CONCAT, 0));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.second),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class AnonymousTokensRsaBssaClientTest : public testing::Test {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto key, CreateClientTestKey());
    rsa_key_ = std::move(key.first);
    public_key_ = std::move(key.second);
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        client_, AnonymousTokensRsaBssaClient::Create(public_key_));
  }

  absl::StatusOr<AnonymousTokensSignResponse> CreateResponse(
      const AnonymousTokensSignRequest& request) {
    AnonymousTokensSignResponse response;
    for (const auto& request_token : request.blinded_tokens()) {
      auto* response_token = response.add_anonymous_tokens();
      response_token->set_use_case(request_token.use_case());
      response_token->set_key_version(request_token.key_version());
      response_token->set_public_metadata(request_token.public_metadata());
      response_token->set_serialized_blinded_message(
          request_token.serialized_token());
      ANON_TOKENS_ASSIGN_OR_RETURN(
          *response_token->mutable_serialized_token(),
          TestSign(request_token.serialized_token(), rsa_key_.get()));
    }
    return response;
  }

  std::vector<PlaintextMessageWithPublicMetadata> CreateInput(
      const std::vector<std::string>& messages) {
    std::vector<PlaintextMessageWithPublicMetadata> output;
    output.reserve(messages.size());
    for (const std::string& message : messages) {
      PlaintextMessageWithPublicMetadata proto;
      proto.set_plaintext_message(message);
      output.push_back(proto);
    }
    return output;
  }

  bssl::UniquePtr<RSA> rsa_key_;
  RSABlindSignaturePublicKey public_key_;
  std::unique_ptr<AnonymousTokensRsaBssaClient> client_;
};

TEST_F(AnonymousTokensRsaBssaClientTest, SuccessOneMessage) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      client_->CreateRequest(CreateInput({"message"})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request));
  QUICHE_EXPECT_OK(client_->ProcessResponse(response));
  EXPECT_EQ(response.anonymous_tokens_size(), 1);
}

TEST_F(AnonymousTokensRsaBssaClientTest, SuccessMultipleMessages) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      client_->CreateRequest(CreateInput(
          {"message1", "msg2", "anotherMessage", "one_more_message"})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request));
  EXPECT_EQ(response.anonymous_tokens_size(), 4);
  QUICHE_EXPECT_OK(client_->ProcessResponse(response));
}

TEST_F(AnonymousTokensRsaBssaClientTest, EnsureRandomTokens) {
  std::string message = "test_same_message";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      client_->CreateRequest(CreateInput({message, message})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<RSABlindSignatureTokenWithInput> tokens,
      client_->ProcessResponse(response));
  ASSERT_EQ(tokens.size(), 2);
  for (const RSABlindSignatureTokenWithInput& token : tokens) {
    EXPECT_EQ(token.input().plaintext_message(), message);
  }
  EXPECT_NE(tokens[0].token().message_mask(), tokens[1].token().message_mask());
  EXPECT_NE(tokens[0].token().token(), tokens[1].token().token());
}

TEST_F(AnonymousTokensRsaBssaClientTest, EmptyInput) {
  EXPECT_THAT(client_->CreateRequest(CreateInput({})),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, NotYetValidKey) {
  RSABlindSignaturePublicKey not_valid_key = public_key_;
  absl::Time start_time = absl::Now() + absl::Minutes(100);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      *not_valid_key.mutable_key_validity_start_time(),
      TimeToProto(start_time));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<AnonymousTokensRsaBssaClient> client,
      AnonymousTokensRsaBssaClient::Create(not_valid_key));
  EXPECT_THAT(client->CreateRequest(CreateInput({"message"})),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ExpiredKey) {
  RSABlindSignaturePublicKey expired_key = public_key_;
  absl::Time end_time = absl::Now() - absl::Seconds(1);
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(*expired_key.mutable_expiration_time(),
                                   TimeToProto(end_time));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<AnonymousTokensRsaBssaClient> client,
      AnonymousTokensRsaBssaClient::Create(expired_key));
  EXPECT_THAT(client->CreateRequest(CreateInput({"message"})),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, CreateRequestTwice) {
  QUICHE_EXPECT_OK(client_->CreateRequest(CreateInput({"once"})));
  EXPECT_THAT(client_->CreateRequest(CreateInput({"twice"})),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseWithoutCreateRequest) {
  AnonymousTokensSignResponse response;
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessEmptyResponse) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      client_->CreateRequest(CreateInput({"message"})));
  AnonymousTokensSignResponse response;
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseWithBadUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      client_->CreateRequest(CreateInput({"message"})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request));
  response.mutable_anonymous_tokens(0)->set_use_case("TEST_USE_CASE_2");
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseWithBadKeyVersion) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      client_->CreateRequest(CreateInput({"message"})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request));
  response.mutable_anonymous_tokens(0)->set_key_version(2);
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseFromDifferentClient) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<AnonymousTokensRsaBssaClient> client2,
      AnonymousTokensRsaBssaClient::Create(public_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request1,
      client_->CreateRequest(CreateInput({"message"})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request2,
      client2->CreateRequest(CreateInput({"message"})));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response1,
                                   CreateResponse(request1));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response2,
                                   CreateResponse(request2));
  EXPECT_THAT(client_->ProcessResponse(response2),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client2->ProcessResponse(response1),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
