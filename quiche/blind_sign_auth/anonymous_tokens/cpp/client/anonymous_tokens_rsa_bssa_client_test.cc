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
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/constants.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/crypto/rsa_blind_signer.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/shared/proto_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/shared/status_utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/cpp/testing/utils.h"
#include "quiche/blind_sign_auth/anonymous_tokens/proto/anonymous_tokens.pb.h"
#include "openssl/base.h"
#include "openssl/rsa.h"

namespace private_membership {
namespace anonymous_tokens {
namespace {

using ::testing::SizeIs;
using quiche::test::StatusIs;

// Returns a fixed public private key pair by calling GetStrongRsaKeys4096().
absl::StatusOr<std::pair<RSABlindSignaturePublicKey, RSAPrivateKey>>
CreateClientTestKey(absl::string_view use_case = "TEST_USE_CASE",
                    int key_version = 1,
                    MessageMaskType mask_type = AT_MESSAGE_MASK_CONCAT,
                    int message_mask_size = 32,
                    bool enable_public_metadata = false) {
  ANON_TOKENS_ASSIGN_OR_RETURN(auto key_pair, GetStrongRsaKeys4096());
  RSABlindSignaturePublicKey public_key;
  public_key.set_use_case(std::string(use_case));
  public_key.set_key_version(key_version);
  public_key.set_serialized_public_key(key_pair.first.SerializeAsString());
  absl::Time start_time = absl::Now() - absl::Minutes(100);
  ANON_TOKENS_ASSIGN_OR_RETURN(*public_key.mutable_key_validity_start_time(),
                               TimeToProto(start_time));
  public_key.set_sig_hash_type(AT_HASH_TYPE_SHA384);
  public_key.set_mask_gen_function(AT_MGF_SHA384);
  public_key.set_salt_length(kSaltLengthInBytes48);
  public_key.set_key_size(kRsaModulusSizeInBytes512);
  public_key.set_message_mask_type(mask_type);
  public_key.set_message_mask_size(message_mask_size);
  public_key.set_public_metadata_support(enable_public_metadata);

  return std::make_pair(std::move(public_key), std::move(key_pair.second));
}

// Creates the input consisting on plaintext messages and public metadata that
// can be passed to the AnonymousTokensRsaBssaClient.
absl::StatusOr<std::vector<PlaintextMessageWithPublicMetadata>> CreateInput(
    absl::Span<const std::string> messages,
    absl::Span<const std::string> public_metadata = {}) {
  // Check input parameter sizes.
  if (!public_metadata.empty() && messages.size() != public_metadata.size()) {
    return absl::InvalidArgumentError(
        "Input vectors should be of the same size.");
  }

  std::vector<PlaintextMessageWithPublicMetadata> anonymmous_tokens_input_proto;
  anonymmous_tokens_input_proto.reserve(messages.size());
  for (int i = 0; i < messages.size(); ++i) {
    PlaintextMessageWithPublicMetadata input_message_and_metadata;
    input_message_and_metadata.set_plaintext_message(messages[i]);
    if (!public_metadata.empty()) {
      input_message_and_metadata.set_public_metadata(public_metadata[i]);
    }
    anonymmous_tokens_input_proto.push_back(input_message_and_metadata);
  }
  return anonymmous_tokens_input_proto;
}

// Creates the server response for anonymous tokens request by using
// RsaBlindSigner.
absl::StatusOr<AnonymousTokensSignResponse> CreateResponse(
    const AnonymousTokensSignRequest& request, const RSAPrivateKey& private_key,
    bool enable_public_metadata = false) {
  AnonymousTokensSignResponse response;
  for (const auto& request_token : request.blinded_tokens()) {
    auto* response_token = response.add_anonymous_tokens();
    response_token->set_use_case(request_token.use_case());
    response_token->set_key_version(request_token.key_version());
    response_token->set_public_metadata(request_token.public_metadata());
    response_token->set_serialized_blinded_message(
        request_token.serialized_token());
    std::optional<std::string> public_metadata = std::nullopt;
    if (enable_public_metadata) {
      public_metadata = request_token.public_metadata();
    }
    ANON_TOKENS_ASSIGN_OR_RETURN(
        std::unique_ptr<RsaBlindSigner> blind_signer,
        RsaBlindSigner::New(private_key, public_metadata));
    ANON_TOKENS_ASSIGN_OR_RETURN(
        *response_token->mutable_serialized_token(),
        blind_signer->Sign(request_token.serialized_token()));
  }
  return response;
}

TEST(CreateAnonymousTokensRsaBssaClientTest, Success) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key, CreateClientTestKey());
  QUICHE_EXPECT_OK(AnonymousTokensRsaBssaClient::Create(rsa_key.first));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key,
                                   CreateClientTestKey("INVALID_USE_CASE"));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.first),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, NotAUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key,
                                   CreateClientTestKey("NOT_A_USE_CASE"));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.first),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidKeyVersion) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto rsa_key,
                                   CreateClientTestKey("TEST_USE_CASE", 0));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.first),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidMessageMaskType) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto rsa_key,
      CreateClientTestKey("TEST_USE_CASE", 0, AT_MESSAGE_MASK_TYPE_UNDEFINED));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.first),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST(CreateAnonymousTokensRsaBssaClientTest, InvalidMessageMaskSize) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      auto rsa_key,
      CreateClientTestKey("TEST_USE_CASE", 0, AT_MESSAGE_MASK_CONCAT, 0));
  EXPECT_THAT(AnonymousTokensRsaBssaClient::Create(rsa_key.first),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class AnonymousTokensRsaBssaClientTest : public testing::Test {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(std::tie(public_key_, private_key_),
                                     CreateClientTestKey());
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        client_, AnonymousTokensRsaBssaClient::Create(public_key_));
  }

  RSAPrivateKey private_key_;
  RSABlindSignaturePublicKey public_key_;
  std::unique_ptr<AnonymousTokensRsaBssaClient> client_;
};

TEST_F(AnonymousTokensRsaBssaClientTest, SuccessOneMessage) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request,
                                   client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request, private_key_));
  EXPECT_THAT(response.anonymous_tokens(), SizeIs(1));
  QUICHE_EXPECT_OK(client_->ProcessResponse(response));
}

TEST_F(AnonymousTokensRsaBssaClientTest, SuccessMultipleMessages) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message1", "msg2", "anotherMessage", "one_more_message"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request,
                                   client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request, private_key_));
  EXPECT_THAT(response.anonymous_tokens(), SizeIs(4));
  QUICHE_EXPECT_OK(client_->ProcessResponse(response));
}

TEST_F(AnonymousTokensRsaBssaClientTest, EnsureRandomTokens) {
  std::string message = "test_same_message";
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({message, message}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request,
                                   client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request, private_key_));
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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({}));
  EXPECT_THAT(client_->CreateRequest(input_messages),
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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  EXPECT_THAT(client->CreateRequest(input_messages),
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
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  EXPECT_THAT(client->CreateRequest(input_messages),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, CreateRequestTwice) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  QUICHE_EXPECT_OK(client_->CreateRequest(input_messages));
  EXPECT_THAT(client_->CreateRequest(input_messages),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseWithoutCreateRequest) {
  AnonymousTokensSignResponse response;
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kFailedPrecondition));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessEmptyResponse) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request,
                                   client_->CreateRequest(input_messages));
  AnonymousTokensSignResponse response;
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseWithBadUseCase) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request,
                                   client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request, private_key_));
  response.mutable_anonymous_tokens(0)->set_use_case("TEST_USE_CASE_2");
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseWithBadKeyVersion) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request,
                                   client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response,
                                   CreateResponse(request, private_key_));
  response.mutable_anonymous_tokens(0)->set_key_version(2);
  EXPECT_THAT(client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientTest, ProcessResponseFromDifferentClient) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<AnonymousTokensRsaBssaClient> client2,
      AnonymousTokensRsaBssaClient::Create(public_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request1,
                                   client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignRequest request2,
                                   client2->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response1,
                                   CreateResponse(request1, private_key_));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(AnonymousTokensSignResponse response2,
                                   CreateResponse(request2, private_key_));
  EXPECT_THAT(client_->ProcessResponse(response2),
              StatusIs(absl::StatusCode::kInvalidArgument));
  EXPECT_THAT(client2->ProcessResponse(response1),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

class AnonymousTokensRsaBssaClientWithPublicMetadataTest
    : public testing::Test {
 protected:
  void SetUp() override {
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        std::tie(public_key_, private_key_),
        CreateClientTestKey("TEST_USE_CASE", /*key_version=*/1,
                            AT_MESSAGE_MASK_CONCAT,
                            kRsaMessageMaskSizeInBytes32,
                            /*enable_public_metadata=*/true));
    ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
        public_metadata_client_,
        AnonymousTokensRsaBssaClient::Create(public_key_));
  }

  RSAPrivateKey private_key_;
  RSABlindSignaturePublicKey public_key_;
  std::unique_ptr<AnonymousTokensRsaBssaClient> public_metadata_client_;
};

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       SuccessOneMessageWithPublicMetadata) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}, {"md1"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      public_metadata_client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/true));
  EXPECT_THAT(response.anonymous_tokens(), SizeIs(1));
  QUICHE_EXPECT_OK(public_metadata_client_->ProcessResponse(response));
}

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       FailureWithEmptyPublicMetadata) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}, {"md1"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      public_metadata_client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/false));
  EXPECT_THAT(public_metadata_client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       FailureWithWrongPublicMetadata) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}, {"md1"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      public_metadata_client_->CreateRequest(input_messages));
  request.mutable_blinded_tokens(0)->set_public_metadata(
      "wrong_public_metadata");
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/true));
  EXPECT_THAT(public_metadata_client_->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       FailureWithPublicMetadataSupportOff) {
  // Create a client with public metadata support disabled.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(auto key_pair, CreateClientTestKey());
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::unique_ptr<AnonymousTokensRsaBssaClient> non_public_metadata_client,
      AnonymousTokensRsaBssaClient::Create(key_pair.first));

  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message"}, {"md1"}));
  // Use client_ that does not support public metadata.
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      non_public_metadata_client->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/true));
  EXPECT_THAT(non_public_metadata_client->ProcessResponse(response),
              StatusIs(absl::StatusCode::kInvalidArgument));
}

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       SuccessMultipleMessagesWithDistinctPublicMetadata) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message1", "msg2", "anotherMessage", "one_more_message"},
                  {"md1", "md2", "md3", "md4"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      public_metadata_client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/true));
  EXPECT_THAT(response.anonymous_tokens(), SizeIs(4));
  QUICHE_EXPECT_OK(public_metadata_client_->ProcessResponse(response));
}

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       SuccessMultipleMessagesWithRepeatedPublicMetadata) {
  // Create input with repeated public metadata
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message1", "msg2", "anotherMessage", "one_more_message"},
                  {"md1", "md2", "md2", "md1"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      public_metadata_client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/true));
  EXPECT_THAT(response.anonymous_tokens(), SizeIs(4));
  QUICHE_EXPECT_OK(public_metadata_client_->ProcessResponse(response));
}

TEST_F(AnonymousTokensRsaBssaClientWithPublicMetadataTest,
       SuccessMultipleMessagesWithEmptyStringPublicMetadata) {
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      std::vector<PlaintextMessageWithPublicMetadata> input_messages,
      CreateInput({"message1", "msg2", "anotherMessage", "one_more_message"},
                  {"md1", "", "", "md4"}));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignRequest request,
      public_metadata_client_->CreateRequest(input_messages));
  ANON_TOKENS_ASSERT_OK_AND_ASSIGN(
      AnonymousTokensSignResponse response,
      CreateResponse(request, private_key_, /*enable_public_metadata=*/true));
  EXPECT_THAT(response.anonymous_tokens(), SizeIs(4));
  QUICHE_EXPECT_OK(public_metadata_client_->ProcessResponse(response));
}

}  // namespace
}  // namespace anonymous_tokens
}  // namespace private_membership
