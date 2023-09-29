// Copyright (c) 2023 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche/blind_sign_auth/blind_sign_auth.h"

#include <memory>
#include <string>
#include <utility>

#include "absl/status/status.h"
#include "absl/status/statusor.h"
#include "absl/strings/escaping.h"
#include "absl/strings/string_view.h"
#include "absl/time/time.h"
#include "anonymous_tokens/cpp/testing/proto_utils.h"
#include "anonymous_tokens/cpp/testing/utils.h"
#include "openssl/base.h"
#include "quiche/blind_sign_auth/blind_sign_auth_protos.h"
#include "quiche/blind_sign_auth/blind_sign_http_interface.h"
#include "quiche/blind_sign_auth/blind_sign_http_response.h"
#include "quiche/blind_sign_auth/test_tools/mock_blind_sign_http_interface.h"
#include "quiche/common/platform/api/quiche_mutex.h"
#include "quiche/common/platform/api/quiche_test.h"
#include "quiche/common/test_tools/quiche_test_utils.h"

namespace quiche {
namespace test {
namespace {

using ::testing::_;
using ::testing::Eq;
using ::testing::InSequence;
using ::testing::Invoke;
using ::testing::StartsWith;
using ::testing::Unused;

class BlindSignAuthTest : public QuicheTest {
 protected:
  void SetUp() override {
    // Create public key.
    auto keypair = anonymous_tokens::CreateTestKey();
    if (!keypair.ok()) {
      return;
    }
    keypair_ = *std::move(keypair);
    keypair_.second.set_key_version(1);
    keypair_.second.set_use_case("TEST_USE_CASE");

    // Create fake GetInitialDataRequest.
    expected_get_initial_data_request_.set_use_attestation(false);
    expected_get_initial_data_request_.set_service_type("chromeipblinding");
    expected_get_initial_data_request_.set_location_granularity(
        privacy::ppn::GetInitialDataRequest_LocationGranularity_CITY_GEOS);

    // Create fake public key response.
    privacy::ppn::GetInitialDataResponse fake_get_initial_data_response;
    anonymous_tokens::RSABlindSignaturePublicKey public_key;
    ASSERT_TRUE(
        public_key.ParseFromString(keypair_.second.SerializeAsString()));
    *fake_get_initial_data_response.mutable_at_public_metadata_public_key() =
        public_key;

    // Create public metadata info.
    privacy::ppn::PublicMetadata::Location location;
    location.set_country("US");
    anonymous_tokens::Timestamp expiration;
    expiration.set_seconds(absl::ToUnixSeconds(absl::Now() + absl::Hours(1)));
    privacy::ppn::PublicMetadata public_metadata;
    *public_metadata.mutable_exit_location() = location;
    public_metadata.set_service_type("chromeipblinding");
    *public_metadata.mutable_expiration() = expiration;
    public_metadata_info_.set_validation_version(1);
    *public_metadata_info_.mutable_public_metadata() = public_metadata;
    *fake_get_initial_data_response.mutable_public_metadata_info() =
        public_metadata_info_;
    fake_get_initial_data_response_ = fake_get_initial_data_response;

    // Create BlindSignAuthOptions.
    privacy::ppn::BlindSignAuthOptions options;
    options.set_enable_privacy_pass(false);

    blind_sign_auth_ =
        std::make_unique<BlindSignAuth>(&mock_http_interface_, options);
  }

  void TearDown() override {
    blind_sign_auth_.reset(nullptr);
    keypair_.first.reset(nullptr);
    keypair_.second.Clear();
  }

 public:
  void CreateSignResponse(const std::string& body) {
    privacy::ppn::AuthAndSignRequest request;
    ASSERT_TRUE(request.ParseFromString(body));

    // Validate AuthAndSignRequest.
    EXPECT_EQ(request.oauth_token(), oauth_token_);
    EXPECT_EQ(request.service_type(), "chromeipblinding");
    // Phosphor does not need the public key hash if the KeyType is
    // privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE.
    EXPECT_EQ(request.key_type(), privacy::ppn::AT_PUBLIC_METADATA_KEY_TYPE);
    EXPECT_EQ(request.public_key_hash(), "");
    EXPECT_EQ(request.public_metadata_info().SerializeAsString(),
              public_metadata_info_.SerializeAsString());
    EXPECT_EQ(request.key_version(), keypair_.second.key_version());
    EXPECT_EQ(request.do_not_use_rsa_public_exponent(), true);

    // Construct AuthAndSignResponse.
    privacy::ppn::AuthAndSignResponse response;
    for (const auto& request_token : request.blinded_token()) {
      std::string decoded_blinded_token;
      ASSERT_TRUE(absl::Base64Unescape(request_token, &decoded_blinded_token));
      absl::StatusOr<std::string> serialized_token =
          anonymous_tokens::TestSign(decoded_blinded_token,
                                                         keypair_.first.get());
      QUICHE_EXPECT_OK(serialized_token);
      response.add_blinded_token_signature(
          absl::Base64Escape(*serialized_token));
    }
    sign_response_ = response;
  }

  void ValidateGetTokensOutput(const absl::Span<BlindSignToken>& tokens) {
    for (const auto& token : tokens) {
      privacy::ppn::SpendTokenData spend_token_data;
      ASSERT_TRUE(spend_token_data.ParseFromString(token.token));
      // Validate token structure.
      EXPECT_EQ(spend_token_data.public_metadata().SerializeAsString(),
                public_metadata_info_.public_metadata().SerializeAsString());
      EXPECT_THAT(spend_token_data.unblinded_token(), StartsWith("blind:"));
      EXPECT_GE(spend_token_data.unblinded_token_signature().size(),
                spend_token_data.unblinded_token().size());
      EXPECT_EQ(spend_token_data.signing_key_version(),
                keypair_.second.key_version());
      EXPECT_NE(spend_token_data.use_case(),
                anonymous_tokens::AnonymousTokensUseCase::
                    ANONYMOUS_TOKENS_USE_CASE_UNDEFINED);
      EXPECT_NE(spend_token_data.message_mask(), "");
    }
  }

  MockBlindSignHttpInterface mock_http_interface_;
  std::unique_ptr<BlindSignAuth> blind_sign_auth_;
  std::pair<bssl::UniquePtr<RSA>,
            anonymous_tokens::RSABlindSignaturePublicKey>
      keypair_;
  privacy::ppn::PublicMetadataInfo public_metadata_info_;
  privacy::ppn::AuthAndSignResponse sign_response_;
  privacy::ppn::GetInitialDataResponse fake_get_initial_data_response_;
  std::string oauth_token_ = "oauth_token";
  privacy::ppn::GetInitialDataRequest expected_get_initial_data_request_;
};

TEST_F(BlindSignAuthTest, TestGetTokensSuccessful) {
  BlindSignHttpResponse fake_public_key_response(
      200, fake_get_initial_data_response_.SerializeAsString());

  {
    InSequence seq;

    EXPECT_CALL(
        mock_http_interface_,
        DoRequest(
            Eq(BlindSignHttpRequestType::kGetInitialData), Eq(oauth_token_),
            Eq(expected_get_initial_data_request_.SerializeAsString()), _))
        .Times(1)
        .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
          std::move(get_initial_data_cb)(fake_public_key_response);
        });

    EXPECT_CALL(mock_http_interface_,
                DoRequest(Eq(BlindSignHttpRequestType::kAuthAndSign),
                          Eq(oauth_token_), _, _))
        .Times(1)
        .WillOnce(Invoke([this](Unused, Unused, const std::string& body,
                                BlindSignHttpCallback callback) {
          CreateSignResponse(body);
          BlindSignHttpResponse http_response(
              200, sign_response_.SerializeAsString());
          std::move(callback)(http_response);
        }));
  }

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [this, &done,
       num_tokens](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        QUICHE_EXPECT_OK(tokens);
        EXPECT_EQ(tokens->size(), num_tokens);
        ValidateGetTokensOutput(*tokens);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestGetTokensFailedNetworkError) {
  EXPECT_CALL(mock_http_interface_,
              DoRequest(Eq(BlindSignHttpRequestType::kGetInitialData),
                        Eq(oauth_token_), _, _))
      .Times(1)
      .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
        std::move(get_initial_data_cb)(
            absl::InternalError("Failed to create socket"));
      });

  EXPECT_CALL(mock_http_interface_,
              DoRequest(Eq(BlindSignHttpRequestType::kAuthAndSign), _, _, _))
      .Times(0);

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInternal);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestGetTokensFailedBadGetInitialDataResponse) {
  *fake_get_initial_data_response_.mutable_at_public_metadata_public_key()
       ->mutable_use_case() = "SPAM";

  BlindSignHttpResponse fake_public_key_response(
      200, fake_get_initial_data_response_.SerializeAsString());

  EXPECT_CALL(
      mock_http_interface_,
      DoRequest(Eq(BlindSignHttpRequestType::kGetInitialData), Eq(oauth_token_),
                Eq(expected_get_initial_data_request_.SerializeAsString()), _))
      .Times(1)
      .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
        std::move(get_initial_data_cb)(fake_public_key_response);
      });

  EXPECT_CALL(mock_http_interface_,
              DoRequest(Eq(BlindSignHttpRequestType::kAuthAndSign), _, _, _))
      .Times(0);

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInvalidArgument);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestGetTokensFailedBadAuthAndSignResponse) {
  BlindSignHttpResponse fake_public_key_response(
      200, fake_get_initial_data_response_.SerializeAsString());
  {
    InSequence seq;

    EXPECT_CALL(
        mock_http_interface_,
        DoRequest(
            Eq(BlindSignHttpRequestType::kGetInitialData), Eq(oauth_token_),
            Eq(expected_get_initial_data_request_.SerializeAsString()), _))
        .Times(1)
        .WillOnce([=](auto&&, auto&&, auto&&, auto get_initial_data_cb) {
          std::move(get_initial_data_cb)(fake_public_key_response);
        });

    EXPECT_CALL(mock_http_interface_,
                DoRequest(Eq(BlindSignHttpRequestType::kAuthAndSign),
                          Eq(oauth_token_), _, _))
        .Times(1)
        .WillOnce(Invoke([this](Unused, Unused, const std::string& body,
                                BlindSignHttpCallback callback) {
          CreateSignResponse(body);
          // Add an invalid signature that can't be Base64 decoded.
          sign_response_.add_blinded_token_signature("invalid_signature%");
          BlindSignHttpResponse http_response(
              200, sign_response_.SerializeAsString());
          std::move(callback)(http_response);
        }));
  }

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kInternal);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, std::move(callback));
  done.WaitForNotification();
}

TEST_F(BlindSignAuthTest, TestGetTokensFailedPrivacyPass) {
  privacy::ppn::BlindSignAuthOptions options;
  options.set_enable_privacy_pass(true);
  blind_sign_auth_ =
      std::make_unique<BlindSignAuth>(&mock_http_interface_, options);

  int num_tokens = 1;
  QuicheNotification done;
  SignedTokenCallback callback =
      [&done](absl::StatusOr<absl::Span<BlindSignToken>> tokens) {
        EXPECT_THAT(tokens.status().code(), absl::StatusCode::kUnimplemented);
        done.Notify();
      };
  blind_sign_auth_->GetTokens(oauth_token_, num_tokens, std::move(callback));
  done.WaitForNotification();
}

}  // namespace
}  // namespace test
}  // namespace quiche
