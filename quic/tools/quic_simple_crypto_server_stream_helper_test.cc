#include "net/third_party/quiche/src/quic/tools/quic_simple_crypto_server_stream_helper.h"

#include "net/third_party/quiche/src/quic/core/quic_utils.h"
#include "net/third_party/quiche/src/quic/platform/api/quic_test.h"
#include "net/third_party/quiche/src/quic/test_tools/mock_random.h"
#include "net/third_party/quiche/src/quic/test_tools/quic_test_utils.h"

namespace quic {

class QuicSimpleCryptoServerStreamHelperTest : public QuicTest {};

TEST_F(QuicSimpleCryptoServerStreamHelperTest, GenerateConnectionIdForReject) {
  test::MockRandom random;
  QuicSimpleCryptoServerStreamHelper helper(&random);

  EXPECT_EQ(QuicUtils::CreateRandomConnectionId(&random),
            helper.GenerateConnectionIdForReject(QUIC_VERSION_35,
                                                 test::TestConnectionId()));

  EXPECT_EQ(QuicUtils::CreateRandomConnectionId(&random),
            helper.GenerateConnectionIdForReject(QUIC_VERSION_99,
                                                 test::TestConnectionId()));
}

}  // namespace quic
