#ifndef QUICHE_HTTP2_ADAPTER_MINIMAL_HEADER_VALIDATOR_H_
#define QUICHE_HTTP2_ADAPTER_MINIMAL_HEADER_VALIDATOR_H_

#include "absl/strings/string_view.h"
#include "quiche/http2/adapter/header_validator_base.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace http2 {
namespace adapter {

// A validator that performs the minimum validation necessary.
class QUICHE_EXPORT MinimalHeaderValidator : public HeaderValidatorBase {
 public:
  MinimalHeaderValidator() = default;

  void StartHeaderBlock() override;
  HeaderStatus ValidateSingleHeader(absl::string_view key,
                                    absl::string_view value) override;

  bool FinishHeaderBlock(HeaderType type) override;

 private:
  bool has_method_ = false;
  bool has_scheme_ = false;
  bool has_path_ = false;
};

}  // namespace adapter
}  // namespace http2

#endif  // QUICHE_HTTP2_ADAPTER_MINIMAL_HEADER_VALIDATOR_H_
