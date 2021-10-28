// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "quiche_platform_impl/quiche_url_utils_impl.h"

#include "absl/container/flat_hash_map.h"
#include "absl/container/flat_hash_set.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_replace.h"
#include "url/url_util.h"

namespace quiche {

bool ExpandURITemplateImpl(
    const std::string& uri_template,
    const absl::flat_hash_map<std::string, std::string>& parameters,
    std::string* target, absl::flat_hash_set<std::string>* vars_found) {
  absl::flat_hash_set<std::string> found;
  std::string result = uri_template;
  for (const auto& pair : parameters) {
    const std::string& name = pair.first;
    const std::string& value = pair.second;
    std::string name_input = absl::StrCat("{", name, "}");
    url::RawCanonOutputT<char> canon_value;
    url::EncodeURIComponent(value.c_str(), value.length(), &canon_value);
    std::string encoded_value(canon_value.data(), canon_value.length());
    int num_replaced =
        absl::StrReplaceAll({{name_input, encoded_value}}, &result);
    if (num_replaced > 0) {
      found.insert(name);
    }
  }
  if (vars_found != nullptr) {
    *vars_found = found;
  }
  *target = result;
  return true;
}

}  // namespace quiche
