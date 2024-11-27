// Copyright 2024 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file

#include "quiche/quic/moqt/moqt_track.h"

#include "quiche/quic/moqt/moqt_messages.h"

namespace moqt {

bool RemoteTrack::CheckDataStreamType(MoqtDataStreamType type) {
  if (data_stream_type_.has_value()) {
    return data_stream_type_.value() == type;
  }
  data_stream_type_ = type;
  return true;
}

}  // namespace moqt
