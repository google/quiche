// Copyright 2021 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef QUICHE_COMMON_BALSA_BALSA_VISITOR_INTERFACE_H_
#define QUICHE_COMMON_BALSA_BALSA_VISITOR_INTERFACE_H_

#include <cstddef>

#include "quiche/common/balsa/balsa_enums.h"
#include "quiche/common/platform/api/quiche_export.h"

namespace quiche {

class BalsaHeaders;

// By default the BalsaFrame instantiates a class derived from this interface
// which does absolutely nothing. If you'd prefer to have interesting
// functionality execute when any of the below functions are called by the
// BalsaFrame, then you should subclass it, and set an instantiation of your
// subclass as the current visitor for the BalsaFrame class using
// BalsaFrame::set_visitor().
class QUICHE_EXPORT_PRIVATE BalsaVisitorInterface {
 public:
  virtual ~BalsaVisitorInterface() {}

  // Summary:
  //   This is how the BalsaFrame passes you the raw input which it knows to
  //   be a part of the body. To be clear, every byte of the Balsa which isn't
  //   part of the header (or its framing), or trailers will be passed through
  //   this function.  This includes data as well as chunking framing.
  // Arguments:
  //   input - contains the bytes available for read.
  //   size - contains the number of bytes it is safe to read from input.
  virtual void OnRawBodyInput(const char* input, size_t size) = 0;

  // Summary:
  //   This is like OnRawBodyInput, but it will only include those parts of
  //   the body which would be stored by a program such as wget, i.e. the bytes
  //   indicating chunking will have been removed. Trailers will not be
  //   passed in through this function-- they'll be passed in through
  //   OnTrailerInput.
  // Arguments:
  //  input - contains the bytes available for read.
  //  size - contains the number of bytes it is safe to read from input.
  virtual void OnBodyChunkInput(const char* input, size_t size) = 0;

  // Summary:
  //   BalsaFrame passes the raw header data through this function. This is
  //   not cleaned up in any way.
  // Arguments:
  //  input - contains the bytes available for read.
  //  size - contains the number of bytes it is safe to read from input.
  virtual void OnHeaderInput(const char* input, size_t size) = 0;

  // Summary:
  //   BalsaFrame passes the raw trailer data through this function. This is
  //   not cleaned up in any way.  Note that trailers only occur in a message
  //   if there was a chunked encoding, and not always then.
  //
  // Arguments:
  //  input - contains the bytes available for read.
  //  size - contains the number of bytes it is safe to read from input.
  virtual void OnTrailerInput(const char* input, size_t size) = 0;

  // Summary:
  //   Since the BalsaFrame already has to parse the headers in order to
  //   determine proper framing, it might as well pass the parsed and
  //   cleaned-up results to whatever might need it.  This function exists for
  //   that purpose-- parsed headers are passed into this function.
  // Arguments:
  //   headers - contains the parsed headers in the order in which
  //             they occurred in the header.
  virtual void ProcessHeaders(const BalsaHeaders& headers) = 0;

  // Summary:
  //   Since the BalsaFrame already has to parse the trailer, it might as well
  //   pass the parsed and cleaned-up results to whatever might need it.
  //   This function exists for that purpose-- parsed trailer is passed into
  //   this function. This will not be called if the trailer_ object is
  //   not set in the framer, even if trailer exists in request/response.
  // Arguments:
  //   trailer - contains the parsed headers in the order in which
  //             they occurred in the trailer.
  virtual void ProcessTrailers(const BalsaHeaders& trailer) = 0;

  // Summary:
  //   Called when the first line of the message is parsed, in this case, for a
  //   request.
  // Arguments:
  //   line_input - pointer to the beginning of the first line string.
  //   line_length - length of the first line string. (i.e. the numer of
  //                 bytes it is safe to read from line_ptr)
  //   method_input - pointer to the beginning of the method string
  //   method_length - length of the method string (i.e. the number
  //                   of bytes it is safe to read from method_input)
  //   request_uri_input - pointer to the beginning of the request uri
  //                       string.
  //   request_uri_length - length of the method string (i.e. the number
  //                        of bytes it is safe to read from method_input)
  //   version_input - pointer to the beginning of the version string.
  //   version_length - length of the version string (i.e. the number
  //                    of bytes it i ssafe to read from version_input)
  virtual void OnRequestFirstLineInput(
      const char* line_input, size_t line_length, const char* method_input,
      size_t method_length, const char* request_uri_input,
      size_t request_uri_length, const char* version_input,
      size_t version_length) = 0;

  // Summary:
  //   Called when the first line of the message is parsed, in this case, for a
  //   response.
  // Arguments:
  //   line_input - pointer to the beginning of the first line string.
  //   line_length - length of the first line string. (i.e. the numer of
  //                 bytes it is safe to read from line_ptr)
  //   version_input - pointer to the beginning of the version string.
  //   version_length - length of the version string (i.e. the number
  //                    of bytes it i ssafe to read from version_input)
  //   status_input - pointer to the beginning of the status string
  //   status_length - length of the status string (i.e. the number
  //                   of bytes it is safe to read from status_input)
  //   reason_input - pointer to the beginning of the reason string
  //   reason_length - length of the reason string (i.e. the number
  //                   of bytes it is safe to read from reason_input)
  virtual void OnResponseFirstLineInput(
      const char* line_input, size_t line_length, const char* version_input,
      size_t version_length, const char* status_input, size_t status_length,
      const char* reason_input, size_t reason_length) = 0;

  // Called when a chunk length is parsed.
  // Arguments:
  //   chunk length - the length of the next incoming chunk.
  virtual void OnChunkLength(size_t chunk_length) = 0;

  // Summary:
  //   BalsaFrame passes the raw chunk extension data through this function.
  //   The data is not cleaned up at all.
  //
  // Arguments:
  //  input - contains the bytes available for read.
  //  size - contains the number of bytes it is safe to read from input.
  virtual void OnChunkExtensionInput(const char* input, size_t size) = 0;

  // Summary:
  //   Called when the header is framed and processed.
  virtual void HeaderDone() = 0;

  // Summary:
  //   Called when the 100 Continue headers are framed and processed.
  virtual void ContinueHeaderDone() = 0;

  // Summary:
  //   Called when the message is framed and processed.
  virtual void MessageDone() = 0;

  // Summary:
  //   Called when an error is detected
  // Arguments:
  //   error_code - the error which is to be reported
  virtual void HandleError(BalsaFrameEnums::ErrorCode error_code) = 0;

  // Summary:
  //   Called when something meriting a warning is detected
  // Arguments:
  //   error_code - the warning which is to be reported
  virtual void HandleWarning(BalsaFrameEnums::ErrorCode error_code) = 0;
};

}  // namespace quiche

#endif  // QUICHE_COMMON_BALSA_BALSA_VISITOR_INTERFACE_H_
