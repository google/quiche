# HTTP/2

This directory contains C++ code implementing
[the HTTP/2 protocol](https://www.rfc-editor.org/rfc/rfc9113.html).

Much of this code was written originally as a collaboration between the
[Chromium networking](https://www.chromium.org/developers/design-documents/network-stack/)
and
[Google Front End](https://cloud.google.com/docs/security/infrastructure/design#google-frontend-service)
teams while developing the experimental SPDY protocol. SPDY was later
standardized as HTTP/2.

## `http2/adapter/`

This subdirectory contains general purpose HTTP/2 protocol handling libraries.
The `oghttp2_adapter` library can be used in combination with an event loop, a
TLS library, and a socket library to make a complete HTTP/2 client or server.

## `http2/core/`

This subdirectory contains core utilities, including constants, data structures,
and some common entry points that can be used to parse and serialize HTTP/2
protocol elements.

## `http2/decoder`

This subdirectory contains a decoder for the HTTP/2 wire format, written from
scratch by James Synge. This decoder is used by Chromium-based browsers, the
Google Front End reverse-proxy, and Envoy-based proxies.

## `http2/hpack`

This subdirectory contains a decoder and encoder for the
[HPACK](https://datatracker.ietf.org/doc/html/rfc7541) compression algorithm

## `http2/test_tools`

This subdirectory contains test utilities that facilitate writing unit tests for
code in the other subdirectories.

## Contributors

Some people who have contributed to this codebase include:

*   Alyssa Wilk
*   Antonio Vicente
*   Bence Beky
*   Biren Roy
*   Dan Zhang
*   Daniel Hollingshead
*   Dianna Hu
*   Hasan Khalil
*   James Synge
*   John Graettinger
*   Michaela LaVan
*   Mike Belshe
*   Mike Warres
*   Robbie Shade
*   Roberto Peon
*   Ryan Hamilton
*   Victor Vasiliev
*   Yang Song
