// Copyright 2026 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Live interop for draft-jholland-quic-multicast-08 on QUICHE's client side
// (lane cr-core, D3). Opens a real WebTransport-over-HTTP/3 session with
// QUICHE's client classes, offers the MCQUIC transport parameter and
// `wt-multicast: ?1`, hands the unicast MC frames to QuicMulticastClient
// (C2 codec, C4 control), opens the SSM socket the client asks for and feeds
// each datagram to QuicMulticastClient::OnChannelPacket (C5 ingress). It then
// judges: channel packets decrypted, and clock-stream bodies reassembled from
// channel frames equal to what the WebTransport stream delivered.
//
// Lab bed only. Logs frame kinds and public fields; never secrets or hashes.
//
// Usage (inside netns q-rx2):
//   quic_multicast_live_client --host=192.0.2.1 --port=4435 --path=/clock
//     --iface=192.0.2.3 --allowed-source=192.0.2.1 --min-packets=150
//     --min-streams=120 --timeout-s=60 --summary=/path/summary.json
//   --no-multicast  negative control: no TP, no header, no client.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "absl/base/casts.h"
#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_join.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "openssl/mem.h"
#include "quiche/quic/core/crypto/transport_parameters.h"
#include "quiche/quic/core/http/quic_spdy_client_session.h"
#include "quiche/quic/core/http/quic_spdy_client_stream.h"
#include "quiche/quic/core/http/quic_spdy_session.h"
#include "quiche/quic/core/http/web_transport_http3.h"
#include "quiche/quic/core/io/quic_default_event_loop.h"
#include "quiche/quic/core/io/quic_event_loop.h"
#include "quiche/quic/core/quic_config.h"
#include "quiche/quic/core/quic_data_reader.h"
#include "quiche/quic/core/quic_default_clock.h"
#include "quiche/quic/core/quic_default_connection_helper.h"
#include "quiche/quic/core/quic_error_codes.h"
#include "quiche/quic/core/quic_multicast_channel.h"
#include "quiche/quic/core/quic_multicast_client.h"
#include "quiche/quic/core/quic_multicast_frames.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_session.h"
#include "quiche/quic/core/quic_time.h"
#include "quiche/quic/core/quic_types.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_client_base.h"
#include "quiche/quic/tools/quic_client_default_network_helper.h"
#include "quiche/quic/tools/quic_event_loop_tools.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/web_transport/web_transport.h"

namespace quic {
namespace {

// First server-initiated uni stream above HTTP/3's control and QPACK streams.
constexpr QuicStreamId kFirstSharedStreamId = 15;
constexpr QuicStreamOffset kPrefixLength = 10;  // 40 54 + 8-byte session ID.

struct Options {
  std::string host = "192.0.2.1";
  uint16_t port = 4435;
  std::string sni = "localhost";
  std::string path = "/clock";
  std::string iface = "192.0.2.3";
  std::vector<QuicIpAddress> allowed_sources;
  uint64_t min_packets = 150;
  uint64_t min_streams = 120;
  int timeout_s = 60;
  uint32_t max_uni_streams = 1u << 30;  // As C7 does; small values test credit.
  std::string summary;
  bool multicast = true;
};

bool ParseOptions(int argc, char** argv, Options* o) {
  for (int i = 1; i < argc; ++i) {
    absl::string_view a = argv[i];
    if (a == "--no-multicast") {
      o->multicast = false;
      continue;
    }
    std::pair<absl::string_view, absl::string_view> kv =
        absl::StrSplit(a, absl::MaxSplits('=', 1));
    absl::string_view k = kv.first, v = kv.second;
    uint64_t n = 0;
    bool ok = true;
    if (k == "--host") {
      o->host = std::string(v);
    } else if (k == "--port") {
      ok = absl::SimpleAtoi(v, &n) && n > 0 && n < 65536;
      o->port = static_cast<uint16_t>(n);
    } else if (k == "--sni") {
      o->sni = std::string(v);
    } else if (k == "--path") {
      o->path = std::string(v);
    } else if (k == "--iface") {
      o->iface = std::string(v);
    } else if (k == "--allowed-source") {
      QuicIpAddress ip;
      ok = ip.FromString(std::string(v));
      o->allowed_sources.push_back(ip);
    } else if (k == "--min-packets") {
      ok = absl::SimpleAtoi(v, &o->min_packets);
    } else if (k == "--min-streams") {
      ok = absl::SimpleAtoi(v, &o->min_streams);
    } else if (k == "--timeout-s") {
      ok = absl::SimpleAtoi(v, &o->timeout_s);
    } else if (k == "--max-uni-streams") {
      ok = absl::SimpleAtoi(v, &o->max_uni_streams) && o->max_uni_streams > 0;
    } else if (k == "--summary") {
      o->summary = std::string(v);
    } else {
      ok = false;
    }
    if (!ok) {
      fprintf(stderr, "bad argument: %s\n", argv[i]);
      return false;
    }
  }
  return true;
}

std::string Hex(absl::string_view s) { return absl::BytesToHexString(s); }

class LiveTool;

// QuicSpdyClientSession with two taps: MC frames on the unicast connection
// (kinds and public fields), and every STREAM frame the session receives,
// tagged by whether QuicMulticastClient delivered it from a channel.
class LiveSession : public QuicSpdyClientSession {
 public:
  LiveSession(const QuicConfig& config,
              const ParsedQuicVersionVector& versions,
              QuicConnection* connection, const QuicServerId& server_id,
              QuicCryptoClientConfig* crypto_config, LiveTool* tool)
      : QuicSpdyClientSession(config, versions, connection, server_id,
                              crypto_config, QuicPriorityType::kWebTransport),
        tool_(tool) {}

  WebTransportHttp3VersionSet LocallySupportedWebTransportVersions()
      const override {
    return kDefaultSupportedWebTransportVersions;
  }
  HttpDatagramSupport LocalHttpDatagramSupport() override {
    return HttpDatagramSupport::kRfcAndDraft04;
  }

  void OnStreamFrame(const QuicStreamFrame& frame) override;
  QuicMulticastFrameStatus OnMulticastFrame(uint64_t frame_type,
                                            QuicDataReader* reader) override;

 private:
  LiveTool* tool_;
};

class LiveClient : public QuicClientBase {
 public:
  LiveClient(QuicSocketAddress server_address, const QuicServerId& server_id,
             const QuicConfig& config, QuicEventLoop* event_loop,
             LiveTool* tool)
      : QuicClientBase(
            server_id, {ParsedQuicVersion::RFCv1()}, config,
            new QuicDefaultConnectionHelper(),
            event_loop->CreateAlarmFactory().release(),
            std::make_unique<QuicClientDefaultNetworkHelper>(event_loop, this),
            std::make_unique<FakeProofVerifier>(), nullptr),
        tool_(tool) {
    set_server_address(server_address);
  }
  ~LiveClient() override { ResetSession(); }

  LiveSession* live_session() {
    return absl::down_cast<LiveSession*>(QuicClientBase::session());
  }

 protected:
  void InitializeSession() override {
    live_session()->Initialize();
    live_session()->CryptoConnect();
  }
  bool EarlyDataAccepted() override {
    return live_session()->EarlyDataAccepted();
  }
  bool ReceivedInchoateReject() override {
    return live_session()->ReceivedInchoateReject();
  }
  int GetNumSentClientHellosFromSession() override {
    return live_session()->GetNumSentClientHellos();
  }
  int GetNumReceivedServerConfigUpdatesFromSession() override {
    return live_session()->GetNumReceivedServerConfigUpdates();
  }
  bool HasActiveRequests() override {
    return live_session()->HasActiveRequestStreams();
  }
  std::unique_ptr<QuicSession> CreateQuicClientSession(
      const ParsedQuicVersionVector& versions,
      QuicConnection* connection) override;

 private:
  LiveTool* tool_;
};

// Everything the judge needs about one shared stream.
struct SharedStream {
  std::map<QuicStreamOffset, std::string> channel_segments;
  std::optional<QuicStreamOffset> channel_fin_end;
  uint64_t channel_frames = 0;
  uint64_t unicast_shared_bytes = 0;  // Unicast bytes at offset >= 10.
  std::optional<std::string> body;    // Complete WebTransport read.
};

class LiveTool : public QuicMulticastClient::Delegate,
                 public QuicSocketEventListener {
 public:
  explicit LiveTool(Options options)
      : options_(std::move(options)),
        clock_(QuicDefaultClock::Get()),
        event_loop_(GetDefaultEventLoop()->Create(QuicDefaultClock::Get())) {}

  int Run();

  // Session taps.
  void OnSessionStreamFrame(const QuicStreamFrame& frame);
  void OnUnicastMcFrame(uint64_t frame_type, absl::string_view body);
  int channel_depth_ = 0;  // > 0 while QuicMulticastClient may deliver.

  // WebTransport.
  void OnSessionReady();
  void OnSessionClosed(webtransport::SessionErrorCode code,
                       const std::string& message);
  void OnStreamComplete(QuicStreamId id, std::string body);
  void OnStreamReset(QuicStreamId id) {
    ++streams_reset_;
    Trace(absl::StrCat("wt stream ", id, " reset"));
  }
  void OnDatagram() { ++datagrams_; }

  bool multicast() const { return options_.multicast; }
  const std::vector<QuicIpAddress>& allowed_sources() const {
    return options_.allowed_sources;
  }

  // QuicMulticastClient::Delegate.
  bool JoinChannel(absl::string_view channel_id, const QuicIpAddress& source,
                   const QuicIpAddress& group, uint16_t port) override;
  void LeaveChannel(absl::string_view channel_id) override;

  // QuicSocketEventListener.
  void OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                     QuicSocketEventMask events) override;

 private:
  struct ChannelSocket {
    std::string channel_id;
    in_addr source;
  };

  double Elapsed() const {
    return (clock_->Now() - start_).ToMicroseconds() / 1e6;
  }
  void Trace(const std::string& line) {
    printf("t=%.3f %s\n", Elapsed(), line.c_str());
    fflush(stdout);
  }
  void Kind(const std::string& kind) {
    if (!kinds_.empty() && kinds_.back().first == kind) {
      ++kinds_.back().second;
    } else {
      kinds_.push_back({kind, 1});
    }
  }
  QuicMulticastClient* mc() {
    return client_ == nullptr || client_->live_session() == nullptr
               ? nullptr
               : client_->live_session()->multicast_client();
  }
  void SnapshotStats();
  uint64_t CoveredStreams(uint64_t* mismatched) const;
  std::string Summary();

  Options options_;
  const QuicClock* clock_;
  std::unique_ptr<QuicEventLoop> event_loop_;
  std::unique_ptr<LiveClient> client_;
  QuicSpdyClientStream* connect_stream_ = nullptr;
  QuicTime start_ = QuicTime::Zero();
  int64_t start_unix_us_ = 0;

  // Facts for the summary.
  std::string response_status_;
  std::vector<std::string> echo_values_;
  bool server_tp_ = false;
  std::string server_tp_hex_;
  bool session_ready_ = false;
  bool accepted_called_ = false;
  std::string session_closed_;
  std::vector<std::pair<std::string, uint64_t>> kinds_;
  std::map<std::string, std::string> first_detail_;
  std::string joined_channel_;
  std::string join_detail_;
  bool left_ = false;
  std::map<SocketFd, ChannelSocket> sockets_;
  uint64_t socket_packets_ = 0;
  uint64_t socket_bytes_ = 0;
  uint64_t wrong_source_ = 0;
  double first_channel_packet_t_ = -1;
  uint64_t channel_frames_ = 0;
  uint64_t channel_frame_bytes_ = 0;
  QuicStreamOffset channel_min_offset_ = ~QuicStreamOffset{0};
  uint64_t unicast_shared_bytes_ = 0;
  std::map<QuicStreamId, SharedStream> streams_;
  uint64_t streams_reset_ = 0;
  uint64_t datagrams_ = 0;
  std::optional<QuicMulticastChannel::Stats> stats_;
};

void LiveSession::OnStreamFrame(const QuicStreamFrame& frame) {
  tool_->OnSessionStreamFrame(frame);
  QuicSpdyClientSession::OnStreamFrame(frame);
}

QuicMulticastFrameStatus LiveSession::OnMulticastFrame(
    uint64_t frame_type, QuicDataReader* reader) {
  tool_->OnUnicastMcFrame(frame_type, reader->PeekRemainingPayload());
  // MC_KEY and MC_INTEGRITY can release buffered channel packets: frames
  // QuicMulticastClient hands the session in here came from the channel.
  ++tool_->channel_depth_;
  QuicMulticastFrameStatus status =
      QuicSpdyClientSession::OnMulticastFrame(frame_type, reader);
  --tool_->channel_depth_;
  return status;
}

std::unique_ptr<QuicSession> LiveClient::CreateQuicClientSession(
    const ParsedQuicVersionVector& versions, QuicConnection* connection) {
  auto session = std::make_unique<LiveSession>(
      *config(), versions, connection, server_id(), crypto_config(), tool_);
  if (tool_->multicast()) {
    // I3: //net creates the client right after the session, before the
    // handshake, so the config (and the server's TP 0xff3e808) is kept.
    session->set_multicast_client(std::make_unique<QuicMulticastClient>(
        session.get(), tool_, tool_->allowed_sources()));
  }
  return session;
}

class StreamReader : public webtransport::StreamVisitor {
 public:
  StreamReader(LiveTool* tool, webtransport::Stream* stream)
      : tool_(tool), stream_(stream) {}
  void OnCanRead() override {
    if (done_) {
      return;
    }
    webtransport::Stream::ReadResult r = stream_->Read(&body_);
    if (r.fin) {
      done_ = true;
      tool_->OnStreamComplete(stream_->GetStreamId(), std::move(body_));
    }
  }
  void OnCanWrite() override {}
  void OnResetStreamReceived(webtransport::StreamErrorCode) override {
    tool_->OnStreamReset(stream_->GetStreamId());
  }
  void OnStopSendingReceived(webtransport::StreamErrorCode) override {}
  void OnWriteSideInDataRecvdState() override {}

 private:
  LiveTool* tool_;
  webtransport::Stream* stream_;
  std::string body_;
  bool done_ = false;
};

class SessionVisitor : public webtransport::SessionVisitor {
 public:
  SessionVisitor(LiveTool* tool, webtransport::Session* session)
      : tool_(tool), session_(session) {}
  void OnSessionReady() override { tool_->OnSessionReady(); }
  void OnSessionClosed(webtransport::SessionErrorCode code,
                       const std::string& message) override {
    tool_->OnSessionClosed(code, message);
  }
  void OnIncomingBidirectionalStreamAvailable() override {}
  void OnIncomingUnidirectionalStreamAvailable() override {
    while (webtransport::Stream* s =
               session_->AcceptIncomingUnidirectionalStream()) {
      s->SetVisitor(std::make_unique<StreamReader>(tool_, s));
      s->visitor()->OnCanRead();
    }
  }
  void OnDatagramReceived(absl::string_view) override { tool_->OnDatagram(); }
  void OnCanCreateNewOutgoingBidirectionalStream() override {}
  void OnCanCreateNewOutgoingUnidirectionalStream() override {}

 private:
  LiveTool* tool_;
  webtransport::Session* session_;
};

void LiveTool::OnSessionStreamFrame(const QuicStreamFrame& frame) {
  const bool shared =
      (frame.stream_id & 0x3) == 0x3 && frame.stream_id >= kFirstSharedStreamId;
  if (channel_depth_ > 0) {
    ++channel_frames_;
    channel_frame_bytes_ += frame.data_length;
    if (frame.offset < channel_min_offset_) {
      channel_min_offset_ = frame.offset;
    }
    SharedStream& s = streams_[frame.stream_id];
    ++s.channel_frames;
    s.channel_segments[frame.offset] =
        std::string(frame.data_buffer, frame.data_length);
    if (frame.fin) {
      s.channel_fin_end = frame.offset + frame.data_length;
    }
    return;
  }
  if (shared && frame.offset + frame.data_length > kPrefixLength) {
    const QuicStreamOffset from =
        frame.offset > kPrefixLength ? frame.offset : kPrefixLength;
    const uint64_t n = frame.offset + frame.data_length - from;
    unicast_shared_bytes_ += n;
    streams_[frame.stream_id].unicast_shared_bytes += n;
  }
}

void LiveTool::OnUnicastMcFrame(uint64_t frame_type, absl::string_view body) {
  QuicDataReader r(body);
  std::string kind, detail;
  switch (frame_type) {
    case kMcAnnounceV4:
    case kMcAnnounceV6: {
      QuicMcAnnounce f;
      kind = "ANNOUNCE";
      if (DecodeMcAnnounce(frame_type, &r, &f)) {
        detail = absl::StrCat(
            "id=", Hex(f.channel_id), " S=", f.source.ToString(),
            " G=", f.group.ToString(), " port=", f.port, " hp=0x",
            absl::Hex(f.header_protection_algorithm), " aead=0x",
            absl::Hex(f.aead_algorithm), " hash=", f.integrity_hash_algorithm,
            " rate_kibps=", f.max_rate_kibps,
            " max_ack_delay_ms=", f.max_ack_delay_ms,
            " header_secret_len=", f.header_secret.size());
        OPENSSL_cleanse(f.header_secret.data(), f.header_secret.size());
      } else {
        detail = "DECODE FAILED";
      }
      break;
    }
    case kMcKey: {
      QuicMcKey f;
      kind = "KEY";
      if (DecodeMcKey(&r, &f)) {
        detail = absl::StrCat("id=", Hex(f.channel_id),
                              " key_sequence=", f.key_sequence,
                              " from_pn=", f.from_packet_number,
                              " secret_len=", f.secret.size());
        OPENSSL_cleanse(f.secret.data(), f.secret.size());
      } else {
        detail = "DECODE FAILED";
      }
      break;
    }
    case kMcJoin: {
      QuicMcJoin f;
      kind = "JOIN";
      detail = DecodeMcJoin(&r, &f)
                   ? absl::StrCat("id=", Hex(f.channel_id),
                                  " limits_seq=", f.limits_sequence,
                                  " state_seq=", f.state_sequence,
                                  " key_seq=", f.key_sequence)
                   : "DECODE FAILED";
      break;
    }
    case kMcLeave:
      kind = "LEAVE";
      break;
    case kMcRetire:
      kind = "RETIRE";
      break;
    case kMcIntegrity:
    case kMcIntegrityWithLength: {
      QuicMcIntegrity f;
      kind = frame_type == kMcIntegrity ? "INTEGRITY" : "INTEGRITY_WITH_LENGTH";
      detail = DecodeMcIntegrity(frame_type, kMcSha256HashLength, &r, &f)
                   ? absl::StrCat("id=", Hex(f.channel_id),
                                  " pn_start=", f.packet_number_start,
                                  " hashes=",
                                  f.packet_hashes.size() / kMcSha256HashLength)
                   : "DECODE FAILED";
      break;
    }
    default:
      kind = absl::StrCat("0x", absl::Hex(frame_type));
      break;
  }
  Kind("rx " + kind);
  if (!first_detail_.contains(kind)) {
    first_detail_[kind] = detail;
    Trace(absl::StrCat("rx ", kind, " ", detail));
  } else if (detail == "DECODE FAILED") {
    Trace(absl::StrCat("rx ", kind, " DECODE FAILED"));
  }
}

void LiveTool::OnSessionReady() {
  session_ready_ = true;
  const quiche::HttpHeaderBlock& h = connect_stream_->response_headers();
  if (auto it = h.find(":status"); it != h.end()) {
    response_status_ = std::string(it->second);
  }
  if (auto it = h.find("wt-multicast"); it != h.end()) {
    // Repeated fields are joined with NUL by the QPACK decoder.
    std::vector<std::string> values = absl::StrSplit(it->second, '\0');
    echo_values_ = std::move(values);
  }
  // Only a session with a multicast client keeps its config after the
  // handshake (C1 fix 957164a4); a stock session has none to read.
  if (mc() != nullptr) {
    const TransportParameters::ParameterMap& tps =
        client_->live_session()->config()->received_custom_transport_parameters();
    auto tp = tps.find(static_cast<TransportParameters::TransportParameterId>(
        kMcServerSupportId));
    server_tp_ = tp != tps.end();
    if (server_tp_) {
      server_tp_hex_ = Hex(tp->second);
    }
  }
  Trace(absl::StrCat("wt ready status=", response_status_, " wt-multicast=[",
                     absl::StrJoin(echo_values_, ","), "] server_tp_0xff3e808=",
                     server_tp_ ? server_tp_hex_ : "absent"));
  if (mc() != nullptr && echo_values_.size() == 1 && echo_values_[0] == "?1") {
    accepted_called_ = true;
    Kind("OnMulticastAccepted");
    mc()->OnMulticastAccepted();  // Sends MC_LIMITS when the TP is present.
  }
}

void LiveTool::OnSessionClosed(webtransport::SessionErrorCode code,
                               const std::string& message) {
  session_closed_ = absl::StrCat(code, " ", message);
  Trace("wt session closed: " + session_closed_);
}

void LiveTool::OnStreamComplete(QuicStreamId id, std::string body) {
  streams_[id].body = std::move(body);
}

bool LiveTool::JoinChannel(absl::string_view channel_id,
                           const QuicIpAddress& source,
                           const QuicIpAddress& group, uint16_t port) {
  Kind("delegate JoinChannel");
  join_detail_ = absl::StrCat("id=", Hex(channel_id), " S=", source.ToString(),
                              " G=", group.ToString(), " port=", port);
  QuicIpAddress iface;
  if (!source.IsIPv4() || !group.IsIPv4() || !iface.FromString(options_.iface)) {
    Trace("JoinChannel refused: IPv4 only: " + join_detail_);
    return false;
  }
  SocketFd fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  int one = 1, zero = 0, rcvbuf = 4 << 20;
  sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(port);
  bind_addr.sin_addr = group.GetIPv4();
  ip_mreq_source mreq = {};
  mreq.imr_multiaddr = group.GetIPv4();
  mreq.imr_interface = iface.GetIPv4();
  mreq.imr_sourceaddr = source.GetIPv4();
  const char* step = nullptr;
  if (fd < 0) {
    step = "socket";
  } else if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one))) {
    step = "SO_REUSEADDR";
  } else if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_ALL, &zero,
                        sizeof(zero))) {
    step = "IP_MULTICAST_ALL";
  } else if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf))) {
    step = "SO_RCVBUF";
  } else if (bind(fd, reinterpret_cast<sockaddr*>(&bind_addr),
                  sizeof(bind_addr))) {
    step = "bind";
  } else if (setsockopt(fd, IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP, &mreq,
                        sizeof(mreq))) {
    step = "IP_ADD_SOURCE_MEMBERSHIP";
  } else if (!event_loop_->RegisterSocket(fd, kSocketEventReadable, this)) {
    step = "RegisterSocket";
  }
  if (step != nullptr) {
    Trace(absl::StrCat("JoinChannel failed at ", step, ": ", strerror(errno)));
    if (fd >= 0) {
      close(fd);
    }
    return false;
  }
  sockets_[fd] = {std::string(channel_id), source.GetIPv4()};
  joined_channel_ = std::string(channel_id);
  Trace(absl::StrCat("delegate JoinChannel ", join_detail_, " iface=",
                     options_.iface, " fd=", fd));
  return true;
}

void LiveTool::LeaveChannel(absl::string_view channel_id) {
  Kind("delegate LeaveChannel");
  left_ = true;
  SnapshotStats();  // The client erases the channel after this call.
  for (auto it = sockets_.begin(); it != sockets_.end(); ++it) {
    if (it->second.channel_id == channel_id) {
      (void)event_loop_->UnregisterSocket(it->first);
      close(it->first);
      sockets_.erase(it);
      break;
    }
  }
  Trace("delegate LeaveChannel id=" + Hex(channel_id));
}

void LiveTool::OnSocketEvent(QuicEventLoop* event_loop, SocketFd fd,
                             QuicSocketEventMask events) {
  if (!(events & kSocketEventReadable)) {
    return;
  }
  char buf[2048];
  bool more = true;
  for (int i = 0; i < 64; ++i) {
    auto it = sockets_.find(fd);
    if (it == sockets_.end() || !client_->connected()) {
      return;  // Left or closed re-entrantly.
    }
    const std::string channel_id = it->second.channel_id;
    const in_addr source = it->second.source;
    sockaddr_in from = {};
    socklen_t from_len = sizeof(from);
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0,
                         reinterpret_cast<sockaddr*>(&from), &from_len);
    if (n < 0) {
      more = false;
      if (errno != EAGAIN && errno != EWOULDBLOCK) {
        Trace(absl::StrCat("recvfrom: ", strerror(errno)));
      }
      break;
    }
    if (from.sin_addr.s_addr != source.s_addr) {
      ++wrong_source_;
      continue;
    }
    ++socket_packets_;
    socket_bytes_ += n;
    if (first_channel_packet_t_ < 0) {
      first_channel_packet_t_ = Elapsed();
      Trace(absl::StrCat("first channel datagram, ", n, " B"));
    }
    ++channel_depth_;
    mc()->OnChannelPacket(channel_id, absl::string_view(buf, n),
                          ECN_NOT_ECT, clock_->Now());
    --channel_depth_;
  }
  if (!sockets_.contains(fd)) {
    return;
  }
  if (more) {
    (void)event_loop->ArtificiallyNotifyEvent(fd, kSocketEventReadable);
  } else if (!event_loop->SupportsEdgeTriggered()) {
    (void)event_loop->RearmSocket(fd, kSocketEventReadable);
  }
}

void LiveTool::SnapshotStats() {
  if (mc() == nullptr || joined_channel_.empty()) {
    return;
  }
  if (const QuicMulticastChannel::Stats* s = mc()->channel_stats(joined_channel_)) {
    stats_ = *s;
  }
}

// Streams whose body, as the WebTransport stream delivered it, equals the
// bytes the channel delivered from offset 10 to FIN.
uint64_t LiveTool::CoveredStreams(uint64_t* mismatched) const {
  uint64_t covered = 0;
  *mismatched = 0;
  for (const auto& [id, s] : streams_) {
    if (!s.body.has_value() || s.channel_segments.empty()) {
      continue;
    }
    std::string channel_body;
    QuicStreamOffset next = kPrefixLength;
    for (const auto& [offset, data] : s.channel_segments) {
      if (offset > next) {
        break;  // A gap: the channel alone did not cover this stream.
      }
      if (offset + data.size() > next) {
        channel_body.append(data, next - offset);
        next = offset + data.size();
      }
    }
    if (s.channel_fin_end.has_value() && *s.channel_fin_end == next &&
        channel_body == *s.body) {
      ++covered;
    } else if (s.channel_fin_end.has_value() && *s.channel_fin_end == next) {
      ++*mismatched;
    }
  }
  return covered;
}

std::string LiveTool::Summary() {
  uint64_t mismatched = 0;
  const uint64_t covered = CoveredStreams(&mismatched);
  uint64_t complete = 0, parsed = 0, clock_sane = 0, seq_steps = 0,
           seq_breaks = 0, channel_only_candidates = 0;
  std::optional<QuicStreamId> first_id, last_id, prev_id;
  std::optional<uint64_t> prev_seq;
  const int64_t now_ms = QuicDefaultClock::Get()->WallNow().ToUNIXMicroseconds() / 1000;
  std::string sample_body;
  for (const auto& [id, s] : streams_) {
    if (!s.body.has_value()) {
      continue;
    }
    ++complete;
    if (!first_id.has_value()) {
      first_id = id;
      sample_body = *s.body;
    }
    last_id = id;
    std::vector<absl::string_view> parts = absl::StrSplit(*s.body, ' ');
    int64_t ms = 0;
    uint64_t seq = 0;
    if (parts.size() == 2 && absl::SimpleAtoi(parts[0], &ms) &&
        absl::SimpleAtoi(parts[1], &seq)) {
      ++parsed;
      if (ms <= now_ms && now_ms - ms < 120'000) {
        ++clock_sane;
      }
      if (prev_seq.has_value() && prev_id.has_value() && *prev_id + 4 == id) {
        (seq == *prev_seq + 1 ? seq_steps : seq_breaks)++;
      }
      prev_seq = seq;
      prev_id = id;
    }
    if (s.unicast_shared_bytes == 0 && s.channel_frames > 0) {
      ++channel_only_candidates;
    }
  }
  SnapshotStats();
  std::vector<std::string> kinds;
  for (const auto& [k, n] : kinds_) {
    kinds.push_back(n == 1 ? k : absl::StrCat(k, "*", n));
  }
  const bool echo_ok = echo_values_.size() == 1 && echo_values_[0] == "?1";
  const bool pass =
      options_.multicast && echo_ok && server_tp_ && !joined_channel_.empty() &&
      stats_.has_value() && stats_->delivered_packets >= 100 &&
      stats_->integrity_mismatches == 0 && covered >= 100 && mismatched == 0;
  auto q = [](absl::string_view s) { return absl::StrCat("\"", s, "\""); };
  std::string stats_json = "null";
  if (stats_.has_value()) {
    stats_json = absl::StrCat(
        "{\"delivered_packets\":", stats_->delivered_packets,
        ",\"integrity_mismatches\":", stats_->integrity_mismatches,
        ",\"duplicates\":", stats_->duplicates,
        ",\"undecodable\":", stats_->undecodable,
        ",\"guard_drops\":", stats_->guard_drops,
        ",\"expired\":", stats_->expired, ",\"evicted\":", stats_->evicted,
        "}");
  }
  std::vector<std::string> details;
  for (const auto& [k, d] : first_detail_) {
    details.push_back(absl::StrCat(q(k), ":", q(d)));
  }
  return absl::StrCat(
      "{\"pass\":", pass ? "true" : "false",
      ",\"multicast\":", options_.multicast ? "true" : "false",
      ",\"start_unix_us\":", start_unix_us_, ",\"elapsed_s\":", Elapsed(),
      ",\"server\":", q(absl::StrCat(options_.host, ":", options_.port)),
      ",\"session_ready\":", session_ready_ ? "true" : "false",
      ",\"status\":", q(response_status_), ",\"echo\":[",
      absl::StrJoin(echo_values_, ",",
                    [&](std::string* out, const std::string& v) {
                      absl::StrAppend(out, q(v));
                    }),
      "],\"server_tp_0xff3e808\":", server_tp_ ? q(server_tp_hex_) : "null",
      ",\"on_multicast_accepted\":", accepted_called_ ? "true" : "false",
      ",\"mc\":", q(absl::StrJoin(kinds, ", ")), ",\"first\":{",
      absl::StrJoin(details, ","), "},\"join\":", q(join_detail_),
      ",\"left\":", left_ ? "true" : "false",
      ",\"socket_packets\":", socket_packets_,
      ",\"socket_bytes\":", socket_bytes_, ",\"wrong_source\":", wrong_source_,
      ",\"first_channel_packet_t\":", first_channel_packet_t_,
      ",\"channel_stats\":", stats_json,
      ",\"channel_frames_to_session\":", channel_frames_,
      ",\"channel_frame_bytes\":", channel_frame_bytes_,
      ",\"channel_min_offset\":",
      channel_frames_ ? absl::StrCat(channel_min_offset_) : "null",
      ",\"unicast_shared_bytes\":", unicast_shared_bytes_,
      ",\"streams_complete\":", complete, ",\"bodies_parsed\":", parsed,
      ",\"bodies_clock_sane\":", clock_sane, ",\"seq_steps\":", seq_steps,
      ",\"seq_breaks\":", seq_breaks,
      ",\"streams_covered_by_channel\":", covered,
      ",\"streams_channel_mismatch\":", mismatched,
      ",\"streams_no_unicast_body_bytes\":", channel_only_candidates,
      ",\"streams_reset\":", streams_reset_, ",\"datagrams\":", datagrams_,
      ",\"first_stream\":", first_id.has_value() ? absl::StrCat(*first_id) : "null",
      ",\"last_stream\":", last_id.has_value() ? absl::StrCat(*last_id) : "null",
      ",\"sample_body\":", q(sample_body),
      ",\"session_closed\":", q(session_closed_), "}");
}

int LiveTool::Run() {
  start_ = clock_->Now();
  start_unix_us_ = QuicDefaultClock::Get()->WallNow().ToUNIXMicroseconds();
  QuicIpAddress host;
  if (!host.FromString(options_.host)) {
    fprintf(stderr, "bad --host\n");
    return 2;
  }
  QuicConfig config;
  config.SetMaxUnidirectionalStreamsToSend(options_.max_uni_streams);
  config.SetInitialSessionFlowControlWindowToSend(16u << 20);
  config.SetInitialStreamFlowControlWindowToSend(1u << 20);
  if (options_.multicast) {
    config.custom_transport_parameters_to_send()
        [static_cast<TransportParameters::TransportParameterId>(
            kMcClientParamsId)] =
        EncodeMcClientParams(QuicMcDefaultClientParams());
  }
  client_ = std::make_unique<LiveClient>(
      QuicSocketAddress(host, options_.port),
      QuicServerId(options_.sni, options_.port), config, event_loop_.get(),
      this);
  if (!client_->Initialize() || !client_->Connect()) {
    Trace("QUIC connect failed");
    printf("SUMMARY %s\n", Summary().c_str());
    return 1;
  }
  Trace("QUIC handshake done");
  LiveSession* session = client_->live_session();
  if (!ProcessEventsUntil(event_loop_.get(),
                          [&] { return session->settings_received(); }) ||
      !session->SupportsWebTransport()) {
    Trace("no HTTP/3 SETTINGS with WebTransport");
    printf("SUMMARY %s\n", Summary().c_str());
    return 1;
  }
  connect_stream_ = absl::down_cast<QuicSpdyClientStream*>(
      session->CreateOutgoingBidirectionalStream());
  quiche::HttpHeaderBlock headers;
  headers[":method"] = "CONNECT";
  headers[":protocol"] = "webtransport";
  headers[":scheme"] = "https";
  headers[":authority"] = absl::StrCat(options_.sni, ":", options_.port);
  headers[":path"] = options_.path;
  if (options_.multicast) {
    headers["wt-multicast"] = "?1";
  }
  connect_stream_->SendRequest(std::move(headers), "", false);
  WebTransportHttp3* wt = connect_stream_->web_transport();
  if (wt == nullptr) {
    Trace("no WebTransport session on the CONNECT stream");
    return 1;
  }
  wt->SetVisitor(std::make_unique<SessionVisitor>(this, wt));
  Trace(absl::StrCat("CONNECT sent on stream ", connect_stream_->id(),
                     options_.multicast ? " with wt-multicast: ?1 and TP 0xff3e800="
                                        : " (no multicast)",
                     options_.multicast
                         ? Hex(EncodeMcClientParams(QuicMcDefaultClientParams()))
                         : ""));

  const QuicTime deadline =
      start_ + QuicTime::Delta::FromSeconds(options_.timeout_s);
  QuicTime next_check = clock_->Now();
  while (clock_->Now() < deadline && client_->connected()) {
    event_loop_->RunEventLoopOnce(QuicTime::Delta::FromMilliseconds(50));
    if (clock_->Now() < next_check) {
      continue;
    }
    next_check = clock_->Now() + QuicTime::Delta::FromSeconds(1);
    SnapshotStats();
    uint64_t mismatched = 0;
    const uint64_t covered = CoveredStreams(&mismatched);
    if (stats_.has_value() && stats_->delivered_packets >= options_.min_packets &&
        covered >= options_.min_streams) {
      Trace("targets met");
      break;
    }
  }
  if (!client_->connected()) {
    Trace("connection closed: " +
          std::string(QuicErrorCodeToString(
              client_->live_session()->error())));
  }
  const std::string summary = Summary();
  printf("SUMMARY %s\n", summary.c_str());
  if (!options_.summary.empty()) {
    if (FILE* f = fopen(options_.summary.c_str(), "w")) {
      fprintf(f, "%s\n", summary.c_str());
      fclose(f);
    }
  }
  if (client_->connected()) {
    wt->CloseSession(0, "done");
    client_->Disconnect();
  }
  return summary.rfind("{\"pass\":true", 0) == 0 ? 0 : 3;
}

}  // namespace
}  // namespace quic

int main(int argc, char** argv) {
  quic::Options options;
  if (!quic::ParseOptions(argc, argv, &options)) {
    return 2;
  }
  if (options.allowed_sources.empty()) {
    quic::QuicIpAddress s;
    (void)s.FromString(options.host);
    options.allowed_sources.push_back(s);
  }
  quic::LiveTool tool(std::move(options));
  return tool.Run();
}
