#include "noescape/network/panel_client.hpp"
#include "noescape/network/crypto_util.hpp"
#include <sstream>
#include <ctime>
#include <cstring>
#include <chrono>
#include <cctype>
#include <cstdlib>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
using socket_t = SOCKET;
#define IS_VALID_SOCKET(s) ((s) != INVALID_SOCKET)
#define CLOSE_SOCKET(s) closesocket(s)
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <poll.h>
#include <fcntl.h>
using socket_t = int;
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#endif

namespace noescape::network {

namespace {

void EnsureNetworkInit() {
#if defined(_WIN32)
    static bool initialized = false;
    if (!initialized) {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
        initialized = true;
    }
#endif
}

bool ConnectWithTimeout(socket_t sock, const struct sockaddr* addr, socklen_t addrlen, uint32_t timeout_ms) {
#if defined(_WIN32)
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    int res = connect(sock, addr, static_cast<int>(addrlen));
    if (res == 0) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        return true;
    }
    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        return false;
    }
    fd_set writeSet, errSet;
    FD_ZERO(&writeSet);
    FD_ZERO(&errSet);
    FD_SET(sock, &writeSet);
    FD_SET(sock, &errSet);
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (select(0, nullptr, &writeSet, &errSet, &tv) > 0 && FD_ISSET(sock, &writeSet) && !FD_ISSET(sock, &errSet)) {
        mode = 0;
        ioctlsocket(sock, FIONBIO, &mode);
        return true;
    }
    return false;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    int res = connect(sock, addr, addrlen);
    if (res == 0) {
        fcntl(sock, F_SETFL, flags);
        return true;
    }
    if (errno != EINPROGRESS) {
        return false;
    }
    struct pollfd pfd{};
    pfd.fd = sock;
    pfd.events = POLLOUT;
    int pollRes = poll(&pfd, 1, static_cast<int>(timeout_ms));
    if (pollRes > 0 && (pfd.revents & POLLOUT) && !(pfd.revents & (POLLERR | POLLHUP))) {
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) == 0 && err == 0) {
            fcntl(sock, F_SETFL, flags);
            return true;
        }
    }
    return false;
#endif
}

std::string JsonEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size() + 8);
    for (unsigned char c : in) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += static_cast<char>(c);
        }
    }
    return out;
}

} // namespace

PanelClient::PanelClient(std::string base_url, std::string secret_key)
    : base_url_(std::move(base_url)),
      secret_key_(std::move(secret_key)),
      hwid_(CryptoUtil::GetMachineHWID()) {
    EnsureNetworkInit();
}

PanelClient::~PanelClient() = default;

PanelClient::ParsedUrl PanelClient::ParseUrl(const std::string& url) {
    ParsedUrl res;
    res.port = 80;
    res.path = "/";

    std::string s = url;
    size_t protoPos = s.find("://");
    if (protoPos != std::string::npos) {
        std::string scheme = s.substr(0, protoPos);
        for (auto& c : scheme) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (scheme == "https") { res.secure = true; res.port = 443; }
        else if (scheme != "http") res.valid = false;
        s = s.substr(protoPos + 3);
    }

    size_t slashPos = s.find('/');
    std::string hostPort;
    if (slashPos != std::string::npos) {
        hostPort = s.substr(0, slashPos);
        res.path = s.substr(slashPos);
    } else {
        hostPort = s;
    }

    size_t colonPos = hostPort.find(':');
    if (colonPos != std::string::npos) {
        res.host = hostPort.substr(0, colonPos);
        long port = std::strtol(hostPort.substr(colonPos + 1).c_str(), nullptr, 10);
        if (port <= 0 || port > 65535) res.valid = false;
        else res.port = static_cast<uint16_t>(port);
    } else {
        res.host = hostPort;
    }
    if (res.host.empty()) res.valid = false;

    return res;
}

std::string PanelClient::HttpPost(const ParsedUrl& target, const std::string& body, uint32_t timeout_ms) {
    EnsureNetworkInit();
    // Never silently downgrade https:// to cleartext HTTP; TLS is not implemented.
    if (!target.valid || target.secure) return "";
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms * 2);

    struct addrinfo hints{}, *servinfo = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(target.port);
    if (getaddrinfo(target.host.c_str(), portStr.c_str(), &hints, &servinfo) != 0 || !servinfo) {
        return "";
    }

    socket_t sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (!IS_VALID_SOCKET(sock)) {
        freeaddrinfo(servinfo);
        return "";
    }

#if defined(_WIN32)
    DWORD tv = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (!ConnectWithTimeout(sock, servinfo->ai_addr, static_cast<socklen_t>(servinfo->ai_addrlen), timeout_ms)) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(servinfo);
        return "";
    }
    freeaddrinfo(servinfo);

    std::ostringstream req;
    req << "POST " << target.path << " HTTP/1.1\r\n"
        << "Host: " << target.host << ((target.port == 80) ? std::string() : ":" + std::to_string(target.port)) << "\r\n"
        << "Content-Type: application/json\r\n"
        << "Content-Length: " << body.length() << "\r\n"
        << "Connection: close\r\n\r\n"
        << body;

    std::string reqStr = req.str();
    if (send(sock, reqStr.c_str(), static_cast<int>(reqStr.length()), 0) <= 0) {
        CLOSE_SOCKET(sock);
        return "";
    }

    std::string response;
    char buf[1024];
    int bytes = 0;
    // Bounded in total time and size: a slow-drip or endless response must not stall the caller
    constexpr size_t kMaxResponse = 64 * 1024;
    while (response.size() < kMaxResponse && std::chrono::steady_clock::now() < deadline &&
           (bytes = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        response.append(buf, bytes);
    }

    CLOSE_SOCKET(sock);
    return response;
}

std::string PanelClient::HttpGet(const ParsedUrl& target, uint32_t timeout_ms) {
    EnsureNetworkInit();
    // Never silently downgrade https:// to cleartext HTTP; TLS is not implemented.
    if (!target.valid || target.secure) return "";
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms * 2);

    struct addrinfo hints{}, *servinfo = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    std::string portStr = std::to_string(target.port);
    if (getaddrinfo(target.host.c_str(), portStr.c_str(), &hints, &servinfo) != 0 || !servinfo) {
        return "";
    }

    socket_t sock = socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
    if (!IS_VALID_SOCKET(sock)) {
        freeaddrinfo(servinfo);
        return "";
    }

#if defined(_WIN32)
    DWORD tv = timeout_ms;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif

    if (!ConnectWithTimeout(sock, servinfo->ai_addr, static_cast<socklen_t>(servinfo->ai_addrlen), timeout_ms)) {
        CLOSE_SOCKET(sock);
        freeaddrinfo(servinfo);
        return "";
    }
    freeaddrinfo(servinfo);

    std::ostringstream req;
    req << "GET " << target.path << " HTTP/1.1\r\n"
        << "Host: " << target.host << ((target.port == 80) ? std::string() : ":" + std::to_string(target.port)) << "\r\n"
        << "Connection: close\r\n\r\n";

    std::string reqStr = req.str();
    if (send(sock, reqStr.c_str(), static_cast<int>(reqStr.length()), 0) <= 0) {
        CLOSE_SOCKET(sock);
        return "";
    }

    std::string response;
    char buf[1024];
    int bytes = 0;
    // Bounded in total time and size: a slow-drip or endless response must not stall the caller
    constexpr size_t kMaxResponse = 64 * 1024;
    while (response.size() < kMaxResponse && std::chrono::steady_clock::now() < deadline &&
           (bytes = recv(sock, buf, sizeof(buf) - 1, 0)) > 0) {
        response.append(buf, bytes);
    }

    CLOSE_SOCKET(sock);
    return response;
}

HeartbeatPacket PanelClient::ConstructHeartbeat(uint32_t current_threat_score, const std::string& status) {
    HeartbeatPacket pkt;
    pkt.hwid = hwid_;
    pkt.timestamp = static_cast<uint64_t>(std::time(nullptr));
    pkt.threat_score = current_threat_score;
    pkt.events_count = 0;
    pkt.status = status;

    std::ostringstream payload;
    payload << pkt.hwid << ":" << pkt.timestamp << ":" << pkt.threat_score << ":" << pkt.status;
    pkt.hmac_signature = CryptoUtil::HmacSha256(secret_key_, payload.str());

    return pkt;
}

bool PanelClient::SendHeartbeat(uint32_t current_threat_score, const std::string& status) {
    auto pkt = ConstructHeartbeat(current_threat_score, status);

    std::ostringstream json;
    json << "{"
         << "\"hwid\":\"" << pkt.hwid << "\","
         << "\"timestamp\":" << pkt.timestamp << ","
         << "\"threat_score\":" << pkt.threat_score << ","
         << "\"status\":\"" << pkt.status << "\","
         << "\"signature\":\"" << pkt.hmac_signature << "\""
         << "}";

    ParsedUrl parsed = ParseUrl(base_url_ + "/heartbeat");
    std::string resp = HttpPost(parsed, json.str(), 1500);
    return resp.rfind("HTTP/1.1 2", 0) == 0 || resp.rfind("HTTP/1.0 2", 0) == 0;
}

bool PanelClient::SendBanReport(const core::DetectionEvent& event, uint32_t current_threat_score) {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::ostringstream payload;
    payload << hwid_ << ":" << now << ":" << core::DetectionEvent::TypeToString(event.type)
            << ":" << event.details;
    std::string sig = CryptoUtil::HmacSha256(secret_key_, payload.str());

    std::ostringstream json;
    json << "{"
         << "\"hwid\":\"" << hwid_ << "\","
         << "\"timestamp\":" << now << ","
         << "\"threat_score\":" << current_threat_score << ","
         << "\"type\":\"" << core::DetectionEvent::TypeToString(event.type) << "\","
         << "\"severity\":\"" << core::DetectionEvent::SeverityToString(event.severity) << "\","
         << "\"component\":\"" << JsonEscape(event.component) << "\","
         << "\"details\":\"" << JsonEscape(event.details) << "\","
         << "\"signature\":\"" << sig << "\""
         << "}";

    ParsedUrl parsed = ParseUrl(base_url_ + "/alert");
    std::string resp = HttpPost(parsed, json.str(), 2000);
    return resp.rfind("HTTP/1.1 2", 0) == 0 || resp.rfind("HTTP/1.0 2", 0) == 0;
}

BanCheckResult PanelClient::QueryBanStatus() {
    BanCheckResult result;
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::string path = base_url_ + "/check?hwid=" + hwid_ + "&nonce=" + std::to_string(now);
    ParsedUrl parsed = ParseUrl(path);
    std::string resp = HttpGet(parsed, 1500);

    if (resp.empty()) {
        result.status = BanCheckStatus::NETWORK_ERROR;
        result.reason = "Backend server unreachable or timeout";
        return result;
    }

    if (resp.rfind("HTTP/1.1 2", 0) != 0 && resp.rfind("HTTP/1.0 2", 0) != 0) {
        result.status = BanCheckStatus::NETWORK_ERROR;
        result.reason = "Backend returned a non-2xx status";
        return result;
    }

    // Signature is mandatory and bound to hwid + status + our nonce (anti-replay, anti-strip)
    bool isBanned = (resp.find("\"banned\":true") != std::string::npos);
    bool isClean = (resp.find("\"banned\":false") != std::string::npos);
    size_t sigPos = resp.find("\"signature\":\"");
    size_t sigEnd = (sigPos == std::string::npos) ? std::string::npos : resp.find('"', sigPos + 13);
    if (sigEnd == std::string::npos || isBanned == isClean) {
        result.status = BanCheckStatus::SIGNATURE_INVALID;
        result.reason = "Missing signature or ambiguous panel response";
        return result;
    }
    std::string serverSig = resp.substr(sigPos + 13, sigEnd - (sigPos + 13));
    std::string expectedSig = CryptoUtil::HmacSha256(
        secret_key_, hwid_ + ":" + (isBanned ? "1" : "0") + ":" + std::to_string(now));
    if (!CryptoUtil::ConstantTimeEquals(serverSig, expectedSig)) {
        result.status = BanCheckStatus::SIGNATURE_INVALID;
        result.reason = "Panel response HMAC signature validation failed (Tampered or MitM)";
        return result;
    }

    if (resp.find("\"banned\":true") != std::string::npos ||
        resp.find("banned:1") != std::string::npos) {
        result.status = BanCheckStatus::BANNED;
        result.reason = "Global Hardware ID Blacklist Match";
        return result;
    }

    if (resp.find("\"banned\":false") != std::string::npos ||
        resp.find("banned:0") != std::string::npos) {
        result.status = BanCheckStatus::CLEAN;
        result.reason = "Hardware ID is clean";
        return result;
    }

    // Response arrived but did not match expected JSON schema
    result.status = BanCheckStatus::NETWORK_ERROR;
    result.reason = "Malformed response payload from backend";
    return result;
}

bool PanelClient::CheckBanStatus(bool& out_is_banned, std::string& out_reason) {
    auto res = QueryBanStatus();
    if (res.status == BanCheckStatus::BANNED) {
        out_is_banned = true;
        out_reason = res.reason;
        return true;
    } else if (res.status == BanCheckStatus::CLEAN) {
        out_is_banned = false;
        out_reason = res.reason;
        return true;
    } else {
        out_is_banned = false;
        out_reason = res.reason;
        return false;
    }
}

} // namespace noescape::network
