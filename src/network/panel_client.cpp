#include "noescape/network/panel_client.hpp"
#include "noescape/network/crypto_util.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <mutex>
#include <random>
#include <sstream>
#include <vector>

#if defined(_WIN32)
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <winhttp.h>
#include <wincrypt.h>
#if defined(_MSC_VER)
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")
#endif
using socket_t = SOCKET;
#define INVALID_SOCK INVALID_SOCKET
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
#include <cerrno>
#include <csignal>
using socket_t = int;
#define INVALID_SOCK (-1)
#define IS_VALID_SOCKET(s) ((s) >= 0)
#define CLOSE_SOCKET(s) close(s)
#if defined(NOESCAPE_HAS_OPENSSL)
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#endif
#endif

namespace noescape::network {

namespace {

using Clock = std::chrono::steady_clock;
constexpr size_t kMaxResponse = 64 * 1024;

void EnsureNetworkInit() {
#if defined(_WIN32)
    static std::once_flag once;
    std::call_once(once, []() {
        WSADATA wsa;
        WSAStartup(MAKEWORD(2, 2), &wsa);
    });
#endif
}

int RemainingMs(Clock::time_point deadline) {
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return ms > 0 ? static_cast<int>(ms) : 0;
}

void SetSocketTimeouts(socket_t sock, int ms) {
    if (ms <= 0) ms = 1;
#if defined(_WIN32)
    DWORD tv = static_cast<DWORD>(ms);
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
    struct timeval tv{};
    tv.tv_sec = ms / 1000;
    tv.tv_usec = (ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

bool ConnectWithTimeout(socket_t sock, const struct sockaddr* addr, socklen_t addrlen, int timeout_ms) {
#if defined(_WIN32)
    u_long mode = 1;
    ioctlsocket(sock, FIONBIO, &mode);
    int res = connect(sock, addr, static_cast<int>(addrlen));
    if (res != 0 && WSAGetLastError() != WSAEWOULDBLOCK) return false;
    if (res != 0) {
        fd_set writeSet, errSet;
        FD_ZERO(&writeSet);
        FD_ZERO(&errSet);
        FD_SET(sock, &writeSet);
        FD_SET(sock, &errSet);
        timeval tv{};
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        if (select(0, nullptr, &writeSet, &errSet, &tv) <= 0 || !FD_ISSET(sock, &writeSet) || FD_ISSET(sock, &errSet)) {
            return false;
        }
    }
    mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
    return true;
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    int res = connect(sock, addr, addrlen);
    if (res != 0 && errno != EINPROGRESS) return false;
    if (res != 0) {
        struct pollfd pfd{};
        pfd.fd = sock;
        pfd.events = POLLOUT;
        int pollRes = poll(&pfd, 1, timeout_ms);
        if (pollRes <= 0 || !(pfd.revents & POLLOUT) || (pfd.revents & (POLLERR | POLLHUP))) return false;
        int err = 0;
        socklen_t len = sizeof(err);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) return false;
    }
    fcntl(sock, F_SETFL, flags);
    return true;
#endif
}

// Resolves and connects (IPv4 and IPv6). getaddrinfo itself cannot be cancelled, which is one
// reason the engine runs all panel I/O on its own thread.
socket_t ConnectTcp(const std::string& host, uint16_t port, Clock::time_point deadline) {
    struct addrinfo hints{}, *servinfo = nullptr;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    std::string portStr = std::to_string(port);
    if (getaddrinfo(host.c_str(), portStr.c_str(), &hints, &servinfo) != 0 || !servinfo) {
        return INVALID_SOCK;
    }
    socket_t result = INVALID_SOCK;
    for (auto* ai = servinfo; ai && RemainingMs(deadline) > 0; ai = ai->ai_next) {
        socket_t sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (!IS_VALID_SOCKET(sock)) continue;
        if (ConnectWithTimeout(sock, ai->ai_addr, static_cast<socklen_t>(ai->ai_addrlen), RemainingMs(deadline))) {
            result = sock;
            break;
        }
        CLOSE_SOCKET(sock);
    }
    freeaddrinfo(servinfo);
    return result;
}

int SendFlags() {
#if defined(MSG_NOSIGNAL)
    return MSG_NOSIGNAL; // a peer reset must not SIGPIPE-kill the host game
#else
    return 0;
#endif
}

std::string BuildRequest(const PanelClient::ParsedUrl& t, const char* method, const std::string& body,
                         const std::string& signature) {
    std::ostringstream req;
    req << method << " " << t.path << " HTTP/1.1\r\n"
        << "Host: " << t.host;
    if (!((t.secure && t.port == 443) || (!t.secure && t.port == 80))) req << ":" << t.port;
    req << "\r\n"
        << "User-Agent: NoEscapeAC/7\r\n"
        << "Connection: close\r\n";
    if (!signature.empty()) req << "X-NoEscape-Signature: " << signature << "\r\n";
    if (!body.empty() || std::strcmp(method, "POST") == 0) {
        req << "Content-Type: application/json\r\n"
            << "Content-Length: " << body.size() << "\r\n";
    }
    req << "\r\n" << body;
    return req.str();
}

PanelClient::HttpResult ParseHttpResponse(const std::string& raw) {
    PanelClient::HttpResult r;
    if (raw.rfind("HTTP/1.", 0) != 0 || raw.size() < 12) return r;
    size_t hdrEnd = raw.find("\r\n\r\n");
    if (hdrEnd == std::string::npos) return r;
    r.status = std::atoi(raw.c_str() + 9);
    std::string headers = raw.substr(0, hdrEnd);
    std::string body = raw.substr(hdrEnd + 4);
    std::transform(headers.begin(), headers.end(), headers.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (headers.find("transfer-encoding: chunked") != std::string::npos) {
        std::string decoded;
        size_t p = 0;
        while (p < body.size()) {
            size_t eol = body.find("\r\n", p);
            if (eol == std::string::npos) break;
            unsigned long n = std::strtoul(body.substr(p, eol - p).c_str(), nullptr, 16);
            if (n == 0 || n > kMaxResponse || eol + 2 + n > body.size()) break;
            decoded.append(body, eol + 2, n);
            p = eol + 2 + n + 2;
        }
        body = decoded;
    }
    r.body = body;
    return r;
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
                if (c < 0x20) { char b[8]; std::snprintf(b, sizeof(b), "\\u%04x", c); out += b; }
                else out += static_cast<char>(c);
        }
    }
    return out;
}

std::string JsonString(const std::string& body, const std::string& key, size_t from = 0) {
    std::string pat = "\"" + key + "\":\"";
    size_t p = body.find(pat, from);
    if (p == std::string::npos) return "";
    p += pat.size();
    size_t e = body.find('"', p);
    return e == std::string::npos ? std::string() : body.substr(p, e - p);
}

bool JsonNumber(const std::string& body, const std::string& key, size_t from, uint64_t& out) {
    std::string pat = "\"" + key + "\":";
    size_t p = body.find(pat, from);
    if (p == std::string::npos) return false;
    p += pat.size();
    if (p >= body.size() || !std::isdigit(static_cast<unsigned char>(body[p]))) return false;
    out = std::strtoull(body.c_str() + p, nullptr, 10);
    return true;
}

bool IsToken(const std::string& v, size_t maxLen) {
    if (v.empty() || v.size() > maxLen) return false;
    for (char c : v) {
        if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_')) return false;
    }
    return true;
}

std::string NormalizePin(const std::string& pin) {
    std::string out;
    for (char c : pin) {
        if (std::isxdigit(static_cast<unsigned char>(c))) {
            out += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
    }
    return out.size() == 64 ? out : std::string();
}

#if !defined(_WIN32) && defined(NOESCAPE_HAS_OPENSSL)
SSL_CTX* ClientContext() {
    static SSL_CTX* ctx = []() -> SSL_CTX* {
        SSL_CTX* c = SSL_CTX_new(TLS_client_method());
        if (!c) return nullptr;
        SSL_CTX_set_min_proto_version(c, TLS1_2_VERSION);
        SSL_CTX_set_default_verify_paths(c);
        SSL_CTX_set_mode(c, SSL_MODE_AUTO_RETRY);
        return c;
    }();
    return ctx;
}

std::string PeerSpkiSha256(SSL* ssl) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    X509* cert = SSL_get1_peer_certificate(ssl);
#else
    X509* cert = SSL_get_peer_certificate(ssl);
#endif
    if (!cert) return "";
    std::string out;
    int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), nullptr);
    if (len > 0) {
        std::vector<unsigned char> der(static_cast<size_t>(len));
        unsigned char* p = der.data();
        if (i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &p) == len) {
            out = CryptoUtil::Sha256(der.data(), der.size());
        }
    }
    X509_free(cert);
    return out;
}
#endif

#if defined(_WIN32)
std::wstring Widen(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return L"";
    std::wstring w(static_cast<size_t>(n), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    if (!w.empty() && w.back() == L'\0') w.pop_back();
    return w;
}

std::string WinCertSpkiSha256(HINTERNET hRequest) {
    PCCERT_CONTEXT cert = nullptr;
    DWORD sz = sizeof(cert);
    if (!WinHttpQueryOption(hRequest, WINHTTP_OPTION_SERVER_CERT_CONTEXT, &cert, &sz) || !cert) return "";
    std::string out;
    DWORD len = 0;
    if (CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &cert->pCertInfo->SubjectPublicKeyInfo, nullptr, &len) && len) {
        std::vector<BYTE> der(len);
        if (CryptEncodeObject(X509_ASN_ENCODING, X509_PUBLIC_KEY_INFO, &cert->pCertInfo->SubjectPublicKeyInfo, der.data(), &len)) {
            out = CryptoUtil::Sha256(der.data(), len);
        }
    }
    CertFreeCertificateContext(cert);
    return out;
}
#endif

} // namespace

PanelClient::PanelClient(std::string base_url, std::string secret_key, std::string spki_pin_sha256_hex)
    : base_url_(std::move(base_url)),
      secret_key_(std::move(secret_key)),
      pin_(NormalizePin(spki_pin_sha256_hex)),
      hwid_(CryptoUtil::GetMachineHWID()) {
    EnsureNetworkInit();
#if !defined(_WIN32)
    // OpenSSL writes cannot pass MSG_NOSIGNAL: make sure a peer reset never kills the game.
    // Only replaces the *default* disposition; a host-installed handler is left untouched.
    static std::once_flag once;
    std::call_once(once, []() {
        struct sigaction sa{};
        if (sigaction(SIGPIPE, nullptr, &sa) == 0 && sa.sa_handler == SIG_DFL) {
            sa.sa_handler = SIG_IGN;
            sigaction(SIGPIPE, &sa, nullptr);
        }
    });
#endif
}

PanelClient::~PanelClient() = default;

void PanelClient::SetPin(std::string spki_pin_sha256_hex) {
    pin_ = NormalizePin(spki_pin_sha256_hex);
}

bool PanelClient::TlsSupported() {
#if defined(_WIN32) || defined(NOESCAPE_HAS_OPENSSL)
    return true;
#else
    return false;
#endif
}

std::string PanelClient::RandomNonce() {
    // 128 random bits; random_device is backed by getrandom()/BCryptGenRandom on supported toolchains
    std::random_device rd;
    uint8_t buf[16];
    for (size_t i = 0; i < sizeof(buf); i += 4) {
        uint32_t v = rd();
        std::memcpy(buf + i, &v, 4);
    }
    return CryptoUtil::ToHex(buf, sizeof(buf));
}

PanelClient::ParsedUrl PanelClient::ParseUrl(const std::string& url) {
    ParsedUrl res;
    res.port = 80;
    res.path = "/";

    // Reject header injection through the URL
    if (url.find_first_of("\r\n \t") != std::string::npos) res.valid = false;

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

    auto parsePort = [&](const std::string& p) {
        char* end = nullptr;
        long port = std::strtol(p.c_str(), &end, 10);
        if (p.empty() || !end || *end != '\0' || port <= 0 || port > 65535) res.valid = false;
        else res.port = static_cast<uint16_t>(port);
    };

    if (!hostPort.empty() && hostPort[0] == '[') {               // [IPv6]:port
        size_t close = hostPort.find(']');
        if (close == std::string::npos) { res.valid = false; return res; }
        res.host = hostPort.substr(1, close - 1);
        if (close + 1 < hostPort.size()) {
            if (hostPort[close + 1] != ':') { res.valid = false; return res; }
            parsePort(hostPort.substr(close + 2));
        }
    } else {
        size_t colonPos = hostPort.find(':');
        if (colonPos != std::string::npos) {
            res.host = hostPort.substr(0, colonPos);
            parsePort(hostPort.substr(colonPos + 1));
        } else {
            res.host = hostPort;
        }
    }
    if (res.host.empty()) res.valid = false;
    return res;
}

PanelClient::HttpResult PanelClient::Request(const ParsedUrl& target, const char* method,
                                             const std::string& body, uint32_t timeout_ms) const {
    HttpResult result;
    if (!target.valid) return result;
    EnsureNetworkInit();
    // Hard deadline for the whole exchange (name resolution excluded, see ConnectTcp)
    const auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    const std::string signature = body.empty() ? std::string() : CryptoUtil::HmacSha256(secret_key_, body);

#if defined(_WIN32)
    if (target.secure) {
        // WinHTTP: system TLS stack + certificate store; the pin is enforced before the body is sent
        HINTERNET hSession = WinHttpOpen(L"NoEscapeAC/7", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
                                         WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
        if (!hSession) return result;
        int t = static_cast<int>(timeout_ms);
        WinHttpSetTimeouts(hSession, t, t, t, t);
        DWORD protocols = WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_2;
#if defined(WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3)
        protocols |= WINHTTP_FLAG_SECURE_PROTOCOL_TLS1_3;
#endif
        WinHttpSetOption(hSession, WINHTTP_OPTION_SECURE_PROTOCOLS, &protocols, sizeof(protocols));
        HINTERNET hConnect = WinHttpConnect(hSession, Widen(target.host).c_str(), target.port, 0);
        HINTERNET hRequest = hConnect ? WinHttpOpenRequest(hConnect, Widen(method).c_str(), Widen(target.path).c_str(),
                                                           nullptr, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES,
                                                           WINHTTP_FLAG_SECURE) : nullptr;
        if (hRequest) {
            if (!pin_.empty()) {
                // With a pin the server key itself is the trust anchor (self-signed panels allowed)
                DWORD flags = SECURITY_FLAG_IGNORE_UNKNOWN_CA | SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                              SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
                WinHttpSetOption(hRequest, WINHTTP_OPTION_SECURITY_FLAGS, &flags, sizeof(flags));
            }
            std::wstring headers = L"Content-Type: application/json\r\n";
            if (!signature.empty()) headers += L"X-NoEscape-Signature: " + Widen(signature) + L"\r\n";
            bool ok = WinHttpSendRequest(hRequest, headers.c_str(), static_cast<DWORD>(-1L),
                                         WINHTTP_NO_REQUEST_DATA, 0, static_cast<DWORD>(body.size()), 0) != FALSE;
            if (ok && !pin_.empty()) {
                std::string spki = WinCertSpkiSha256(hRequest);
                if (spki.empty() || !CryptoUtil::ConstantTimeEquals(spki, pin_)) {
                    result.pin_mismatch = true;
                    ok = false;
                }
            }
            DWORD written = 0;
            if (ok && !body.empty()) {
                ok = WinHttpWriteData(hRequest, body.data(), static_cast<DWORD>(body.size()), &written) &&
                     written == body.size();
            }
            if (ok && WinHttpReceiveResponse(hRequest, nullptr)) {
                DWORD code = 0, sz = sizeof(code);
                WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                                    WINHTTP_HEADER_NAME_BY_INDEX, &code, &sz, WINHTTP_NO_HEADER_INDEX);
                std::string data;
                DWORD avail = 0;
                while (data.size() < kMaxResponse && RemainingMs(deadline) > 0 &&
                       WinHttpQueryDataAvailable(hRequest, &avail) && avail > 0) {
                    std::string chunk(std::min<DWORD>(avail, 8192), '\0');
                    DWORD read = 0;
                    if (!WinHttpReadData(hRequest, chunk.data(), static_cast<DWORD>(chunk.size()), &read) || read == 0) break;
                    data.append(chunk.data(), read);
                }
                result.status = static_cast<int>(code);
                result.body = data;
            }
            WinHttpCloseHandle(hRequest);
        }
        if (hConnect) WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);
        return result;
    }
#else
    if (target.secure) {
#if !defined(NOESCAPE_HAS_OPENSSL)
        return result; // no TLS in this build: refuse rather than silently downgrade to cleartext
#else
        SSL_CTX* ctx = ClientContext();
        if (!ctx) return result;
        socket_t sock = ConnectTcp(target.host, target.port, deadline);
        if (!IS_VALID_SOCKET(sock)) return result;
        SetSocketTimeouts(sock, RemainingMs(deadline));
        SSL* ssl = SSL_new(ctx);
        if (!ssl) { CLOSE_SOCKET(sock); return result; }
        SSL_set_fd(ssl, sock);
        SSL_set_tlsext_host_name(ssl, target.host.c_str());
        if (pin_.empty()) {
            // No pin: full WebPKI validation including hostname
            SSL_set_verify(ssl, SSL_VERIFY_PEER, nullptr);
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#endif
            SSL_set1_host(ssl, target.host.c_str());
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic pop
#endif
        } else {
            SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr); // trust is established by the pin below
        }
        std::string raw;
        bool ok = SSL_connect(ssl) == 1;
        if (ok && !pin_.empty()) {
            std::string spki = PeerSpkiSha256(ssl);
            if (spki.empty() || !CryptoUtil::ConstantTimeEquals(spki, pin_)) {
                result.pin_mismatch = true;
                ok = false; // nothing (not even the request line) is sent to an unpinned server
            }
        }
        if (ok) {
            std::string req = BuildRequest(target, method, body, signature);
            size_t off = 0;
            while (ok && off < req.size() && RemainingMs(deadline) > 0) {
                int w = SSL_write(ssl, req.data() + off, static_cast<int>(req.size() - off));
                if (w <= 0) ok = false; else off += static_cast<size_t>(w);
            }
            char buf[4096];
            while (ok && raw.size() < kMaxResponse && RemainingMs(deadline) > 0) {
                SetSocketTimeouts(sock, RemainingMs(deadline));
                int n = SSL_read(ssl, buf, sizeof(buf));
                if (n <= 0) break;
                raw.append(buf, static_cast<size_t>(n));
            }
            SSL_shutdown(ssl);
        }
        ERR_clear_error();
        SSL_free(ssl);
        CLOSE_SOCKET(sock);
        if (result.pin_mismatch) return result;
        return ParseHttpResponse(raw);
#endif
    }
#endif

    // Plain HTTP (development / trusted networks only)
    socket_t sock = ConnectTcp(target.host, target.port, deadline);
    if (!IS_VALID_SOCKET(sock)) return result;
    std::string req = BuildRequest(target, method, body, signature);
    size_t off = 0;
    bool ok = true;
    while (off < req.size() && RemainingMs(deadline) > 0) {
        SetSocketTimeouts(sock, RemainingMs(deadline));
        int n = send(sock, req.data() + off, static_cast<int>(req.size() - off), SendFlags());
        if (n <= 0) { ok = false; break; }
        off += static_cast<size_t>(n);
    }
    std::string raw;
    char buf[4096];
    // Bounded in total time and size: a slow-drip or endless response cannot stall the caller
    while (ok && raw.size() < kMaxResponse && RemainingMs(deadline) > 0) {
        SetSocketTimeouts(sock, RemainingMs(deadline));
        int n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        raw.append(buf, static_cast<size_t>(n));
    }
    CLOSE_SOCKET(sock);
    return ParseHttpResponse(raw);
}

bool PanelClient::VerifyServerSignature(const std::string& message, const std::string& signature_hex) const {
    if (!server_public_key_.empty()) {
        // When an asymmetric server public key is configured, require a valid Ed25519 signature;
        // a leaked symmetric client key cannot forge server challenges or ban status responses.
        return CryptoUtil::VerifyAsymmetric(server_public_key_, message, signature_hex);
    }
    if (secret_key_.empty()) {
        // If neither asymmetric server public key nor shared secret key is provisioned, refuse verification
        return false;
    }
    std::string expectedHmac = CryptoUtil::HmacSha256(secret_key_, message);
    return CryptoUtil::ConstantTimeEquals(signature_hex, expectedHmac);
}

HeartbeatPacket PanelClient::ConstructHeartbeat(uint32_t current_threat_score, const std::string& status) {
    HeartbeatPacket pkt;
    pkt.hwid = hwid_;
    pkt.timestamp = static_cast<uint64_t>(std::time(nullptr));
    pkt.threat_score = current_threat_score;
    pkt.events_count = 0;
    pkt.status = status;
    pkt.nonce = RandomNonce();

    std::ostringstream payload;
    payload << pkt.hwid << ":" << pkt.timestamp << ":" << pkt.threat_score << ":" << pkt.status << ":" << pkt.nonce;
    pkt.hmac_signature = CryptoUtil::HmacSha256(secret_key_, payload.str());
    return pkt;
}

bool PanelClient::SendHeartbeat(uint32_t current_threat_score, const std::string& status) {
    return Heartbeat(current_threat_score, status).ok;
}

HeartbeatResult PanelClient::Heartbeat(uint32_t current_threat_score, const std::string& status) {
    HeartbeatResult out;
    auto pkt = ConstructHeartbeat(current_threat_score, status);
    std::ostringstream json;
    json << "{"
         << "\"hwid\":\"" << JsonEscape(pkt.hwid) << "\","
         << "\"timestamp\":" << pkt.timestamp << ","
         << "\"threat_score\":" << pkt.threat_score << ","
         << "\"status\":\"" << JsonEscape(pkt.status) << "\","
         << "\"nonce\":\"" << pkt.nonce << "\","
         << "\"key_id\":\"" << JsonEscape(key_id_) << "\","
         << "\"build_version\":\"" << JsonEscape(client_build_version_) << "\""
         << "}";
    auto res = Request(ParseUrl(base_url_ + "/heartbeat"), "POST", json.str(), 2000);
    out.ok = res.status >= 200 && res.status < 300;
    if (!out.ok) return out;

    // Anti-rollback build version verification
    std::string minVer = JsonString(res.body, "min_build_version", 0);
    if (!minVer.empty()) {
        out.required_min_version = minVer;
        if (!CryptoUtil::IsVersionAtLeast(client_build_version_, minVer)) {
            out.version_rejected = true;
            out.ok = false;
            return out;
        }
    }

    // Optional attestation challenge. It is only honoured when its signature (bound to our
    // HWID and this heartbeat's nonce) verifies - a forged challenge must not make us do work or
    // leak anything.
    size_t cp = res.body.find("\"challenge\":{");
    if (cp != std::string::npos) {
        AttestChallenge c;
        c.id = JsonString(res.body, "id", cp);
        c.nonce = JsonString(res.body, "nonce", cp);
        std::string sig = JsonString(res.body, "sig", cp);
        bool nums = JsonNumber(res.body, "offset", cp, c.offset) && JsonNumber(res.body, "length", cp, c.length);
        JsonNumber(res.body, "expires_at", cp, c.expires_at);
        c.present = true;

        uint64_t nowSec = static_cast<uint64_t>(std::time(nullptr));
        if (c.expires_at > 0 && nowSec > c.expires_at) {
            c = AttestChallenge{};
            c.present = true;
            c.expired = true;
            c.forged = true;
            out.challenge = c;
            return out;
        }

        std::string canonical = "challenge:" + hwid_ + ":" + pkt.nonce + ":" + c.id + ":" + c.nonce + ":" +
                                std::to_string(c.offset) + ":" + std::to_string(c.length);
        if (!nums || !IsToken(c.id, 64) || !IsToken(c.nonce, 128) ||
            !VerifyServerSignature(canonical, sig)) {
            c = AttestChallenge{};
            c.present = true;
            c.forged = true;
        }
        out.challenge = c;
    }
    return out;
}

bool PanelClient::SendAttestation(const AttestChallenge& challenge, const std::string& answer_hex) {
    if (!challenge.present || challenge.forged || challenge.expired) return false;
    std::ostringstream json;
    json << "{"
         << "\"hwid\":\"" << JsonEscape(hwid_) << "\","
         << "\"timestamp\":" << static_cast<uint64_t>(std::time(nullptr)) << ","
         << "\"nonce\":\"" << RandomNonce() << "\","
         << "\"challenge_id\":\"" << challenge.id << "\","
         << "\"answer\":\"" << answer_hex << "\","
         << "\"key_id\":\"" << JsonEscape(key_id_) << "\""
         << "}";
    auto res = Request(ParseUrl(base_url_ + "/attest"), "POST", json.str(), 2000);
    return res.status >= 200 && res.status < 300;
}

bool PanelClient::SendBanReport(const core::DetectionEvent& event, uint32_t current_threat_score) {
    uint64_t now = static_cast<uint64_t>(std::time(nullptr));
    std::ostringstream json;
    json << "{"
         << "\"hwid\":\"" << JsonEscape(hwid_) << "\","
         << "\"timestamp\":" << now << ","
         << "\"nonce\":\"" << RandomNonce() << "\","
         << "\"key_id\":\"" << JsonEscape(key_id_) << "\","
         << "\"threat_score\":" << current_threat_score << ","
         << "\"type\":\"" << core::DetectionEvent::TypeToString(event.type) << "\","
         << "\"category\":\"" << core::DetectionEvent::CategoryToString(event.category) << "\","
         << "\"confidence\":\"" << core::DetectionEvent::ConfidenceToString(event.confidence) << "\","
         << "\"severity\":\"" << core::DetectionEvent::SeverityToString(event.severity) << "\","
         << "\"component\":\"" << JsonEscape(event.component) << "\","
         << "\"details\":\"" << JsonEscape(event.details) << "\""
         << "}";
    // The whole body is authenticated (X-NoEscape-Signature), so no field can be altered and
    // there is no field-concatenation ambiguity.
    auto res = Request(ParseUrl(base_url_ + "/alert"), "POST", json.str(), 2000);
    return res.status >= 200 && res.status < 300;
}

BanCheckResult PanelClient::QueryBanStatus() {
    BanCheckResult result;
    const std::string nonce = RandomNonce(); // unpredictable: a recorded reply cannot be replayed
    auto res = Request(ParseUrl(base_url_ + "/check?hwid=" + hwid_ + "&nonce=" + nonce), "GET", "", 2000);

    if (res.pin_mismatch) {
        result.status = BanCheckStatus::SIGNATURE_INVALID;
        result.reason = "Panel TLS certificate does not match the configured pin (MitM or fake panel)";
        return result;
    }
    if (res.status == 0) {
        result.status = BanCheckStatus::NETWORK_ERROR;
        result.reason = "Backend server unreachable or timeout";
        return result;
    }
    if (res.status < 200 || res.status >= 300) {
        result.status = BanCheckStatus::NETWORK_ERROR;
        result.reason = "Backend returned HTTP " + std::to_string(res.status);
        return result;
    }

    const std::string& body = res.body;
    bool isBanned = body.find("\"banned\":true") != std::string::npos;
    bool isClean = body.find("\"banned\":false") != std::string::npos;
    size_t sigPos = body.find("\"signature\":\"");
    size_t sigEnd = (sigPos == std::string::npos) ? std::string::npos : body.find('"', sigPos + 13);
    if (sigEnd == std::string::npos || isBanned == isClean) {
        result.status = BanCheckStatus::SIGNATURE_INVALID;
        result.reason = "Missing signature or ambiguous panel response";
        return result;
    }
    std::string serverSig = body.substr(sigPos + 13, sigEnd - (sigPos + 13));
    std::string canonical = hwid_ + ":" + (isBanned ? "1" : "0") + ":" + nonce;
    if (!VerifyServerSignature(canonical, serverSig)) {
        result.status = BanCheckStatus::SIGNATURE_INVALID;
        result.reason = "Panel response signature validation failed (Tampered or MitM)";
        return result;
    }

    result.status = isBanned ? BanCheckStatus::BANNED : BanCheckStatus::CLEAN;
    result.reason = isBanned ? "Global Hardware ID Blacklist Match" : "Hardware ID is clean";
    return result;
}

bool PanelClient::CheckBanStatus(bool& out_is_banned, std::string& out_reason) {
    auto res = QueryBanStatus();
    out_is_banned = (res.status == BanCheckStatus::BANNED);
    out_reason = res.reason;
    return res.status == BanCheckStatus::BANNED || res.status == BanCheckStatus::CLEAN;
}

} // namespace noescape::network
