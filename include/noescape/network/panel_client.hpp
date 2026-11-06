#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include "noescape/core/types.hpp"

namespace noescape::network {

struct HeartbeatPacket {
    std::string hwid;
    uint64_t timestamp{0};
    uint32_t threat_score{0};
    uint32_t events_count{0};
    std::string status;
    std::string nonce;
    std::string hmac_signature;
};

enum class BanCheckStatus {
    CLEAN,
    BANNED,
    NETWORK_ERROR,
    SIGNATURE_INVALID
};

struct BanCheckResult {
    BanCheckStatus status{BanCheckStatus::NETWORK_ERROR};
    std::string reason;
    uint64_t server_timestamp{0};
};

// Panel protocol (see tools/reference_server.py for the server side):
//  * Requests  : JSON body, authenticated with "X-NoEscape-Signature: HMAC-SHA256(secret, raw body)".
//                Every body carries a timestamp and a random single-use nonce (anti-replay).
//  * /check    : GET with a random 128-bit nonce; reply {"banned":bool,"signature":HMAC("hwid:0|1:nonce")}.
//  * Transport : https:// uses TLS 1.2+ (OpenSSL on POSIX, WinHTTP on Windows). If a pin is set,
//                the server's SubjectPublicKeyInfo SHA-256 must match it (defeats fake panels and
//                MitM even with a user-installed root CA). Without TLS support https is refused,
//                never downgraded to cleartext.
class PanelClient {
public:
    PanelClient(std::string base_url, std::string secret_key, std::string spki_pin_sha256_hex = "");
    ~PanelClient();

    bool SendBanReport(const core::DetectionEvent& event, uint32_t current_threat_score);
    bool SendHeartbeat(uint32_t current_threat_score, const std::string& status = "HEALTHY");
    BanCheckResult QueryBanStatus();
    bool CheckBanStatus(bool& out_is_banned, std::string& out_reason);
    HeartbeatPacket ConstructHeartbeat(uint32_t current_threat_score, const std::string& status);

    const std::string& GetHwid() const { return hwid_; }
    const std::string& GetBaseUrl() const { return base_url_; }
    void SetBaseUrl(std::string url) { base_url_ = std::move(url); }
    void SetPin(std::string spki_pin_sha256_hex);

    // True when this build can speak https:// (OpenSSL / WinHTTP available)
    static bool TlsSupported();

    struct ParsedUrl {
        bool secure{false};
        bool valid{true};
        std::string host;
        uint16_t port{80};
        std::string path;
    };
    static ParsedUrl ParseUrl(const std::string& url);

    struct HttpResult {
        int status{0};          // HTTP status code, 0 = transport failure
        bool pin_mismatch{false};
        std::string body;
    };

private:
    std::string base_url_;
    std::string secret_key_;
    std::string pin_;
    std::string hwid_;

    HttpResult Request(const ParsedUrl& target, const char* method, const std::string& body,
                       uint32_t timeout_ms) const;
    static std::string RandomNonce();
};

} // namespace noescape::network
