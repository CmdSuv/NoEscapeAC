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

class PanelClient {
public:
    PanelClient(std::string base_url, std::string secret_key);
    ~PanelClient();

    // Sends an immediate ban alert to the server
    bool SendBanReport(const core::DetectionEvent& event, uint32_t current_threat_score);

    // Sends periodic HMAC-signed heartbeat
    bool SendHeartbeat(uint32_t current_threat_score, const std::string& status = "HEALTHY");

    // Queries backend panel with HMAC challenge-response verification
    BanCheckResult QueryBanStatus();

    // Backwards-compatible ban status checker (returns true on definitive check, false on network error)
    bool CheckBanStatus(bool& out_is_banned, std::string& out_reason);

    // Constructs a signed heartbeat packet struct
    HeartbeatPacket ConstructHeartbeat(uint32_t current_threat_score, const std::string& status);

    const std::string& GetHwid() const { return hwid_; }
    const std::string& GetBaseUrl() const { return base_url_; }
    void SetBaseUrl(std::string url) { base_url_ = std::move(url); }

private:
    std::string base_url_;
    std::string secret_key_;
    std::string hwid_;

    struct ParsedUrl {
        std::string host;
        uint16_t port{80};
        std::string path;
    };

    static ParsedUrl ParseUrl(const std::string& url);
    static std::string HttpPost(const ParsedUrl& target, const std::string& body, uint32_t timeout_ms = 2500);
    static std::string HttpGet(const ParsedUrl& target, uint32_t timeout_ms = 2500);
};

} // namespace noescape::network
