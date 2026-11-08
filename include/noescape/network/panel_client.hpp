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
    std::string client_ephemeral_pubkey;
    std::string ed25519_signature;
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
// Server-issued code-attestation challenge, delivered in the heartbeat reply. The client proves
// it still runs the expected code by returning HMAC(secret, id:nonce:<bytes of own code>).
struct AttestChallenge {
    bool present{false};
    bool forged{false};        // a challenge arrived but its signature did not verify
    bool expired{false};       // challenge timestamp/TTL expired
    std::string id;
    std::string nonce;
    uint64_t offset{0};        // into the anti-cheat's executable segment
    uint64_t length{0};
    uint64_t expires_at{0};
};

struct HeartbeatResult {
    bool ok{false};
    bool version_rejected{false};
    std::string required_min_version;
    AttestChallenge challenge;
};

class PanelClient {
public:
    PanelClient(std::string base_url, std::string secret_key, std::string spki_pin_sha256_hex = "");
    ~PanelClient();

    bool SendBanReport(const core::DetectionEvent& event, uint32_t current_threat_score);
    bool SendHeartbeat(uint32_t current_threat_score, const std::string& status = "HEALTHY");

    // Heartbeat that also returns the server's attestation challenge (if any)
    HeartbeatResult Heartbeat(uint32_t current_threat_score, const std::string& status = "HEALTHY");

    // Answers a challenge; answer_hex = IntegrityChecker::Attest(...)
    bool SendAttestation(const AttestChallenge& challenge, const std::string& answer_hex);

    const std::string& SecretKey() const { return secret_key_; }
    BanCheckResult QueryBanStatus();
    bool CheckBanStatus(bool& out_is_banned, std::string& out_reason);
    HeartbeatPacket ConstructHeartbeat(uint32_t current_threat_score, const std::string& status);
    static std::string RandomNonce();

    const std::string& GetHwid() const { return hwid_; }
    const std::string& GetBaseUrl() const { return base_url_; }
    void SetBaseUrl(std::string url) { base_url_ = std::move(url); }
    void SetPin(std::string spki_pin_sha256_hex);

    // Asymmetric server public key & key rotation / build version anti-rollback controls
    void SetServerPublicKey(std::string pub_key_hex) { server_public_key_ = std::move(pub_key_hex); }
    const std::string& GetServerPublicKey() const { return server_public_key_; }
    void SetKeyId(std::string key_id) { key_id_ = std::move(key_id); }
    const std::string& GetKeyId() const { return key_id_; }
    void SetClientBuildVersion(std::string ver) { client_build_version_ = std::move(ver); }
    const std::string& GetClientBuildVersion() const { return client_build_version_; }

    // Client ephemeral Ed25519 signing keypair
    const std::string& GetClientEphemeralPublicKey() const { return client_ephemeral_pub_hex_; }
    const std::string& GetClientEphemeralPrivateKey() const { return client_ephemeral_priv_hex_; }

    // Verifies a server message using Ed25519 asymmetric key if configured, else HMAC
    bool VerifyServerSignature(const std::string& message, const std::string& signature_hex) const;

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
    std::string server_public_key_;
    std::string key_id_{"default-v1"};
    std::string client_build_version_{"7.0.13"};
    std::string client_ephemeral_priv_hex_;
    std::string client_ephemeral_pub_hex_;

    HttpResult Request(const ParsedUrl& target, const char* method, const std::string& body,
                       uint32_t timeout_ms) const;
};

} // namespace noescape::network
