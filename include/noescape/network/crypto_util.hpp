#pragma once

#include <string>
#include <vector>
#include <cstdint>

namespace noescape::network {

class CryptoUtil {
public:
    // Pure C++20 Ring-3 SHA-256 implementation
    static std::string Sha256(const uint8_t* data, size_t length);
    static std::string Sha256(const std::string& input);

    // HMAC-SHA256 for tamper-evident payload signing
    static std::string HmacSha256(const std::string& key, const std::string& data);

    // Machine Hardware ID (HWID) Fingerprinting
    static std::string GetMachineHWID();

    // Constant-time equality for MAC/signature comparison (no early exit on first mismatch)
    static bool ConstantTimeEquals(const std::string& a, const std::string& b);

    // Hex formatting helper
    static std::string ToHex(const uint8_t* data, size_t length);
};

} // namespace noescape::network
