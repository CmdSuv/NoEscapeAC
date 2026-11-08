#pragma once
#include <mutex>

#include <string>
#include <vector>
#include <optional>
#include <cstdint>
#include "noescape/core/types.hpp"

namespace noescape::security {

class IntegrityChecker {
public:
    static IntegrityChecker& Instance();

    // Sets up baseline hash of executable .text segment
    bool Initialize();

    // Verifies current memory against baseline hash
    std::optional<core::DetectionEvent> VerifyIntegrity();

    // Direct access to hashes
    std::string GetBaselineHash() const { std::lock_guard<std::recursive_mutex> l(mutex_); return baseline_hash_; }
    std::string ComputeCurrentTextHash() const;

    // Remote attestation: HMAC(secret, id ":" nonce ":" <bytes of [offset, offset+length) of the
    // executable segment>). Returns false when the range is invalid. The server holds the
    // reference image and recomputes the same value, so a patched client cannot answer correctly
    // without keeping an unpatched copy of its code around.
    bool Attest(const std::string& secret_key, const std::string& id, const std::string& nonce,
                uint64_t offset, uint64_t length, std::string& out_hex);
    bool AttestEd25519(const std::string& private_key_hex, const std::string& id, const std::string& nonce,
                       uint64_t offset, uint64_t length, std::string& out_sig_hex);
    size_t TextSize() const { std::lock_guard<std::recursive_mutex> l(mutex_); return text_size_; }

private:
    IntegrityChecker() = default;

    mutable std::recursive_mutex mutex_;
    std::string baseline_hash_;
    uintptr_t text_start_{0};
    size_t text_size_{0};
    bool initialized_{false};
    bool pre_baseline_mismatch_{false};
    bool TextMatchesDisk() const;

    bool LocateTextSection(uintptr_t& outStart, size_t& outSize);
};

} // namespace noescape::security
