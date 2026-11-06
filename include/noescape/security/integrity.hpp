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
