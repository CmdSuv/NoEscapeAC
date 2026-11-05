#pragma once

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
    std::string GetBaselineHash() const { return baseline_hash_; }
    std::string ComputeCurrentTextHash() const;

private:
    IntegrityChecker() = default;

    std::string baseline_hash_;
    uintptr_t text_start_{0};
    size_t text_size_{0};
    bool initialized_{false};

    bool LocateTextSection(uintptr_t& outStart, size_t& outSize);
};

} // namespace noescape::security
