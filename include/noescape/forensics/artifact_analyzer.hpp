#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include "noescape/core/types.hpp"

namespace noescape::forensics {

struct ArtifactRecord {
    std::string path;
    std::string matched_signature;
    std::string artifact_type;
};

class ArtifactAnalyzer {
public:
    static ArtifactAnalyzer& Instance();

    // Scans directories and system files for known cheat artifacts
    std::vector<ArtifactRecord> ScanFilesystemArtifacts(const std::vector<std::string>& blacklisted_names);

    // Checks active drivers / kernel modules for blacklisted signatures
    std::vector<ArtifactRecord> ScanKernelDrivers(const std::vector<std::string>& blacklisted_drivers);

    // Checks for system-wide injection hooks (e.g. /etc/ld.so.preload or AppInit_DLLs)
    bool CheckSystemWidePreload();

    // Runs a comprehensive forensics audit
    std::vector<core::DetectionEvent> PerformAudit(
        const std::vector<std::string>& blacklisted_names,
        const std::vector<std::string>& blacklisted_drivers
    );

private:
    ArtifactAnalyzer() = default;
};

} // namespace noescape::forensics
