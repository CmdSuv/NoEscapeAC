#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include "noescape/core/types.hpp"

namespace noescape::forensics {

struct ProcessRecord {
    uint32_t pid{0};
    uint32_t ppid{0};
    std::string name;
    std::string path;
    std::string cmdline;
    bool is_deleted_binary{false};
    bool has_injected_env{false};
};

class ProcessAnalyzer {
public:
    static ProcessAnalyzer& Instance();

    // Enumerate active processes on the system
    std::vector<ProcessRecord> EnumerateProcesses();

    // Check processes against blacklists, deleted status, and environment tampering
    std::vector<core::DetectionEvent> AuditProcesses(
        const std::vector<std::string>& blacklist,
        const std::vector<std::string>& cmdline_blacklist
    );

    // Check if the current process itself has LD_PRELOAD or injected environment
    bool CheckCurrentProcessEnvironment();

private:
    ProcessAnalyzer() = default;
};

} // namespace noescape::forensics
