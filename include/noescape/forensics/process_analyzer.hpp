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
    uint32_t granted_access_mask{0};
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

    // Detect external processes holding open file descriptors / handles to our process memory
    // (/proc/<self>/mem, /proc/<self>/pagemap, /proc/<self>/map_files on Linux;
    // SystemExtendedHandleInformation with VM_READ/VM_WRITE on Windows)
    std::vector<ProcessRecord> DetectExternalMemoryReaders();

    // Evaluates an external process handle and its granted access mask (e.g., PROCESS_VM_READ=0x0010,
    // PROCESS_VM_WRITE=0x0020, PROCESS_VM_OPERATION=0x0008, PROCESS_CREATE_THREAD=0x0002)
    std::optional<core::DetectionEvent> InspectExternalHandle(
        uint32_t owner_pid,
        const std::string& owner_name,
        const std::string& owner_path,
        uint32_t granted_access_mask
    );

private:
    ProcessAnalyzer() = default;
};

} // namespace noescape::forensics
