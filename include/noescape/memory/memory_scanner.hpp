#pragma once
#include <functional>

#include <string>
#include <vector>
#include <cstdint>
#include <optional>
#include <map>
#include <mutex>
#include "noescape/core/types.hpp"
#include "noescape/memory/pattern_scanner.hpp"
#include "noescape/memory/cheat_signature.hpp"
#include "noescape/memory/signature_database.hpp"

namespace noescape::memory {

struct MemoryRegion {
    uintptr_t start{0};
    uintptr_t end{0};
    size_t size{0};
    bool readable{false};
    bool writable{false};
    bool executable{false};
    bool is_shared{false};
    bool is_backed_by_file{false};
    uint64_t file_offset{0};
    std::string pathname;
};

class MemoryScanner {
public:
    static MemoryScanner& Instance();

    // Enumerate all active virtual memory regions of the current process
    std::vector<MemoryRegion> QueryMemoryRegions(bool force_refresh = false);

    // Caches memory regions snapshot to eliminate redundant /proc/self/maps reads per cycle
    void RefreshCache();
    void ClearCache();
    bool IsCacheValid() const;

    // Check for unbacked executable regions (e.g. manual mapping, shellcode, RWX allocations)
    std::vector<core::DetectionEvent> DetectUnbackedExecutableRegions();

    // Scans memory regions against cheat signatures with category & target-rule filtering
    std::vector<core::DetectionEvent> ScanSignatures(const std::vector<CheatSignature>& signatures);

    // Legacy overload: scans memory regions against raw byte patterns
    std::vector<core::DetectionEvent> ScanSignatures(const std::vector<Pattern>& patterns);

    // Compares one file-backed executable mapping per call (round-robin) against its
    // on-disk image; detects module stomping / in-memory patching. Linux/ELF only.
    std::vector<core::DetectionEvent> DetectModifiedModules();

    // Detects previously-executable regions that were later made inaccessible
    // (sleep-obfuscation style payloads hiding between audit cycles).
    std::vector<core::DetectionEvent> DetectSleepingPayloads();

    // Runs a full memory audit with custom cheat signatures
    std::vector<core::DetectionEvent> PerformAudit(const std::vector<CheatSignature>& signatures);

    // Legacy overload: runs full memory audit with raw patterns
    std::vector<core::DetectionEvent> PerformAudit(const std::vector<Pattern>& patterns);

    // Runs a full memory audit using the default curated signature database
    std::vector<core::DetectionEvent> PerformAudit();

    // Helpers to retrieve default known cheat signatures
    static std::vector<CheatSignature> GetDefaultCheatSignatures();
    static std::vector<Pattern> GetDefaultCheatPatterns();

    // Called after each scanned chunk so callers (watchdog) can see forward progress
    void SetProgressCallback(std::function<void()> cb) {
        std::lock_guard<std::mutex> l(cache_mutex_);
        progress_cb_ = std::move(cb);
    }

private:
    std::function<void()> progress_cb_;
    int cache_users_{0};
    MemoryScanner() = default;

    std::vector<MemoryRegion> QueryMemoryRegionsInternal();

    mutable std::mutex cache_mutex_;
    std::vector<MemoryRegion> cached_regions_;
    bool cache_valid_{false};

    std::mutex state_mutex_;
    std::map<uintptr_t, uintptr_t> seen_exec_regions_; // start -> end
    size_t module_cursor_{0};
};

} // namespace noescape::memory
