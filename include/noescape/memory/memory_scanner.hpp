#pragma once
#include <functional>
#include <atomic>

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

struct ThreadExecutionInfo {
    uint32_t tid{0};
    uintptr_t instruction_pointer{0};
    uintptr_t stack_pointer{0};
    uintptr_t start_address{0};
    bool ip_in_backed_module{true};
    std::string module_path;
};

struct ModuleProvenanceInfo {
    std::string path;
    uintptr_t base_address{0};
    size_t executable_size{0};
    std::string sha256_disk_hash;
    std::string elf_build_id;
    bool is_signed{false};
    bool is_suspicious_origin{false};
};

struct ScanTelemetry {
    uint64_t total_scans_completed{0};
    uint64_t regions_scanned{0};
    uint64_t bytes_scanned{0};
    uint64_t last_scan_duration_us{0};
    uint64_t mean_scan_duration_us{0};
    uint64_t p95_scan_duration_us{0};
    uint64_t p99_scan_duration_us{0};
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
    // on-disk image; detects module stomping / in-memory patching.
    std::vector<core::DetectionEvent> DetectModifiedModules();

    // Detects previously-executable regions that were later made inaccessible
    // (sleep-obfuscation style payloads hiding between audit cycles).
    std::vector<core::DetectionEvent> DetectSleepingPayloads();

    // Thread execution provenance: inspects active thread start addresses and instruction pointers
    std::vector<ThreadExecutionInfo> QueryActiveThreads();
    std::optional<core::DetectionEvent> InspectThreadAddress(uint32_t tid, uintptr_t code_address);
    std::vector<core::DetectionEvent> AuditThreadProvenance();

    // Module provenance: SHA-256 disk identity, ELF NT_GNU_BUILD_ID, Windows Authenticode, origin validation
    std::vector<ModuleProvenanceInfo> QueryModuleProvenance();
    std::vector<core::DetectionEvent> AuditModuleProvenance();

    // Performance & adaptive scanning telemetry
    ScanTelemetry GetScanTelemetry() const;

    // Runs a full memory audit with custom cheat signatures
    std::vector<core::DetectionEvent> PerformAudit(const std::vector<CheatSignature>& signatures);

    // Legacy overload: runs full memory audit with raw patterns
    std::vector<core::DetectionEvent> PerformAudit(const std::vector<Pattern>& patterns);

    // Runs a full memory audit using the default curated signature database
    std::vector<core::DetectionEvent> PerformAudit();

    // Helpers to retrieve default known cheat signatures
    static std::vector<CheatSignature> GetDefaultCheatSignatures();
    static std::vector<Pattern> GetDefaultCheatPatterns();

    // Limits how many bytes one ScanSignatures() pass reads (0 = unlimited, the default).
    // With a budget the scan becomes incremental and resumes where the previous pass stopped,
    // which bounds the cost of every audit cycle regardless of the host's memory size.
    void SetScanBudget(size_t bytes_per_pass);

    // Declares that the host legitimately generates code at runtime (embedded JIT)
    void SetHostUsesJit(bool v) { host_uses_jit_.store(v); }
    bool HostUsesJit() const { return host_uses_jit_.load(); }

    // Called after each scanned chunk so callers (watchdog) can see forward progress
    void SetProgressCallback(std::function<void()> cb) {
        std::lock_guard<std::mutex> l(cache_mutex_);
        progress_cb_ = std::move(cb);
    }

private:
    bool IsJitRuntime(const std::vector<MemoryRegion>& regions) const;
    void RecordScanDurationUs(uint64_t duration_us, uint64_t regions_count, uint64_t bytes_count);
    std::function<void()> progress_cb_;
    std::atomic<bool> host_uses_jit_{false};
    int cache_users_{0};
    MemoryScanner() = default;

    std::vector<MemoryRegion> QueryMemoryRegionsInternal();

    mutable std::mutex cache_mutex_;
    std::vector<MemoryRegion> cached_regions_;
    bool cache_valid_{false};

    mutable std::mutex state_mutex_;
    size_t scan_budget_bytes_{0};
    uintptr_t scan_cursor_{0};
    std::map<uintptr_t, uintptr_t> seen_exec_regions_; // start -> end
    size_t module_cursor_{0};

    std::map<std::string, ModuleProvenanceInfo> provenance_cache_;
    std::vector<uint64_t> scan_durations_us_;
    ScanTelemetry telemetry_{};
};

} // namespace noescape::memory
