#pragma once

#include <cstdint>
#include <cstddef>
#include <mutex>
#include <vector>
#include "noescape/core/types.hpp"

namespace noescape::memory {

// Tripwire memory: pages that nothing in the legitimate process ever writes.
// Any write by an external process (WriteProcessMemory / process_vm_writev / ptrace)
// marks the page dirty at the OS level (Windows MEM_WRITE_WATCH, Linux soft-dirty bit)
// and/or alters its random content. Reads cannot be detected from Ring-3.
class CanaryMonitor {
public:
    static CanaryMonitor& Instance();

    // Allocates guard-fenced canary pages filled with random data. Idempotent.
    bool Initialize(size_t page_count = 4);
    void Shutdown();

    // Returns events if the canary was written to since the previous check.
    std::vector<core::DetectionEvent> Check();

    // True if the OS write-tracking mechanism was verified to work at Initialize().
    bool IsWriteTrackingSupported() const { return tracking_supported_; }

    // Address/size of canary region (exposed for tests and phantom-data placement).
    uintptr_t Address() const { return reinterpret_cast<uintptr_t>(base_); }
    size_t Size() const { return size_; }

private:
    CanaryMonitor() = default;
    ~CanaryMonitor();

    void ResetTracking();
    bool PageWasWritten();

    std::mutex mutex_;
    uint8_t* base_{nullptr};      // first canary byte
    void* alloc_base_{nullptr};   // includes guard pages
    size_t alloc_size_{0};
    size_t size_{0};
    std::vector<uint8_t> expected_;
    bool tracking_supported_{false};
    // Opened once at Initialize(): after PR_SET_DUMPABLE=0 (AntiDebug::HideCurrentThread)
    // /proc/self/* can no longer be opened by an unprivileged process.
    [[maybe_unused]] int pagemap_fd_{-1};
    [[maybe_unused]] int clear_refs_fd_{-1};
};

} // namespace noescape::memory
