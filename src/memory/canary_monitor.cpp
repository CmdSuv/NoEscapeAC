#include "noescape/memory/canary_monitor.hpp"
#include "noescape/core/envutil.hpp"

#include <cstring>
#include <ctime>
#include <random>
#include <sstream>

#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace noescape::memory {

namespace {

size_t PageSize() {
#if defined(_WIN32)
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    return si.dwPageSize;
#else
    long ps = sysconf(_SC_PAGESIZE);
    return ps > 0 ? static_cast<size_t>(ps) : 4096;
#endif
}

} // namespace

CanaryMonitor& CanaryMonitor::Instance() {
    static CanaryMonitor* instance = new CanaryMonitor();
    return *instance;
}

CanaryMonitor::~CanaryMonitor() {
    Shutdown();
}

bool CanaryMonitor::Initialize(size_t page_count) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (base_) return true;
    if (page_count == 0) page_count = 1;

    const size_t ps = PageSize();
    size_ = page_count * ps;
    alloc_size_ = size_ + 2 * ps;
#if !defined(_WIN32)
    pagemap_fd_ = core::OpenProcSelfWithDumpableFallback("/proc/self/pagemap", O_RDONLY | O_CLOEXEC);
    clear_refs_fd_ = core::OpenProcSelfWithDumpableFallback("/proc/self/clear_refs", O_WRONLY | O_CLOEXEC);
#endif


#if defined(_WIN32)
    // Windows: MEM_WRITE_WATCH records writes from any process, including WriteProcessMemory.
    alloc_base_ = VirtualAlloc(nullptr, alloc_size_, MEM_RESERVE | MEM_COMMIT | MEM_WRITE_WATCH, PAGE_READWRITE);
    if (!alloc_base_) { size_ = 0; return false; }
    base_ = static_cast<uint8_t*>(alloc_base_) + ps;
    // Guard pages are only meaningful on Linux (VMA-merge false positives); Windows tracks per page.
#else
    alloc_base_ = mmap(nullptr, alloc_size_, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (alloc_base_ == MAP_FAILED) {
        if (pagemap_fd_ >= 0) close(pagemap_fd_);
        if (clear_refs_fd_ >= 0) close(clear_refs_fd_);
        pagemap_fd_ = clear_refs_fd_ = -1;
        alloc_base_ = nullptr;
        size_ = 0;
        return false;
    }
    base_ = static_cast<uint8_t*>(alloc_base_) + ps;
    // Canary pages sit between PROT_NONE guards so neighbouring mappings can never merge
    // into this VMA (a merge would set VM_SOFTDIRTY and cause false positives).
    if (mprotect(base_, size_, PROT_READ | PROT_WRITE) != 0) {
        munmap(alloc_base_, alloc_size_);
        if (pagemap_fd_ >= 0) close(pagemap_fd_);
        if (clear_refs_fd_ >= 0) close(clear_refs_fd_);
        pagemap_fd_ = clear_refs_fd_ = -1;
        alloc_base_ = nullptr; base_ = nullptr; size_ = 0;
        return false;
    }
#endif

    std::random_device rd;
    std::mt19937_64 rng(rd());
    expected_.resize(size_);
    for (size_t i = 0; i < size_; i += 8) {
        uint64_t v = rng();
        std::memcpy(&expected_[i], &v, std::min<size_t>(8, size_ - i));
    }
    // Honeypot layout: besides random noise, seed the canary with values that look like typical
    // game state (health/armor/ammo/money as int32 and float). "Scan for value, then write"
    // memory editors (Cheat Engine style) hit these first, turning a generic scan into a detection.
    {
        const int32_t ints[] = {100, 100, 30, 90, 800, 16000, 1, 0};
        const float floats[] = {100.0f, 100.0f, 1.0f, 250.0f, 0.5f};
        const size_t stride = 512;
        for (size_t off = 64; off + 64 <= size_; off += stride) {
            std::memcpy(&expected_[off], ints, sizeof(ints));
            std::memcpy(&expected_[off + sizeof(ints)], floats, sizeof(floats));
        }
    }
    std::memcpy(base_, expected_.data(), size_); // also populates every page

#if defined(_WIN32)
    tracking_supported_ = true;
#else
    // Verify soft-dirty tracking really works on this kernel using a throwaway page.
    void* probe = mmap(nullptr, ps * 3, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (probe != MAP_FAILED) {
        auto* page = static_cast<uint8_t*>(probe) + ps;
        volatile uint8_t* vpage = page;
        mprotect(page, ps, PROT_READ | PROT_WRITE);
        vpage[0] = 1;
        uint8_t* saved = base_;
        size_t savedSize = size_;
        base_ = page; size_ = ps;
        ResetTracking();
        bool cleanAfterReset = !PageWasWritten();
        vpage[0] = 2;
        bool dirtyAfterWrite = PageWasWritten();
        base_ = saved; size_ = savedSize;
        tracking_supported_ = cleanAfterReset && dirtyAfterWrite;
        munmap(probe, ps * 3);
    }
#endif
    ResetTracking();
    return true;
}

void CanaryMonitor::Shutdown() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!alloc_base_) return;
#if defined(_WIN32)
    VirtualFree(alloc_base_, 0, MEM_RELEASE);
#else
    munmap(alloc_base_, alloc_size_);
    if (pagemap_fd_ >= 0) close(pagemap_fd_);
    if (clear_refs_fd_ >= 0) close(clear_refs_fd_);
    pagemap_fd_ = clear_refs_fd_ = -1;
#endif
    alloc_base_ = nullptr;
    base_ = nullptr;
    size_ = 0;
    expected_.clear();
    tracking_supported_ = false;
}

void CanaryMonitor::ResetTracking() {
#if defined(_WIN32)
    if (base_) ResetWriteWatch(base_, size_);
#else
    // "4" clears the soft-dirty bit of every PTE in this process.
    if (clear_refs_fd_ >= 0) {
        ssize_t r = write(clear_refs_fd_, "4\n", 2);
        (void)r;
    }
#endif
}

bool CanaryMonitor::PageWasWritten() {
    if (!base_ || size_ == 0) return false;
#if defined(_WIN32)
    PVOID addrs[64];
    ULONG_PTR count = 64;
    DWORD granularity = 0;
    if (GetWriteWatch(0, base_, size_, addrs, &count, &granularity) == 0) {
        return count > 0;
    }
    return false;
#else
    int fd = pagemap_fd_;
    if (fd < 0) return false;
    const size_t ps = PageSize();
    bool dirty = false;
    for (size_t off = 0; off < size_ && !dirty; off += ps) {
        uint64_t entry = 0;
        off_t idx = static_cast<off_t>((reinterpret_cast<uintptr_t>(base_) + off) / ps * sizeof(uint64_t));
        if (pread(fd, &entry, sizeof(entry), idx) == static_cast<ssize_t>(sizeof(entry))) {
            dirty = (entry >> 55) & 1ULL; // bit 55: soft-dirty
        }
    }
    return dirty;
#endif
}

std::vector<core::DetectionEvent> CanaryMonitor::Check() {
    std::vector<core::DetectionEvent> events;
    std::lock_guard<std::mutex> lock(mutex_);
    if (!base_) return events;

    bool contentChanged = std::memcmp(base_, expected_.data(), size_) != 0;
    bool written = tracking_supported_ && PageWasWritten();

    if (contentChanged || written) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::CANARY_TAMPERED;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "CanaryMonitor";
        std::ostringstream ss;
        ss << "Write to tripwire memory that no legitimate code touches ("
           << (contentChanged ? "content modified" : "page write-tracking flagged")
           << ") - external process memory write suspected";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 90;
        events.push_back(ev);

        // Restore pristine content so a repeated write is detected again
        std::memcpy(base_, expected_.data(), size_);
    }

    ResetTracking();

    // Close the check/reset window: a content-changing write that landed after PageWasWritten()
    // but before the soft-dirty reset would otherwise be forgotten.
    if (events.empty() && std::memcmp(base_, expected_.data(), size_) != 0) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::CANARY_TAMPERED;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "CanaryMonitor";
        ev.details = "Write to tripwire memory that no legitimate code touches (content modified) - "
                     "external process memory write suspected";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 90;
        events.push_back(ev);
        std::memcpy(base_, expected_.data(), size_);
        ResetTracking();
    }
    return events;
}

} // namespace noescape::memory
