#include "noescape/memory/memory_scanner.hpp"
#include "noescape/core/obfuscation.hpp"
#include "noescape/core/envutil.hpp"
#include <fstream>
#include <sstream>
#include <iostream>
#include <ctime>
#include <iomanip>
#include <cstring>
#include <algorithm>
#include <atomic>
#include <climits>
#include <set>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <csignal>
#include <csetjmp>
#include <pthread.h>
#include <sys/mman.h>
#include <elf.h>
#endif

namespace noescape::memory {

namespace {
#if !defined(_WIN32)
    thread_local sigjmp_buf g_scanJmpBuf;
    thread_local volatile sig_atomic_t g_scanActive = 0;

    static struct sigaction g_oldSegv{};
    static struct sigaction g_oldBus{};
    static std::atomic<bool> g_guardInstalled{false};
    static std::mutex g_scanGuardMutex;

    void ScanSigHandler(int sig, siginfo_t* info, void* ucontext) {
        if (g_scanActive) {
            g_scanActive = 0;
            siglongjmp(g_scanJmpBuf, 1);
        }
        if (sig == SIGSEGV && g_guardInstalled.load(std::memory_order_acquire)) {
            if ((g_oldSegv.sa_flags & SA_SIGINFO) && g_oldSegv.sa_sigaction) {
                g_oldSegv.sa_sigaction(sig, info, ucontext);
                return;
            } else if (g_oldSegv.sa_handler == SIG_IGN) {
                return;
            } else if (g_oldSegv.sa_handler && g_oldSegv.sa_handler != SIG_DFL) {
                g_oldSegv.sa_handler(sig);
                return;
            }
        } else if (sig == SIGBUS && g_guardInstalled.load(std::memory_order_acquire)) {
            if ((g_oldBus.sa_flags & SA_SIGINFO) && g_oldBus.sa_sigaction) {
                g_oldBus.sa_sigaction(sig, info, ucontext);
                return;
            } else if (g_oldBus.sa_handler == SIG_IGN) {
                return;
            } else if (g_oldBus.sa_handler && g_oldBus.sa_handler != SIG_DFL) {
                g_oldBus.sa_handler(sig);
                return;
            }
        }
        struct sigaction dfl{};
        dfl.sa_handler = SIG_DFL;
        sigemptyset(&dfl.sa_mask);
        sigaction(sig, &dfl, nullptr);
        raise(sig);
    }

    struct SafeScanGuard {
        std::unique_lock<std::mutex> lock;
        bool segvInstalled{false};
        bool busInstalled{false};

        SafeScanGuard() : lock(g_scanGuardMutex) {
            // Keep SA_ONSTACK if the host (JVM, Go, Mono, crash reporters) uses an alternate signal
            // stack, otherwise stack-overflow faults could no longer be handled.
            struct sigaction cur{};
            struct sigaction sa{};
            sa.sa_sigaction = ScanSigHandler;
            sigemptyset(&sa.sa_mask);
            sa.sa_flags = SA_SIGINFO;
            if (sigaction(SIGSEGV, nullptr, &cur) == 0) sa.sa_flags |= (cur.sa_flags & SA_ONSTACK);
            if (sigaction(SIGSEGV, &sa, &g_oldSegv) == 0) {
                segvInstalled = true;
            }
            sa.sa_flags = SA_SIGINFO;
            if (sigaction(SIGBUS, nullptr, &cur) == 0) sa.sa_flags |= (cur.sa_flags & SA_ONSTACK);
            if (sigaction(SIGBUS, &sa, &g_oldBus) == 0) {
                busInstalled = true;
            }
            if (segvInstalled || busInstalled) {
                g_guardInstalled.store(true, std::memory_order_release);
            }
        }

        ~SafeScanGuard() {
            g_guardInstalled.store(false, std::memory_order_release);
            if (segvInstalled) {
                sigaction(SIGSEGV, &g_oldSegv, nullptr);
            }
            if (busInstalled) {
                sigaction(SIGBUS, &g_oldBus, nullptr);
            }
            g_scanActive = 0;
        }
    };
#endif

static bool ScanChunkSafe(uintptr_t chunkStart,
                          size_t chunkSize,
                          const std::vector<const CheatSignature*>& applicable,
                          std::vector<PatternScanner::SignatureMatchResult>& outMatches) {
#if !defined(_WIN32)
    static const size_t pageSize = []() {
        long sz = sysconf(_SC_PAGESIZE);
        return (sz > 0) ? static_cast<size_t>(sz) : 4096UL;
    }();
    uintptr_t pageMask = ~(pageSize - 1);
    uintptr_t pageStart = chunkStart & pageMask;
    size_t span = ((chunkStart + chunkSize - pageStart) + pageSize - 1) & pageMask;

    // One mincore() over the whole chunk: fails if any page is unmapped (region changed under
    // us) and tells us which pages are resident. Non-resident pages are either never-touched
    // reservations (reads as zeros) or swapped out: skip them at page granularity instead of
    // faulting in megabytes of zero pages.
    thread_local std::vector<unsigned char> residency;
    const size_t numPages = span / pageSize;
    residency.assign(numPages, 0);
    if (mincore(reinterpret_cast<void*>(pageStart), span, residency.data()) != 0) {
        return false;
    }
    outMatches.clear();
    bool anyResident = false;
    for (unsigned char v : residency) {
        if (v & 1) { anyResident = true; break; }
    }
    if (!anyResident) {
        return true;
    }

    if (sigsetjmp(g_scanJmpBuf, 1) != 0) {
        g_scanActive = 0;
        return false;
    }
    g_scanActive = 1;
    const uintptr_t chunkEnd = chunkStart + chunkSize;
    size_t p = 0;
    while (p < numPages && outMatches.size() < 16) {
        while (p < numPages && (residency[p] & 1) == 0) ++p;
        if (p >= numPages) break;
        size_t runEndPage = p + 1;
        while (runEndPage < numPages && (residency[runEndPage] & 1) != 0) ++runEndPage;

        uintptr_t runStart = std::max(chunkStart, pageStart + p * pageSize);
        uintptr_t runEnd = std::min(chunkEnd, pageStart + runEndPage * pageSize);
        if (runEnd > runStart) {
            auto subMatches = PatternScanner::ScanSignatures(
                reinterpret_cast<const uint8_t*>(runStart),
                runEnd - runStart,
                applicable,
                runStart,
                16 - outMatches.size()
            );
            outMatches.insert(outMatches.end(), subMatches.begin(), subMatches.end());
        }
        p = runEndPage;
    }
    g_scanActive = 0;
    return true;
#else
    // Windows: never dereference foreign pages directly. Copy the chunk with ReadProcessMemory,
    // which fails cleanly on decommitted/guard/no-access pages instead of faulting (and needs no
    // compiler-specific SEH, which also cannot be mixed with C++ object unwinding).
    thread_local std::vector<uint8_t> copyBuf;
    if (copyBuf.size() < chunkSize) copyBuf.resize(chunkSize);
    SIZE_T got = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(chunkStart), copyBuf.data(), chunkSize, &got) ||
        got != chunkSize) {
        return false;
    }
    outMatches = PatternScanner::ScanSignatures(copyBuf.data(), chunkSize, applicable, chunkStart, 16);
    return true;
#endif
}

} // namespace

MemoryScanner& MemoryScanner::Instance() {
    static MemoryScanner* instance = new MemoryScanner();
    return *instance;
}

void MemoryScanner::RefreshCache() {
    auto regions = QueryMemoryRegionsInternal();
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cached_regions_ = std::move(regions);
    cache_valid_ = true;
    ++cache_users_;
}

void MemoryScanner::ClearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    // Reference counted: only the last concurrent audit actually drops the snapshot
    if (cache_users_ > 0) --cache_users_;
    if (cache_users_ == 0) {
        cached_regions_.clear();
        cache_valid_ = false;
    }
}

bool MemoryScanner::IsCacheValid() const {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    return cache_valid_;
}

std::vector<MemoryRegion> MemoryScanner::QueryMemoryRegions(bool force_refresh) {
    if (!force_refresh) {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        if (cache_valid_) {
            return cached_regions_;
        }
    }

    auto regions = QueryMemoryRegionsInternal();

    {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        if (cache_valid_) {
            cached_regions_ = regions;
        }
    }

    return regions;
}

std::vector<MemoryRegion> MemoryScanner::QueryMemoryRegionsInternal() {
    std::vector<MemoryRegion> regions;

#if defined(_WIN32)
    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);

    uint8_t* p = static_cast<uint8_t*>(sysInfo.lpMinimumApplicationAddress);
    uint8_t* maxAddr = static_cast<uint8_t*>(sysInfo.lpMaximumApplicationAddress);

    while (p < maxAddr) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) {
            p += 0x1000;
            continue;
        }

        if (mbi.State == MEM_COMMIT) {
            MemoryRegion reg;
            reg.start = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
            reg.size = mbi.RegionSize;
            reg.end = reg.start + reg.size;

            const bool inaccessible = (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)) != 0;
            reg.readable = !inaccessible &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            reg.writable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
            reg.executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            reg.is_shared = (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE);

            // Image/mapped sections are file-backed by definition; the name is informational
            // (wide API: ANSI mangles non-ASCII paths).
            wchar_t filePathW[MAX_PATH * 2]{};
            if (GetMappedFileNameW(GetCurrentProcess(), mbi.BaseAddress, filePathW, MAX_PATH * 2) > 0) {
                char utf8[MAX_PATH * 4]{};
                WideCharToMultiByte(CP_UTF8, 0, filePathW, -1, utf8, sizeof(utf8), nullptr, nullptr);
                reg.pathname = utf8;
            } else if (mbi.Type == MEM_IMAGE) {
                reg.pathname = "<image>";
            }
            reg.is_backed_by_file = (mbi.Type == MEM_IMAGE || mbi.Type == MEM_MAPPED);

            regions.push_back(reg);
        }

        p = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
    }

#else
    // Linux: Parse /proc/self/maps
    std::ifstream mapsFile(NOESCAPE_XOR("/proc/self/maps"));
    if (!mapsFile.is_open()) return regions;

    std::string line;
    while (std::getline(mapsFile, line)) {
        if (line.empty()) continue;

        // Example line:
        // 7f814b7e9000-7f814b80b000 r-xp 00000000 08:01 123456 /usr/lib/libc.so.6
        uintptr_t start = 0, end = 0;
        char dash = 0;
        std::string perms, offsetStr, devStr;
        uint64_t inode = 0;
        std::string pathname;

        std::istringstream iss(line);
        if (!(iss >> std::hex >> start >> dash >> end >> perms >> offsetStr >> devStr >> std::dec >> inode)) {
            continue;
        }

        // The remaining text in the line is the pathname (if any)
        std::string remainder;
        if (std::getline(iss, remainder)) {
            size_t firstNonSpace = remainder.find_first_not_of(" \t");
            if (firstNonSpace != std::string::npos) {
                pathname = remainder.substr(firstNonSpace);
            }
        }

        MemoryRegion reg;
        reg.start = start;
        reg.end = end;
        reg.size = (end >= start) ? (end - start) : 0;
        reg.readable = (perms.length() > 0 && perms[0] == 'r');
        reg.writable = (perms.length() > 1 && perms[1] == 'w');
        reg.executable = (perms.length() > 2 && perms[2] == 'x');
        reg.is_shared = (perms.length() > 3 && perms[3] == 's');
        reg.pathname = pathname;
        try { reg.file_offset = std::stoull(offsetStr, nullptr, 16); } catch (...) { reg.file_offset = 0; }
        reg.is_backed_by_file = (inode > 0 && !pathname.empty() && pathname[0] == '/');

        regions.push_back(reg);
    }
#endif

    return regions;
}

bool MemoryScanner::IsJitRuntime(const std::vector<MemoryRegion>& regions) const {
    bool isJitRuntime = HostUsesJit();
#if !defined(_WIN32)
    char exePathBuf[PATH_MAX]{};
    ssize_t exeLen = readlink(NOESCAPE_XOR("/proc/self/exe"), exePathBuf, sizeof(exePathBuf) - 1);
    if (exeLen > 0) {
        exePathBuf[exeLen] = '\0';
        std::string exeStr(exePathBuf);
        size_t sl = exeStr.find_last_of('/');
        std::string base = (sl == std::string::npos) ? exeStr : exeStr.substr(sl + 1);
        std::transform(base.begin(), base.end(), base.begin(), ::tolower);
        for (const char* rt : {"java", "mono", "node", "dotnet"}) {
            if (base.rfind(rt, 0) == 0) { isJitRuntime = true; break; }
        }
    }
#endif
    auto isTransientPath = [](const std::string& p) {
        return p.rfind("/tmp", 0) == 0 || p.rfind("/dev/shm", 0) == 0 || p.rfind("/var/tmp", 0) == 0 ||
               p.rfind("memfd:", 0) == 0 || p.find("(deleted)") != std::string::npos;
    };
    for (const auto& r : regions) {
        if (!r.is_backed_by_file || r.pathname.empty() || r.pathname[0] != '/' || isTransientPath(r.pathname)) continue;
        size_t sl = r.pathname.find_last_of('/');
        std::string base = r.pathname.substr(sl + 1);
        if (base.rfind("libjvm.so", 0) == 0 || base.rfind("libmono", 0) == 0 ||
            base.rfind("libv8", 0) == 0 || base.rfind("libcoreclr", 0) == 0) {
            isJitRuntime = true;
            break;
        }
    }
#if defined(NOESCAPE_SECURE_BUILD) || defined(NDEBUG)
    const char* testEnv = std::getenv("NOESCAPE_TEST_MODE");
    if (testEnv && core::EnvFlagTrue(testEnv)) {
        const char* allowJitEnv = std::getenv("NOESCAPE_ALLOW_JIT");
        if (allowJitEnv && core::EnvFlagTrue(allowJitEnv)) {
            isJitRuntime = true;
        }
    }
#else
    const char* allowJitEnv = std::getenv("NOESCAPE_ALLOW_JIT");
    if (allowJitEnv && core::EnvFlagTrue(allowJitEnv)) {
        isJitRuntime = true;
    }
#endif

    return isJitRuntime;
}

std::vector<core::DetectionEvent> MemoryScanner::DetectUnbackedExecutableRegions() {
    std::vector<core::DetectionEvent> events;
    auto regions = QueryMemoryRegions();

    // Check if host process is a JIT runtime (such as Java JVM / HotSpot or explicitly enabled JIT).
    // In Java/Minecraft, HotSpot allocates anonymous executable memory for its JIT CodeCache.
    const bool isJitRuntime = IsJitRuntime(regions);

    for (const auto& r : regions) {
        if (!r.executable) continue;
        if (r.pathname == "[vsyscall]" || r.pathname == "[vdso]") continue;

        bool suspicious = false;
        bool transientOnly = false; // /tmp-hosted file: weaker signal (devs and installers run from there)
        std::string reason;

        // Condition 1: Executable region not backed by any valid file
        // In JIT runtimes (Java/Minecraft JVM CodeCache), anonymous executable memory is normal.
        if (!r.is_backed_by_file) {
            if (!isJitRuntime) {
                suspicious = true;
                reason = "Anonymous unbacked executable memory segment";
            }
        }
        // Condition 2: File is marked (deleted) on disk
        else if (r.pathname.find("(deleted)") != std::string::npos) {
            // Whitelist legitimate runtime temp extraction such as JNA, LWJGL, Netty, Tracy
            // used by Minecraft / Fabric: /tmp/*.so (deleted) or ~/.cache/JNA/temp/jna*.tmp (deleted)
            bool isLegitRuntimeTemp = (isJitRuntime && (
                r.pathname.find("jna") != std::string::npos ||
                r.pathname.find("JNA") != std::string::npos ||
                r.pathname.find("libjnidispatch") != std::string::npos ||
                r.pathname.find("lwjgl") != std::string::npos ||
                r.pathname.find("glfw") != std::string::npos ||
                r.pathname.find("openal") != std::string::npos ||
                r.pathname.find("jemalloc") != std::string::npos ||
                r.pathname.find("freetype") != std::string::npos ||
                r.pathname.find("tinyfd") != std::string::npos ||
                r.pathname.find("stb") != std::string::npos ||
                r.pathname.find("netty") != std::string::npos ||
                r.pathname.find("tracy") != std::string::npos
            ));
            bool benignDeleted = r.pathname.find("memfd:libffi") != std::string::npos ||
                                 r.pathname.find("memfd:doublemapper") != std::string::npos ||
                                 r.pathname.find("/dev/zero") != std::string::npos;
            if (!isLegitRuntimeTemp && !benignDeleted) {
                suspicious = true;
                reason = "Executable mapped from unlinked/deleted binary: " + r.pathname;
            }
        }
        // Condition 3: Executable region located in /dev/shm, /tmp, or memfd
        else if (r.pathname.rfind("/dev/shm", 0) == 0 || 
                 r.pathname.rfind("/tmp", 0) == 0 ||
                 r.pathname.rfind("memfd:", 0) == 0) {
            bool isLegitRuntimeTemp = (isJitRuntime && (
                r.pathname.find("jna") != std::string::npos ||
                r.pathname.find("JNA") != std::string::npos ||
                r.pathname.find("libjnidispatch") != std::string::npos ||
                r.pathname.find("lwjgl") != std::string::npos ||
                r.pathname.find("glfw") != std::string::npos ||
                r.pathname.find("openal") != std::string::npos ||
                r.pathname.find("jemalloc") != std::string::npos ||
                r.pathname.find("freetype") != std::string::npos ||
                r.pathname.find("tinyfd") != std::string::npos ||
                r.pathname.find("stb") != std::string::npos ||
                r.pathname.find("netty") != std::string::npos ||
                r.pathname.find("tracy") != std::string::npos
            ));
            // libffi closures, JVM code-cache double mapping and Mesa/Wine JIT legitimately use memfd
            bool benignMemfd = r.pathname.rfind("memfd:", 0) == 0 &&
                (r.pathname.find("libffi") != std::string::npos ||
                 r.pathname.find("doublemapper") != std::string::npos ||
                 r.pathname.find("mesa") != std::string::npos ||
                 r.pathname.find("wine") != std::string::npos ||
                 r.pathname.find("jit") != std::string::npos);
            if (!isLegitRuntimeTemp && !benignMemfd) {
                suspicious = true;
                transientOnly = (r.pathname.rfind("/tmp", 0) == 0 || r.pathname.rfind("/var/tmp", 0) == 0);
                reason = "Executable payload residing in transient/volatile memory mount: " + r.pathname;
            }
        }
        // Condition 4: Executable stack or heap
        else if (r.pathname == "[stack]" || r.pathname == "[heap]") {
            suspicious = true;
            reason = "Executable stack/heap anomaly detected (W^X violation): " + r.pathname;
        }
        // Condition 5: File-backed executable section marked RWX (Module Stomping)
        else if (r.is_backed_by_file && r.executable && r.writable) {
            suspicious = true;
            reason = "File-backed executable section marked RWX (Module Stomping / In-memory patch): " + r.pathname;
        }

        if (suspicious) {
            // Also elevate severity if region is simultaneously Writable + Executable (RWX)
            bool isRwx = r.writable && r.executable;

            core::DetectionEvent ev;
            ev.type = core::DetectionType::UNBACKED_EXECUTABLE_MEMORY;
            ev.severity = isRwx ? core::Severity::FATAL_BAN
                                : (transientOnly ? core::Severity::MEDIUM : core::Severity::HIGH);
            ev.component = "MemoryScanner::UnbackedPages";
            ev.details = reason + " [0x" + [] (uintptr_t v) {
                std::ostringstream ss;
                ss << std::hex << v;
                return ss.str();
            }(r.start) + " - 0x" + [] (uintptr_t v) {
                std::ostringstream ss;
                ss << std::hex << v;
                return ss.str();
            }(r.end) + "] " + (isRwx ? "(RWX-PROTECTION)" : "(RX-PROTECTION)");
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
            ev.threat_score = isRwx ? 100 : (transientOnly ? 40 : 75);

            events.push_back(ev);
        }
    }

    return events;
}

std::vector<core::DetectionEvent> MemoryScanner::ScanSignatures(const std::vector<CheatSignature>& signatures) {
    std::vector<core::DetectionEvent> events;
    if (signatures.empty()) return events;

    // Collect internal memory spans occupied by signature database structures to prevent
    // false positives against the anti-cheat's own data in heap / anonymous allocations.
    auto internalSpans = SignatureDatabase::GetInternalSpans();
    if (!signatures.empty()) {
        uintptr_t vecStart = reinterpret_cast<uintptr_t>(signatures.data());
        uintptr_t vecEnd = vecStart + signatures.size() * sizeof(CheatSignature);
        internalSpans.emplace_back(vecStart, vecEnd);
        for (const auto& sig : signatures) {
            uintptr_t objStart = reinterpret_cast<uintptr_t>(&sig);
            internalSpans.emplace_back(objStart, objStart + sizeof(CheatSignature));
            if (!sig.GetName().empty()) {
                uintptr_t s = reinterpret_cast<uintptr_t>(sig.GetName().data());
                internalSpans.emplace_back(s, s + sig.GetName().size() + 1);
            }
            if (!sig.GetDescription().empty()) {
                uintptr_t s = reinterpret_cast<uintptr_t>(sig.GetDescription().data());
                internalSpans.emplace_back(s, s + sig.GetDescription().size() + 1);
            }
            if (!sig.GetBytes().empty()) {
                uintptr_t s = reinterpret_cast<uintptr_t>(sig.GetBytes().data());
                internalSpans.emplace_back(s, s + sig.GetBytes().size() * sizeof(PatternByte));
            }
        }
    }

#if !defined(_WIN32)
    pthread_attr_t threadAttr{};
    if (pthread_getattr_np(pthread_self(), &threadAttr) == 0) {
        void* stackAddr = nullptr;
        size_t stackSize = 0;
        if (pthread_attr_getstack(&threadAttr, &stackAddr, &stackSize) == 0 && stackAddr) {
            uintptr_t s = reinterpret_cast<uintptr_t>(stackAddr);
            internalSpans.emplace_back(s, s + stackSize);
        }
        pthread_attr_destroy(&threadAttr);
    }
#else
    ULONG_PTR lowLimit = 0, highLimit = 0;
    GetCurrentThreadStackLimits(&lowLimit, &highLimit);
    if (lowLimit && highLimit) {
        internalSpans.emplace_back(static_cast<uintptr_t>(lowLimit), static_cast<uintptr_t>(highLimit));
    }
#endif

    auto regions = QueryMemoryRegions();
    // JIT engines legitimately emit "mov rax, imm64; jmp rax"-style stubs into anonymous code
    const bool jitHost = IsJitRuntime(regions);

#if !defined(_WIN32)
    SafeScanGuard safeGuard;
#endif

    size_t budget = 0;
    uintptr_t cursor = 0;
    {
        std::lock_guard<std::mutex> l(state_mutex_);
        budget = scan_budget_bytes_;
        cursor = scan_cursor_;
    }
    size_t scannedBytes = 0;
    bool budgetExhausted = false;
    uintptr_t nextCursor = 0;

    for (const auto& r : regions) {
        if (budgetExhausted) break;
        // Incremental mode: resume where the previous (budget-limited) pass stopped
        if (budget && r.end <= cursor) continue;
        // Skip special kernel mapped regions, device memory, or unreadable/empty segments
        if (!r.readable || r.size == 0) continue;
        // Multi-GiB anonymous reservations (sanitizer shadow, emulator/JIT address-space
        // reservations) are not real memory; scanning them would take minutes.
        if (!r.is_backed_by_file && r.size > (64ull << 30)) continue;
        if (r.pathname.rfind("[vvar", 0) == 0 || r.pathname == "[vsyscall]" || 
            r.pathname == "[vectors]" || r.pathname == "[vdso]") continue;
        if (r.pathname.rfind("/dev/", 0) == 0) continue;
        // Non-executable heap and thread stacks contain normal runtime allocations, local variables,
        // and string tables. Skip non-executable heap/stack regions to eliminate false positives.
        if (!r.executable && (r.pathname == "[heap]" || r.pathname.rfind("[stack", 0) == 0)) continue;

#if defined(_WIN32)
        // Windows paths are NT device paths ("\\Device\\HarddiskVolume3\\..."), never "/..."
        const bool genuineFile = r.is_backed_by_file;
#else
        const bool genuineFile = r.is_backed_by_file && !r.pathname.empty() && r.pathname[0] == '/' &&
                                 r.pathname.find("(deleted)") == std::string::npos;
#endif

        // Filter signatures that are applicable to this region based on its memory target rule
        std::vector<const CheatSignature*> applicable;
        applicable.reserve(signatures.size());
        for (const auto& sig : signatures) {
            if (CheatSignature::IsTargetMatched(sig.GetTargetRule(), genuineFile, r.executable, r.readable)) {
                applicable.push_back(&sig);
            }
        }
        if (applicable.empty()) continue;

        // Chunk large memory blocks into safe segments (8MB) to prevent cheats hiding in >32MB allocations
        constexpr size_t kChunkSize = 8 * 1024 * 1024; // 8 MB safe chunk size
        constexpr size_t kOverlap = 4096;              // 4 KB page overlap to guarantee boundary signatures are detected

        size_t offset = 0;
        if (budget && cursor > r.start && cursor < r.end) {
            offset = static_cast<size_t>(cursor - r.start) & ~static_cast<size_t>(4095);
        }
        std::set<std::pair<uintptr_t, const CheatSignature*>> seenMatches;

        while (offset < r.size) {
            if (budget && scannedBytes >= budget) {
                budgetExhausted = true;
                nextCursor = r.start + offset;
                break;
            }
            size_t currentChunkSize = std::min(kChunkSize, r.size - offset);
            uintptr_t chunkStart = r.start + offset;

            {
                std::function<void()> cb;
                { std::lock_guard<std::mutex> l(cache_mutex_); cb = progress_cb_; }
                if (cb) cb();
            }
            std::vector<PatternScanner::SignatureMatchResult> matches;
            scannedBytes += currentChunkSize;
            if (!ScanChunkSafe(chunkStart, currentChunkSize, applicable, matches)) {
                if (currentChunkSize <= kOverlap || offset + currentChunkSize >= r.size) break;
                offset += (currentChunkSize - kOverlap);
                continue;
            }

            for (const auto& match : matches) {
                if (!match.signature) continue;
                const auto& sig = *match.signature;

                // Deduplicate matches that fall in chunk overlap boundary
                if (!seenMatches.insert({match.address, match.signature}).second) {
                    continue;
                }

                // Discard any match that falls within the anti-cheat's own signature table memory
                bool isSelfMatch = false;
                for (const auto& span : internalSpans) {
                    if (match.address < span.second && (match.address + sig.Length()) > span.first) {
                        isSelfMatch = true;
                        break;
                    }
                }
                if (isSelfMatch) continue;

                core::DetectionEvent ev;
                ev.type = core::DetectionType::MEMORY_SIGNATURE_MATCH;
                ev.severity = sig.GetSeverity();
                ev.threat_score = sig.GetThreatScore();
                if (jitHost && !genuineFile && r.executable &&
                    (sig.GetCategory() == SignatureCategory::HOOK_FRAMEWORK ||
                     sig.GetCategory() == SignatureCategory::SHELLCODE_PROLOGUE)) {
                    ev.severity = core::Severity::MEDIUM;
                    ev.threat_score = std::min<uint32_t>(ev.threat_score, 25);
                }
                ev.component = std::string("MemoryScanner::") + CheatSignature::CategoryToString(sig.GetCategory());

                std::ostringstream ss;
                ss << "[" << CheatSignature::CategoryToString(sig.GetCategory()) << "] "
                   << "Blacklisted signature matched: " << sig.GetName()
                   << " at address 0x" << std::hex << match.address
                   << " (Region: " << (r.pathname.empty() ? "[anon]" : r.pathname) << ")";
                if (!sig.GetDescription().empty()) {
                    ss << " - " << sig.GetDescription();
                }
                ev.details = ss.str();
                ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
                events.push_back(ev);
            }

            if (currentChunkSize <= kOverlap || offset + currentChunkSize >= r.size) {
                break;
            }
            offset += (currentChunkSize - kOverlap);
        }
    }

    if (budget) {
        std::lock_guard<std::mutex> l(state_mutex_);
        scan_cursor_ = budgetExhausted ? nextCursor : 0; // wrap around after a full pass
    }
    return events;
}

void MemoryScanner::SetScanBudget(size_t bytes_per_pass) {
    std::lock_guard<std::mutex> l(state_mutex_);
    scan_budget_bytes_ = bytes_per_pass;
    scan_cursor_ = 0;
}

std::vector<core::DetectionEvent> MemoryScanner::ScanSignatures(const std::vector<Pattern>& patterns) {
    if (patterns.empty()) return {};
    std::vector<CheatSignature> sigs;
    sigs.reserve(patterns.size());
    for (const auto& pat : patterns) {
        const std::string& n = pat.GetName();
        bool isGeneric = (n.rfind("Generic_", 0) == 0 || n.rfind("PushRet_", 0) == 0);
        sigs.emplace_back(
            pat,
            isGeneric ? SignatureCategory::HOOK_FRAMEWORK : SignatureCategory::GENERIC,
            100u,
            core::Severity::FATAL_BAN,
            isGeneric ? MemoryTargetRule::UNBACKED_ONLY : MemoryTargetRule::ALL_EXECUTABLE,
            "Legacy raw byte pattern"
        );
    }
    return ScanSignatures(sigs);
}

#if defined(__clang__) || defined(__GNUC__)
__attribute__((no_sanitize("address", "hwaddress", "thread")))
#endif
std::vector<core::DetectionEvent> MemoryScanner::DetectModifiedModules() {
    std::vector<core::DetectionEvent> events;
#if defined(_WIN32)
    std::vector<MemoryRegion> candidates;
    for (const auto& r : QueryMemoryRegions()) {
        if (!r.executable || !r.readable || !r.is_backed_by_file || r.size == 0) continue;
        if (r.size > 64u * 1024u * 1024u) continue;
        candidates.push_back(r);
    }
    if (candidates.empty()) return events;

    MemoryRegion r;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        r = candidates[module_cursor_++ % candidates.size()];
    }

    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(r.start), &mod) || !mod) {
        return events;
    }
    wchar_t widePath[MAX_PATH * 2]{};
    if (!GetModuleFileNameW(mod, widePath, MAX_PATH * 2)) return events;
    HANDLE f = CreateFileW(widePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return events;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (256ll << 20)) { CloseHandle(f); return events; }
    std::vector<uint8_t> file(static_cast<size_t>(sz.QuadPart));
    DWORD gotBytes = 0;
    bool ok = ReadFile(f, file.data(), static_cast<DWORD>(file.size()), &gotBytes, nullptr) && gotBytes == file.size();
    CloseHandle(f);
    if (!ok || file.size() < sizeof(IMAGE_DOS_HEADER)) return events;

    auto rd = [&](size_t off, size_t len) { return off + len <= file.size(); };
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || !rd(static_cast<size_t>(dos->e_lfanew), sizeof(IMAGE_NT_HEADERS64))) return events;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return events;

    const size_t secOff = static_cast<size_t>(dos->e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                          nt->FileHeader.SizeOfOptionalHeader;
    const WORD nsec = nt->FileHeader.NumberOfSections;
    if (!rd(secOff, static_cast<size_t>(nsec) * sizeof(IMAGE_SECTION_HEADER))) return events;
    auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(file.data() + secOff);

    const uint32_t regionRva = static_cast<uint32_t>(r.start - reinterpret_cast<uintptr_t>(mod));
    size_t codeOff = 0, compareLen = 0;
    for (WORD i = 0; i < nsec; ++i) {
        const auto& s = sections[i];
        const uint32_t secSize = s.Misc.VirtualSize
            ? std::min<uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData)
            : s.SizeOfRawData;
        if (regionRva >= s.VirtualAddress && regionRva < s.VirtualAddress + secSize) {
            size_t inSec = regionRva - s.VirtualAddress;
            codeOff = static_cast<size_t>(s.PointerToRawData) + inSec;
            compareLen = std::min<size_t>(r.size, static_cast<size_t>(secSize) - inSec);
            break;
        }
    }
    if (compareLen < 64 || !rd(codeOff, compareLen)) return events;

    std::vector<uint8_t> memCopy(compareLen);
    SIZE_T copied = 0;
    if (!ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(r.start), memCopy.data(), compareLen, &copied) ||
        copied != compareLen) {
        return events;
    }

    std::vector<bool> mask(compareLen, true);
    auto rvaToOff = [&](uint32_t rv, size_t len, size_t& offOut) {
        for (WORD i = 0; i < nsec; ++i) {
            const auto& s = sections[i];
            if (rv >= s.VirtualAddress && rv + len <= s.VirtualAddress + s.SizeOfRawData) {
                offOut = static_cast<size_t>(s.PointerToRawData) + (rv - s.VirtualAddress);
                return rd(offOut, len);
            }
        }
        return false;
    };
    const auto& relDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    size_t relOff = 0;
    if (relDir.VirtualAddress && relDir.Size && rvaToOff(relDir.VirtualAddress, relDir.Size, relOff)) {
        size_t p = relOff, end = relOff + relDir.Size;
        while (p + sizeof(IMAGE_BASE_RELOCATION) <= end) {
            auto blk = reinterpret_cast<const IMAGE_BASE_RELOCATION*>(file.data() + p);
            if (blk->SizeOfBlock < sizeof(IMAGE_BASE_RELOCATION) || p + blk->SizeOfBlock > end) break;
            size_t n = (blk->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            auto ent = reinterpret_cast<const WORD*>(file.data() + p + sizeof(IMAGE_BASE_RELOCATION));
            for (size_t i = 0; i < n; ++i) {
                int type = ent[i] >> 12;
                uint32_t at = blk->VirtualAddress + (ent[i] & 0x0FFF);
                size_t width = (type == IMAGE_REL_BASED_DIR64) ? 8 : (type == IMAGE_REL_BASED_HIGHLOW ? 4 : 0);
                for (size_t b = 0; b < width; ++b) {
                    uint32_t byteRva = at + static_cast<uint32_t>(b);
                    if (byteRva >= regionRva && byteRva < regionRva + compareLen) {
                        mask[byteRva - regionRva] = false;
                    }
                }
            }
            p += blk->SizeOfBlock;
        }
    }

    const uint8_t* diskPtr = file.data() + codeOff;
    size_t firstDiff = compareLen, diffCount = 0;
    for (size_t i = 0; i < compareLen; ++i) {
        if (mask[i] && memCopy[i] != diskPtr[i]) {
            if (firstDiff == compareLen) firstDiff = i;
            ++diffCount;
        }
    }
    if (diffCount > 0) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::INLINE_HOOK_DETECTED;
        ev.severity = core::Severity::HIGH;
        ev.component = "MemoryScanner::ModuleIntegrity";
        std::ostringstream ss;
        ss << "In-memory executable differs from on-disk image: " << r.pathname
           << " (" << diffCount << " bytes differ, first at +0x" << std::hex << firstDiff << ")";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 50;
        events.push_back(ev);
    }
    return events;
#else
    std::vector<MemoryRegion> candidates;
    for (const auto& r : QueryMemoryRegions()) {
        if (!r.executable || !r.readable || !r.is_backed_by_file || r.size == 0) continue;
        if (r.pathname.empty() || r.pathname[0] != '/' || r.pathname.find("(deleted)") != std::string::npos) continue;
        if (r.size > 64u * 1024u * 1024u) continue;
        candidates.push_back(r);
    }
    if (candidates.empty()) return events;

    MemoryRegion r;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        r = candidates[module_cursor_++ % candidates.size()];
    }

    std::ifstream f(r.pathname, std::ios::binary);
    if (!f.is_open()) return events;
    Elf64_Ehdr eh{};
    f.read(reinterpret_cast<char*>(&eh), sizeof(eh));
    if (f.gcount() != static_cast<std::streamsize>(sizeof(eh)) ||
        std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) {
        return events;
    }

    size_t maxCompare = r.size;
    if (eh.e_ident[EI_CLASS] == ELFCLASS64 && eh.e_phentsize >= sizeof(Elf64_Phdr) && eh.e_phnum <= 512) {
        for (uint16_t i = 0; i < eh.e_phnum; ++i) {
            Elf64_Phdr ph{};
            f.seekg(static_cast<std::streamoff>(eh.e_phoff + static_cast<uint64_t>(i) * eh.e_phentsize));
            f.read(reinterpret_cast<char*>(&ph), sizeof(ph));
            if (f.gcount() != static_cast<std::streamsize>(sizeof(ph))) break;
            if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X)) continue;
            uint64_t segPageOff = ph.p_offset & ~static_cast<uint64_t>(0xFFF);
            if (r.file_offset >= segPageOff && r.file_offset < ph.p_offset + ph.p_filesz) {
                uint64_t avail = (ph.p_offset + ph.p_filesz) - r.file_offset;
                maxCompare = std::min<size_t>(r.size, static_cast<size_t>(avail));
                break;
            }
        }
    }
    f.clear();

    std::vector<uint8_t> disk(maxCompare);
    f.seekg(static_cast<std::streamoff>(r.file_offset));
    f.read(reinterpret_cast<char*>(disk.data()), static_cast<std::streamsize>(maxCompare));
    size_t got = static_cast<size_t>(f.gcount());
    if (got < 64) return events;

    // Bytes beyond end-of-file are zero-filled by the kernel; compare only file-backed span.
    const auto* mem = reinterpret_cast<const uint8_t*>(r.start);
    size_t firstDiff = got;
    size_t diffCount = 0;
    for (size_t i = 0; i < got; ++i) {
        if (mem[i] != disk[i]) {
            if (firstDiff == got) firstDiff = i;
            ++diffCount;
        }
    }

    if (diffCount > 0) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::INLINE_HOOK_DETECTED;
        // Legitimate overlays (Steam/Discord/RTSS) patch code too: elevated score, not an instant ban.
        ev.severity = core::Severity::HIGH;
        ev.component = "MemoryScanner::ModuleIntegrity";
        std::ostringstream ss;
        ss << "In-memory executable differs from on-disk image: " << r.pathname
           << " (" << diffCount << " bytes differ, first at +0x" << std::hex << firstDiff << ")";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 50;
        events.push_back(ev);
    }
    return events;
#endif
}

std::vector<core::DetectionEvent> MemoryScanner::DetectSleepingPayloads() {
    std::vector<core::DetectionEvent> events;
    auto regions = QueryMemoryRegions();

    std::lock_guard<std::mutex> lock(state_mutex_);
    std::map<uintptr_t, uintptr_t> current;
    for (const auto& r : regions) {
        if (r.executable) current[r.start] = r.end;
    }

    for (const auto& r : regions) {
        if (r.readable || r.writable || r.executable || r.is_backed_by_file) continue;
        auto it = seen_exec_regions_.find(r.start);
        if (it == seen_exec_regions_.end()) continue;
        // Anonymous region that was executable earlier and is now fully inaccessible
        core::DetectionEvent ev;
        ev.type = core::DetectionType::UNBACKED_EXECUTABLE_MEMORY;
        ev.severity = core::Severity::HIGH;
        ev.component = "MemoryScanner::SleepingPayload";
        std::ostringstream ss;
        ss << "Previously executable anonymous region made inaccessible (sleep-obfuscation pattern) [0x"
           << std::hex << r.start << " - 0x" << r.end << "]";
        ev.details = ss.str();
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 70;
        events.push_back(ev);
    }

    for (const auto& kv : current) seen_exec_regions_[kv.first] = kv.second;
    // Drop entries whose mapping vanished entirely (munmap) to avoid stale state
    for (auto it = seen_exec_regions_.begin(); it != seen_exec_regions_.end();) {
        bool mapped = false;
        for (const auto& r : regions) if (r.start == it->first) { mapped = true; break; }
        it = mapped ? std::next(it) : seen_exec_regions_.erase(it);
    }
    return events;
}

std::vector<core::DetectionEvent> MemoryScanner::PerformAudit(const std::vector<CheatSignature>& signatures) {
    bool hadCache = IsCacheValid();
    if (!hadCache) {
        RefreshCache();
    }
    auto events = DetectUnbackedExecutableRegions();
    auto sigEvents = ScanSignatures(signatures);
    events.insert(events.end(), sigEvents.begin(), sigEvents.end());
    auto modEvents = DetectModifiedModules();
    events.insert(events.end(), modEvents.begin(), modEvents.end());
    auto sleepEvents = DetectSleepingPayloads();
    events.insert(events.end(), sleepEvents.begin(), sleepEvents.end());
    if (!hadCache) {
        ClearCache();
    }
    return events;
}

std::vector<core::DetectionEvent> MemoryScanner::PerformAudit(const std::vector<Pattern>& patterns) {
    bool hadCache = IsCacheValid();
    if (!hadCache) {
        RefreshCache();
    }
    auto events = DetectUnbackedExecutableRegions();
    auto sigEvents = ScanSignatures(patterns);
    events.insert(events.end(), sigEvents.begin(), sigEvents.end());
    auto modEvents = DetectModifiedModules();
    events.insert(events.end(), modEvents.begin(), modEvents.end());
    auto sleepEvents = DetectSleepingPayloads();
    events.insert(events.end(), sleepEvents.begin(), sleepEvents.end());
    if (!hadCache) {
        ClearCache();
    }
    return events;
}

std::vector<core::DetectionEvent> MemoryScanner::PerformAudit() {
    return PerformAudit(GetDefaultCheatSignatures());
}

std::vector<CheatSignature> MemoryScanner::GetDefaultCheatSignatures() {
    return SignatureDatabase::GetAllSignatures();
}

std::vector<Pattern> MemoryScanner::GetDefaultCheatPatterns() {
    return SignatureDatabase::ToPatterns(SignatureDatabase::GetAllSignatures());
}

} // namespace noescape::memory
