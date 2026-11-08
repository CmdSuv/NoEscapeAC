#include "noescape/memory/memory_scanner.hpp"
#include "noescape/core/obfuscation.hpp"
#include "noescape/core/envutil.hpp"
#include "noescape/network/crypto_util.hpp"
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
#include <filesystem>
#include <chrono>
#include <thread>

#if defined(_WIN32)
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <wintrust.h>
#include <softpub.h>
#else
#include <unistd.h>
#include <sys/types.h>
#include <csignal>
#include <csetjmp>
#include <pthread.h>
#include <sys/mman.h>
#include <elf.h>
#include <sys/uio.h>
#include <sys/syscall.h>
#include <ucontext.h>
#endif

namespace noescape::memory {

namespace {
#if !defined(_WIN32)
static std::atomic<uint32_t> g_targetTid{0};
static std::atomic<uintptr_t> g_capturedRip{0};
static std::atomic<uintptr_t> g_capturedRsp{0};
static std::atomic<bool> g_captureDone{false};
static std::mutex g_signalCaptureMutex;
static struct sigaction g_oldUrg{};
static std::atomic<bool> g_urgOldInstalled{false};

static void ThreadProvenanceSignalHandler(int sig, siginfo_t* info, void* uctx) {
    if (uctx) {
        pid_t curTid = static_cast<pid_t>(syscall(SYS_gettid));
        if (curTid == static_cast<pid_t>(g_targetTid.load(std::memory_order_acquire))) {
            auto* uc = reinterpret_cast<ucontext_t*>(uctx);
#if defined(__x86_64__)
            g_capturedRip.store(static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RIP]), std::memory_order_release);
            g_capturedRsp.store(static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_RSP]), std::memory_order_release);
#elif defined(__i386__)
            g_capturedRip.store(static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_EIP]), std::memory_order_release);
            g_capturedRsp.store(static_cast<uintptr_t>(uc->uc_mcontext.gregs[REG_ESP]), std::memory_order_release);
#endif
            g_captureDone.store(true, std::memory_order_release);
            return;
        }
    }
    if (g_urgOldInstalled.load(std::memory_order_acquire)) {
        if ((g_oldUrg.sa_flags & SA_SIGINFO) && g_oldUrg.sa_sigaction) {
            g_oldUrg.sa_sigaction(sig, info, uctx);
        } else if (g_oldUrg.sa_handler && g_oldUrg.sa_handler != SIG_DFL && g_oldUrg.sa_handler != SIG_IGN) {
            g_oldUrg.sa_handler(sig);
        }
    }
}

static void EnsureThreadSignalHandlerInstalled() {
    static std::once_flag flag;
    std::call_once(flag, []() {
        struct sigaction sa{};
        sa.sa_sigaction = ThreadProvenanceSignalHandler;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = SA_SIGINFO | SA_RESTART;
        if (sigaction(SIGURG, &sa, &g_oldUrg) == 0) {
            g_urgOldInstalled.store(true, std::memory_order_release);
        }
    });
}
#endif

static bool ScanChunkSafe(uintptr_t chunkStart,
                          size_t chunkSize,
                          const std::vector<const CheatSignature*>& applicable,
                          std::vector<PatternScanner::SignatureMatchResult>& outMatches) {
#if !defined(_WIN32)
    thread_local std::vector<uint8_t> localBuf;
    if (localBuf.size() < chunkSize) localBuf.resize(chunkSize);
    struct iovec local_iov { localBuf.data(), chunkSize };
    struct iovec remote_iov { reinterpret_cast<void*>(chunkStart), chunkSize };
    ssize_t nread = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
    if (nread <= 0) {
        return false;
    }
    size_t validBytes = static_cast<size_t>(nread);
    outMatches = PatternScanner::ScanSignatures(localBuf.data(), validBytes, applicable, chunkStart, 16);
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
            break;
        }
        if (mbi.RegionSize == 0) {
            break;
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

        uint8_t* nextP = static_cast<uint8_t*>(mbi.BaseAddress) + mbi.RegionSize;
        if (nextP <= p) {
            break;
        }
        p = nextP;
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
#if defined(_WIN32)
    char exePathBuf[MAX_PATH]{};
    DWORD exeLen = GetModuleFileNameA(NULL, exePathBuf, sizeof(exePathBuf));
    if (exeLen > 0) {
        std::string exeStr(exePathBuf);
        size_t sl = exeStr.find_last_of("\\/");
        std::string base = (sl == std::string::npos) ? exeStr : exeStr.substr(sl + 1);
        std::transform(base.begin(), base.end(), base.begin(), ::tolower);
        for (const char* rt : {"java", "mono", "node", "dotnet"}) {
            if (base.rfind(rt, 0) == 0) { isJitRuntime = true; break; }
        }
    }
#else
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
        if (!r.is_backed_by_file || r.pathname.empty() || isTransientPath(r.pathname)) continue;
        size_t sl = r.pathname.find_last_of("\\/");
        std::string base = (sl == std::string::npos) ? r.pathname : r.pathname.substr(sl + 1);
        std::transform(base.begin(), base.end(), base.begin(), ::tolower);
        if (base.rfind("libjvm.so", 0) == 0 || base.rfind("jvm.dll", 0) == 0 ||
            base.rfind("libmono", 0) == 0 || base.rfind("mono", 0) == 0 ||
            base.rfind("libv8", 0) == 0 || base.rfind("v8", 0) == 0 ||
            base.rfind("libcoreclr", 0) == 0 || base.rfind("coreclr.dll", 0) == 0) {
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
            ev.severity = isRwx ? core::Severity::CRITICAL
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
            ev.timestamp = core::DetectionEvent::NowMonotonicMs();
            ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
            ev.threat_score = isRwx ? 85 : (transientOnly ? 40 : 75);

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



    const auto scanStartTp = std::chrono::steady_clock::now();
    size_t budget = 0;
    uintptr_t cursor = 0;
    {
        std::lock_guard<std::mutex> l(state_mutex_);
        budget = scan_budget_bytes_;
        cursor = scan_cursor_;
    }
    size_t scannedBytes = 0;
    size_t scannedRegionsCount = 0;
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
        ++scannedRegionsCount;

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
                // In a JIT host (Java HotSpot / Minecraft), anonymous executable memory is the JIT CodeCache.
                // Dynamic dispatch stubs (indirect jump relays / trampolines) are legitimately generated by the JIT.
                if (jitHost && !genuineFile && r.executable &&
                    (sig.GetCategory() == SignatureCategory::HOOK_FRAMEWORK ||
                     sig.GetCategory() == SignatureCategory::SHELLCODE_PROLOGUE)) {
                    continue;
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
                ev.timestamp = core::DetectionEvent::NowMonotonicMs();
                ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
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
    const auto scanEndTp = std::chrono::steady_clock::now();
    uint64_t durationUs = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(scanEndTp - scanStartTp).count()
    );
    RecordScanDurationUs(durationUs, scannedRegionsCount, scannedBytes);
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
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
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
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
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
        ev.timestamp = core::DetectionEvent::NowMonotonicMs();
        ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
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

void MemoryScanner::RecordScanDurationUs(uint64_t duration_us, uint64_t regions_count, uint64_t bytes_count) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    telemetry_.total_scans_completed++;
    telemetry_.regions_scanned += regions_count;
    telemetry_.bytes_scanned += bytes_count;
    telemetry_.last_scan_duration_us = duration_us;

    scan_durations_us_.push_back(duration_us);
    if (scan_durations_us_.size() > 128) {
        scan_durations_us_.erase(scan_durations_us_.begin());
    }

    uint64_t sum = 0;
    for (uint64_t v : scan_durations_us_) sum += v;
    telemetry_.mean_scan_duration_us = scan_durations_us_.empty() ? 0 : (sum / scan_durations_us_.size());

    auto sorted = scan_durations_us_;
    std::sort(sorted.begin(), sorted.end());
    if (!sorted.empty()) {
        size_t idx95 = (sorted.size() * 95) / 100;
        if (idx95 >= sorted.size()) idx95 = sorted.size() - 1;
        size_t idx99 = (sorted.size() * 99) / 100;
        if (idx99 >= sorted.size()) idx99 = sorted.size() - 1;
        telemetry_.p95_scan_duration_us = sorted[idx95];
        telemetry_.p99_scan_duration_us = sorted[idx99];
    }
}

ScanTelemetry MemoryScanner::GetScanTelemetry() const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return telemetry_;
}

std::optional<core::DetectionEvent> MemoryScanner::InspectThreadAddress(uint32_t tid, uintptr_t code_address) {
    if (code_address < 0x10000ULL) return std::nullopt;
#if defined(__x86_64__) || defined(_M_X64)
    if (code_address >= 0x0000800000000000ULL) return std::nullopt;
#endif

    auto regions = QueryMemoryRegions();
    const bool jitHost = IsJitRuntime(regions);

    for (const auto& r : regions) {
        if (code_address >= r.start && code_address < r.end) {
            if (r.pathname == "[vdso]" || r.pathname == "[vsyscall]" || r.pathname.rfind("[vvar", 0) == 0) {
                return std::nullopt;
            }
#if defined(_WIN32)
            bool genuineBacked = r.is_backed_by_file;
#else
            bool genuineBacked = r.is_backed_by_file && !r.pathname.empty() && r.pathname[0] == '/' &&
                                 r.pathname.find("(deleted)") == std::string::npos &&
                                 r.pathname.rfind("/memfd:", 0) != 0;
#endif
            if (!r.executable) {
                core::DetectionEvent ev;
                ev.type = core::DetectionType::THREAD_PROVENANCE_ANOMALY;
                ev.severity = core::Severity::CRITICAL;
                ev.component = "MemoryScanner::ThreadProvenance";
                std::ostringstream ss;
                ss << "Thread TID " << tid << " execution pointer 0x" << std::hex << code_address
                   << " resides in non-executable region [0x" << r.start << " - 0x" << r.end << "]";
                ev.details = ss.str();
                ev.timestamp = core::DetectionEvent::NowMonotonicMs();
                ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
                ev.threat_score = 95;
                return ev;
            }
            if (!genuineBacked && !jitHost) {
                core::DetectionEvent ev;
                ev.type = core::DetectionType::THREAD_PROVENANCE_ANOMALY;
                ev.severity = core::Severity::CRITICAL;
                ev.component = "MemoryScanner::ThreadProvenance";
                std::ostringstream ss;
                ss << "Thread TID " << tid << " executing in unbacked anonymous memory at 0x"
                   << std::hex << code_address << " [0x" << r.start << " - 0x" << r.end << "] ("
                   << (r.pathname.empty() ? "[anon]" : r.pathname) << ")";
                ev.details = ss.str();
                ev.timestamp = core::DetectionEvent::NowMonotonicMs();
                ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
                ev.threat_score = 95;
                return ev;
            }
            return std::nullopt;
        }
    }

    // Address is not in any mapped region
#if defined(_WIN32)
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    bool isWine = (ntdll && GetProcAddress(ntdll, "wine_get_version") != nullptr);
    if (isWine && (code_address >= 0x600000000000ULL || code_address < 0x10000ULL)) {
        // Under Wine/Proton, host Linux worker threads (ntsync, audio, async I/O)
        // have RIP pointers in host Linux ELF space (outside Win32 VirtualQuery PE mapping).
        return std::nullopt;
    }
#endif
    core::DetectionEvent ev;
    ev.type = core::DetectionType::THREAD_PROVENANCE_ANOMALY;
    ev.severity = core::Severity::HIGH;
    ev.component = "MemoryScanner::ThreadProvenance";
    std::ostringstream ss;
    ss << "Thread TID " << tid << " points to unmapped user-space address 0x" << std::hex << code_address;
    ev.details = ss.str();
    ev.timestamp = core::DetectionEvent::NowMonotonicMs();
    ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
    ev.threat_score = 75;
    return ev;
}

std::vector<ThreadExecutionInfo> MemoryScanner::QueryActiveThreads() {
    std::vector<ThreadExecutionInfo> threads;
    auto regions = QueryMemoryRegions();
    const bool jitHost = IsJitRuntime(regions);

#if defined(_WIN32)
    DWORD selfPid = GetCurrentProcessId();
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return threads;

    using NtQueryInformationThreadFn = LONG(WINAPI*)(HANDLE, ULONG, PVOID, ULONG, PULONG);
    static NtQueryInformationThreadFn fnNtQueryThread = []() -> NtQueryInformationThreadFn {
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtdll) return nullptr;
        return reinterpret_cast<NtQueryInformationThreadFn>(GetProcAddress(hNtdll, "NtQueryInformationThread"));
    }();
    constexpr ULONG kThreadQuerySetWin32StartAddress = 9;

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(hSnap, &te)) {
        do {
            if (te.th32OwnerProcessID != selfPid) continue;
            ThreadExecutionInfo info{};
            info.tid = te.th32ThreadID;

            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (hThread) {
                uintptr_t startAddr = 0;
                if (fnNtQueryThread &&
                    fnNtQueryThread(hThread, kThreadQuerySetWin32StartAddress, &startAddr, sizeof(startAddr), nullptr) == 0) {
                    info.start_address = startAddr;
                }
                const bool isSelfThread = (te.th32ThreadID == GetCurrentThreadId());
                if (isSelfThread) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_CONTROL;
                    RtlCaptureContext(&ctx);
#if defined(_M_X64) || defined(__x86_64__)
                    info.instruction_pointer = static_cast<uintptr_t>(ctx.Rip);
                    info.stack_pointer = static_cast<uintptr_t>(ctx.Rsp);
#elif defined(_M_IX86) || defined(__i386__)
                    info.instruction_pointer = static_cast<uintptr_t>(ctx.Eip);
                    info.stack_pointer = static_cast<uintptr_t>(ctx.Esp);
#endif
                } else {
                    DWORD prev = SuspendThread(hThread);
                    if (prev != (DWORD)-1) {
                        CONTEXT ctx{};
                        ctx.ContextFlags = CONTEXT_CONTROL;
                        if (GetThreadContext(hThread, &ctx)) {
#if defined(_M_X64) || defined(__x86_64__)
                            info.instruction_pointer = static_cast<uintptr_t>(ctx.Rip);
                            info.stack_pointer = static_cast<uintptr_t>(ctx.Rsp);
#elif defined(_M_IX86) || defined(__i386__)
                            info.instruction_pointer = static_cast<uintptr_t>(ctx.Eip);
                            info.stack_pointer = static_cast<uintptr_t>(ctx.Esp);
#endif
                        }
                        ResumeThread(hThread);
                    }
                }
                CloseHandle(hThread);
            }

            info.ip_in_backed_module = true;
            auto checkModule = [&](uintptr_t addr) {
                if (addr < 0x10000ULL) return;
#if defined(_WIN32)
                HMODULE ntdll = GetModuleHandleA("ntdll.dll");
                bool isWine = (ntdll && GetProcAddress(ntdll, "wine_get_version") != nullptr);
                if (isWine && addr >= 0x600000000000ULL) {
                    return; // Genuine Wine/Proton host thread
                }
#endif
                bool backed = false;
                for (const auto& r : regions) {
                    if (addr >= r.start && addr < r.end) {
                        if (info.module_path.empty()) info.module_path = r.pathname;
                        backed = (r.is_backed_by_file || jitHost) && r.executable;
                        break;
                    }
                }
                if (!backed) {
                    info.ip_in_backed_module = false;
                }
            };
            if (info.start_address != 0) checkModule(info.start_address);
            if (info.instruction_pointer != 0) checkModule(info.instruction_pointer);

            threads.push_back(std::move(info));
        } while (Thread32Next(hSnap, &te));
    }
    CloseHandle(hSnap);
#else
    EnsureThreadSignalHandlerInstalled();
    pid_t myTid = static_cast<pid_t>(syscall(SYS_gettid));
    std::error_code ec;
    for (const auto& entry : std::filesystem::directory_iterator("/proc/self/task", ec)) {
        if (ec) break;
        std::string tidStr = entry.path().filename().string();
        uint32_t tid = 0;
        try {
            tid = static_cast<uint32_t>(std::stoul(tidStr));
        } catch (...) {
            continue;
        }

        ThreadExecutionInfo info{};
        info.tid = tid;

        // 1. Live thread context capture via unprivileged SIGURG reading ucontext_t (avoiding "running" skips)
        bool capturedViaSignal = false;
        if (static_cast<pid_t>(tid) != myTid) {
            std::lock_guard<std::mutex> lk(g_signalCaptureMutex);
            g_targetTid.store(tid, std::memory_order_release);
            g_captureDone.store(false, std::memory_order_release);
            if (syscall(SYS_tgkill, getpid(), tid, SIGURG) == 0) {
                for (int spin = 0; spin < 50; ++spin) {
                    if (g_captureDone.load(std::memory_order_acquire)) {
                        info.instruction_pointer = g_capturedRip.load(std::memory_order_relaxed);
                        info.stack_pointer = g_capturedRsp.load(std::memory_order_relaxed);
                        capturedViaSignal = true;
                        break;
                    }
                    std::this_thread::yield();
                }
            }
        }

        // 2. Fall back to /proc/self/task/<tid>/syscall and stat if not captured via signal
        if (!capturedViaSignal) {
            std::ifstream sysFile(entry.path() / "syscall");
            if (sysFile.is_open()) {
                std::string line;
                if (std::getline(sysFile, line) && line.rfind("running", 0) != 0) {
                    std::istringstream iss(line);
                    std::vector<std::string> tokens;
                    std::string tok;
                    while (iss >> tok) tokens.push_back(tok);
                    if (tokens.size() >= 3) {
                        try {
                            info.stack_pointer = static_cast<uintptr_t>(std::stoull(tokens[tokens.size() - 2], nullptr, 0));
                            info.instruction_pointer = static_cast<uintptr_t>(std::stoull(tokens.back(), nullptr, 0));
                        } catch (...) {}
                    }
                }
            }

            std::ifstream statFile(entry.path() / "stat");
            if (statFile.is_open()) {
                std::string statLine;
                if (std::getline(statFile, statLine)) {
                    size_t closeParen = statLine.rfind(')');
                    if (closeParen != std::string::npos && closeParen + 2 < statLine.size()) {
                        std::istringstream iss(statLine.substr(closeParen + 2));
                        std::string tok;
                        for (int idx = 3; idx <= 30 && (iss >> tok); ++idx) {
                            if (idx == 28 && info.stack_pointer == 0) {
                                try { info.stack_pointer = static_cast<uintptr_t>(std::stoull(tok)); } catch (...) {}
                            } else if (idx == 30 && info.instruction_pointer == 0) {
                                try { info.instruction_pointer = static_cast<uintptr_t>(std::stoull(tok)); } catch (...) {}
                            }
                        }
                    }
                }
            }
        }

        info.ip_in_backed_module = true;
        auto checkLinuxModule = [&](uintptr_t addr) {
            if (addr < 0x10000ULL || addr >= 0x0000800000000000ULL) return;
            bool backed = false;
            for (const auto& r : regions) {
                if (addr >= r.start && addr < r.end) {
                    if (info.module_path.empty()) info.module_path = r.pathname;
                    bool isKernelProvided = (r.pathname == "[vdso]" || r.pathname == "[vsyscall]" || r.pathname.rfind("[vvar", 0) == 0);
                    bool genuineFile = r.is_backed_by_file && !r.pathname.empty() && r.pathname[0] == '/' &&
                                       r.pathname.find("(deleted)") == std::string::npos &&
                                       r.pathname.rfind("/memfd:", 0) != 0;
                    backed = (genuineFile || isKernelProvided || jitHost) && r.executable;
                    break;
                }
            }
            if (!backed) {
                info.ip_in_backed_module = false;
            }
        };
        if (info.instruction_pointer != 0) checkLinuxModule(info.instruction_pointer);
        if (info.start_address != 0) checkLinuxModule(info.start_address);

        threads.push_back(std::move(info));
    }
#endif
    return threads;
}

std::vector<core::DetectionEvent> MemoryScanner::AuditThreadProvenance() {
    std::vector<core::DetectionEvent> events;
    auto threads = QueryActiveThreads();
    auto regions = QueryMemoryRegions();
    const bool jitHost = IsJitRuntime(regions);

    for (const auto& t : threads) {
        // Inspect BOTH start_address AND instruction_pointer!
        if (t.start_address >= 0x10000ULL) {
            auto ev = InspectThreadAddress(t.tid, t.start_address);
            if (ev.has_value()) {
                events.push_back(*ev);
            }
        }
        if (t.instruction_pointer >= 0x10000ULL && t.instruction_pointer != t.start_address) {
            auto ev = InspectThreadAddress(t.tid, t.instruction_pointer);
            if (ev.has_value()) {
                events.push_back(*ev);
            }
        }

        // Stack Walk & Inspection: scan stack memory words for unbacked executable return addresses
        if (t.stack_pointer >= 0x10000ULL) {
#if !defined(_WIN32)
            uintptr_t stackWords[32]{};
            struct iovec local_iov{ stackWords, sizeof(stackWords) };
            struct iovec remote_iov{ reinterpret_cast<void*>(t.stack_pointer), sizeof(stackWords) };
            ssize_t nread = process_vm_readv(getpid(), &local_iov, 1, &remote_iov, 1, 0);
            if (nread > 0) {
                size_t words = static_cast<size_t>(nread) / sizeof(uintptr_t);
                for (size_t wi = 0; wi < words; ++wi) {
                    uintptr_t frameAddr = stackWords[wi];
                    if (frameAddr >= 0x10000ULL && frameAddr < 0x0000800000000000ULL) {
                        for (const auto& r : regions) {
                            if (frameAddr >= r.start && frameAddr < r.end) {
                                if (r.executable && !r.is_backed_by_file && !jitHost &&
                                    r.pathname != "[vdso]" && r.pathname != "[vsyscall]") {
                                    core::DetectionEvent ev;
                                    ev.type = core::DetectionType::THREAD_PROVENANCE_ANOMALY;
                                    ev.severity = core::Severity::CRITICAL;
                                    ev.component = "MemoryScanner::StackWalk";
                                    std::ostringstream ss;
                                    ss << "Thread TID " << t.tid << " stack return address 0x" << std::hex
                                       << frameAddr << " points to unbacked executable memory [0x" << r.start
                                       << " - 0x" << r.end << "]";
                                    ev.details = ss.str();
                                    ev.timestamp = core::DetectionEvent::NowMonotonicMs();
                                    ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
                                    ev.threat_score = 95;
                                    events.push_back(ev);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
#else
            const bool isSelf = (t.tid == GetCurrentThreadId());
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, t.tid);
            if (hThread) {
                CONTEXT ctx{};
                ctx.ContextFlags = CONTEXT_ALL;
                bool gotContext = false;
                if (isSelf) {
                    RtlCaptureContext(&ctx);
                    gotContext = true;
                } else {
                    DWORD prev = SuspendThread(hThread);
                    if (prev != (DWORD)-1) {
                        gotContext = (GetThreadContext(hThread, &ctx) != 0);
                        if (!gotContext) {
                            ResumeThread(hThread);
                        }
                    }
                }
                if (gotContext) {
#if defined(_M_X64) || defined(__x86_64__)
                        CONTEXT walkCtx = ctx;
                        for (int frameIdx = 0; frameIdx < 64 && walkCtx.Rip != 0; ++frameIdx) {
                            uintptr_t frameAddr = static_cast<uintptr_t>(walkCtx.Rip);
                            if (frameAddr >= 0x10000ULL && frameAddr < 0x7FFFFFFFFFFFULL) {
                                for (const auto& r : regions) {
                                    if (frameAddr >= r.start && frameAddr < r.end) {
                                        if (r.executable && !r.is_backed_by_file && !jitHost) {
                                            core::DetectionEvent ev;
                                            ev.type = core::DetectionType::THREAD_PROVENANCE_ANOMALY;
                                            ev.severity = core::Severity::CRITICAL;
                                            ev.component = "MemoryScanner::StackWalk";
                                            std::ostringstream ss;
                                            ss << "Thread TID " << t.tid << " stack return address 0x" << std::hex
                                               << frameAddr << " points to unbacked executable memory [0x" << r.start
                                               << " - 0x" << r.end << "]";
                                            ev.details = ss.str();
                                            ev.timestamp = core::DetectionEvent::NowMonotonicMs();
                                            ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
                                            ev.threat_score = 95;
                                            events.push_back(ev);
                                            break;
                                        }
                                    }
                                }
                            }
                            DWORD64 imageBase = 0;
                            PRUNTIME_FUNCTION fn = RtlLookupFunctionEntry(walkCtx.Rip, &imageBase, nullptr);
                            if (!fn) {
                                if (walkCtx.Rsp >= 0x10000ULL) {
                                    DWORD64 retAddr = 0;
                                    SIZE_T readBytes = 0;
                                    if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(walkCtx.Rsp), &retAddr, sizeof(retAddr), &readBytes) && readBytes == sizeof(retAddr)) {
                                        walkCtx.Rip = retAddr;
                                        walkCtx.Rsp += 8;
                                    } else {
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            } else {
                                PVOID handlerData = nullptr;
                                DWORD64 establisherFrame = 0;
                                RtlVirtualUnwind(UNW_FLAG_NHANDLER, imageBase, walkCtx.Rip, fn, &walkCtx, &handlerData, &establisherFrame, nullptr);
                            }
                        }
#else
                        uintptr_t bp = static_cast<uintptr_t>(ctx.Ebp);
                        for (int frameIdx = 0; frameIdx < 32 && bp >= 0x10000ULL; ++frameIdx) {
                            uintptr_t frameData[2]{};
                            SIZE_T readBytes = 0;
                            if (ReadProcessMemory(GetCurrentProcess(), reinterpret_cast<LPCVOID>(bp), frameData, sizeof(frameData), &readBytes) && readBytes == sizeof(frameData)) {
                                uintptr_t retAddr = frameData[1];
                                for (const auto& r : regions) {
                                    if (retAddr >= r.start && retAddr < r.end) {
                                        if (r.executable && !r.is_backed_by_file && !jitHost) {
                                            core::DetectionEvent ev;
                                            ev.type = core::DetectionType::THREAD_PROVENANCE_ANOMALY;
                                            ev.severity = core::Severity::CRITICAL;
                                            ev.component = "MemoryScanner::StackWalk";
                                            std::ostringstream ss;
                                            ss << "Thread TID " << t.tid << " stack return address 0x" << std::hex
                                               << retAddr << " points to unbacked executable memory [0x" << r.start
                                               << " - 0x" << r.end << "]";
                                            ev.details = ss.str();
                                            ev.timestamp = core::DetectionEvent::NowMonotonicMs();
                                            ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
                                            ev.threat_score = 95;
                                            events.push_back(ev);
                                            break;
                                        }
                                    }
                                }
                                bp = frameData[0];
                            } else {
                                break;
                            }
                        }
#endif
                    if (!isSelf) {
                        ResumeThread(hThread);
                    }
                }
                CloseHandle(hThread);
            }
#endif
        }
    }
    return events;
}

namespace {
#if !defined(_WIN32)
std::string ExtractElfBuildId(const std::string& filePath) {
    std::ifstream f(filePath, std::ios::binary);
    if (!f.is_open()) return "";

    Elf64_Ehdr eh{};
    f.read(reinterpret_cast<char*>(&eh), sizeof(eh));
    if (f.gcount() != static_cast<std::streamsize>(sizeof(eh)) ||
        std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 ||
        eh.e_ident[EI_CLASS] != ELFCLASS64) {
        return "";
    }

    if (eh.e_phentsize < sizeof(Elf64_Phdr) || eh.e_phnum > 512) return "";
    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph{};
        f.seekg(static_cast<std::streamoff>(eh.e_phoff + static_cast<uint64_t>(i) * eh.e_phentsize));
        f.read(reinterpret_cast<char*>(&ph), sizeof(ph));
        if (f.gcount() != static_cast<std::streamsize>(sizeof(ph))) break;
        if (ph.p_type != PT_NOTE || ph.p_filesz == 0 || ph.p_filesz > 65536) continue;

        std::vector<uint8_t> noteBuf(static_cast<size_t>(ph.p_filesz));
        f.seekg(static_cast<std::streamoff>(ph.p_offset));
        f.read(reinterpret_cast<char*>(noteBuf.data()), static_cast<std::streamsize>(noteBuf.size()));
        if (static_cast<size_t>(f.gcount()) != noteBuf.size()) continue;

        size_t off = 0;
        while (off + sizeof(Elf64_Nhdr) <= noteBuf.size()) {
            Elf64_Nhdr nh{};
            std::memcpy(&nh, noteBuf.data() + off, sizeof(nh));
            off += sizeof(Elf64_Nhdr);
            size_t nameAligned = (nh.n_namesz + 3u) & ~3u;
            size_t descAligned = (nh.n_descsz + 3u) & ~3u;
            if (off + nameAligned + descAligned > noteBuf.size()) break;

            if (nh.n_type == NT_GNU_BUILD_ID && nh.n_namesz == 4 &&
                std::memcmp(noteBuf.data() + off, "GNU", 4) == 0 && nh.n_descsz > 0 && nh.n_descsz <= 64) {
                return network::CryptoUtil::ToHex(noteBuf.data() + off + nameAligned, nh.n_descsz);
            }
            off += nameAligned + descAligned;
        }
    }
    return "";
}
#else
bool VerifyWindowsAuthenticode(const std::string& path) {
    if (path.empty()) return false;
    int wlen = MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, nullptr, 0);
    if (wlen <= 0) return false;
    std::wstring wpath(static_cast<size_t>(wlen), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, path.c_str(), -1, wpath.data(), wlen);

    WINTRUST_FILE_INFO fileInfo{};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = wpath.c_str();

    GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData{};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    trustData.dwProvFlags = WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG status = WinVerifyTrust(nullptr, &policyGuid, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &policyGuid, &trustData);
    return status == ERROR_SUCCESS;
}
#endif
} // namespace

std::vector<ModuleProvenanceInfo> MemoryScanner::QueryModuleProvenance() {
    std::vector<ModuleProvenanceInfo> modules;
    auto regions = QueryMemoryRegions();

    std::map<std::string, ModuleProvenanceInfo> byPath;
    for (const auto& r : regions) {
        if (!r.executable || r.pathname.empty()) continue;
        if (r.pathname[0] == '[') continue; // [vdso], [vsyscall], etc.

        auto& entry = byPath[r.pathname];
        if (entry.path.empty()) {
            entry.path = r.pathname;
            entry.base_address = r.start;
        } else {
            entry.base_address = std::min(entry.base_address, r.start);
        }
        entry.executable_size += r.size;
    }

    std::lock_guard<std::mutex> lock(state_mutex_);
    for (auto& [path, info] : byPath) {
        auto cachedIt = provenance_cache_.find(path);
        if (cachedIt != provenance_cache_.end()) {
            cachedIt->second.base_address = info.base_address;
            cachedIt->second.executable_size = info.executable_size;
            modules.push_back(cachedIt->second);
            continue;
        }

#if defined(_WIN32)
        info.sha256_disk_hash = network::CryptoUtil::Sha256File(path);
        info.is_signed = VerifyWindowsAuthenticode(path);
        std::string lower = path;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        info.is_suspicious_origin = (lower.find("\\appdata\\local\\temp\\") != std::string::npos ||
                                     lower.find("\\windows\\temp\\") != std::string::npos);
#else
        bool isMemfdOrDeleted = (path.rfind("/memfd:", 0) == 0 ||
                                 path.find("(deleted)") != std::string::npos);
        bool isWorldTemp = (path.rfind("/dev/shm/", 0) == 0 ||
                            path.rfind("/tmp/", 0) == 0 ||
                            path.rfind("/var/tmp/", 0) == 0);
        info.is_suspicious_origin = isMemfdOrDeleted || isWorldTemp;
        if (!isMemfdOrDeleted && path[0] == '/') {
            info.sha256_disk_hash = network::CryptoUtil::Sha256File(path);
            info.elf_build_id = ExtractElfBuildId(path);
            info.has_build_id = !info.elf_build_id.empty();
            info.is_signed = false;
        }
#endif
        provenance_cache_[path] = info;
        modules.push_back(std::move(info));
    }

    return modules;
}

std::vector<core::DetectionEvent> MemoryScanner::AuditModuleProvenance() {
    std::vector<core::DetectionEvent> events;
    auto modules = QueryModuleProvenance();
    for (const auto& m : modules) {
        if (m.is_suspicious_origin) {
            core::DetectionEvent ev;
            ev.type = core::DetectionType::MODULE_PROVENANCE_ANOMALY;
            ev.severity = (m.path.rfind("/memfd:", 0) == 0 || m.path.find("(deleted)") != std::string::npos)
                ? core::Severity::CRITICAL
                : core::Severity::HIGH;
            ev.component = "MemoryScanner::ModuleProvenance";
            std::ostringstream ss;
            ss << "Executable module loaded from suspicious/ephemeral origin: " << m.path
               << " at base 0x" << std::hex << m.base_address;
            if (!m.sha256_disk_hash.empty()) {
                ss << " (SHA256: " << m.sha256_disk_hash.substr(0, 16) << "...)";
            }
            ev.details = ss.str();
            ev.timestamp = core::DetectionEvent::NowMonotonicMs();
            ev.timestamp_utc_ms = core::DetectionEvent::NowUtcMs();
            ev.threat_score = (ev.severity == core::Severity::CRITICAL) ? 90 : 75;
            events.push_back(ev);
        }
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
    auto threadEvents = AuditThreadProvenance();
    events.insert(events.end(), threadEvents.begin(), threadEvents.end());
    auto provEvents = AuditModuleProvenance();
    events.insert(events.end(), provEvents.begin(), provEvents.end());
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
    auto threadEvents = AuditThreadProvenance();
    events.insert(events.end(), threadEvents.begin(), threadEvents.end());
    auto provEvents = AuditModuleProvenance();
    events.insert(events.end(), provEvents.begin(), provEvents.end());
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
