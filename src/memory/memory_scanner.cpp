#include "noescape/memory/memory_scanner.hpp"
#include "noescape/core/obfuscation.hpp"
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
            struct sigaction sa{};
            sa.sa_sigaction = ScanSigHandler;
            sa.sa_flags = SA_SIGINFO;
            sigemptyset(&sa.sa_mask);
            if (sigaction(SIGSEGV, &sa, &g_oldSegv) == 0) {
                segvInstalled = true;
            }
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
    unsigned char probe[1];
    static const size_t pageSize = []() {
        long sz = sysconf(_SC_PAGESIZE);
        return (sz > 0) ? static_cast<size_t>(sz) : 4096UL;
    }();
    uintptr_t pageMask = ~(pageSize - 1);
    uintptr_t pageStart = chunkStart & pageMask;
    uintptr_t pageEnd = (chunkStart + chunkSize - 1) & pageMask;

    if (mincore(reinterpret_cast<void*>(pageStart), pageSize, probe) != 0 ||
        (pageEnd > pageStart && mincore(reinterpret_cast<void*>(pageEnd), pageSize, probe) != 0)) {
        return false;
    }

    if (sigsetjmp(g_scanJmpBuf, 1) != 0) {
        g_scanActive = 0;
        return false;
    }
    g_scanActive = 1;
    outMatches = PatternScanner::ScanSignatures(
        reinterpret_cast<const uint8_t*>(chunkStart),
        chunkSize,
        applicable,
        chunkStart,
        16
    );
    g_scanActive = 0;
    return true;
#else
    __try {
        outMatches = PatternScanner::ScanSignatures(
            reinterpret_cast<const uint8_t*>(chunkStart),
            chunkSize,
            applicable,
            chunkStart,
            16
        );
        return true;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
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
}

void MemoryScanner::ClearCache() {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cached_regions_.clear();
    cache_valid_ = false;
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

            reg.readable = (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
            reg.writable = (mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)) != 0;
            reg.executable = (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
            reg.is_shared = (mbi.Type == MEM_MAPPED || mbi.Type == MEM_IMAGE);

            char filePath[MAX_PATH]{};
            if (GetMappedFileNameA(GetCurrentProcess(), mbi.BaseAddress, filePath, MAX_PATH) > 0) {
                reg.pathname = filePath;
                reg.is_backed_by_file = true;
            } else {
                reg.is_backed_by_file = false;
            }

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

std::vector<core::DetectionEvent> MemoryScanner::DetectUnbackedExecutableRegions() {
    std::vector<core::DetectionEvent> events;
    auto regions = QueryMemoryRegions();

    // Check if host process is a JIT runtime (such as Java JVM / HotSpot or explicitly enabled JIT).
    // In Java/Minecraft, HotSpot allocates anonymous executable memory for its JIT CodeCache.
    bool isJitRuntime = false;
#if !defined(_WIN32)
    char exePathBuf[PATH_MAX]{};
    ssize_t exeLen = readlink(NOESCAPE_XOR("/proc/self/exe"), exePathBuf, sizeof(exePathBuf) - 1);
    if (exeLen > 0) {
        exePathBuf[exeLen] = '\0';
        std::string exeStr(exePathBuf);
        std::transform(exeStr.begin(), exeStr.end(), exeStr.begin(), ::tolower);
        if (exeStr.find("java") != std::string::npos ||
            exeStr.find("mono") != std::string::npos ||
            exeStr.find("node") != std::string::npos ||
            exeStr.find("dotnet") != std::string::npos) {
            isJitRuntime = true;
        }
    }
#endif
    for (const auto& r : regions) {
        if (r.pathname.find("libjvm") != std::string::npos ||
            r.pathname.find("libmono") != std::string::npos ||
            r.pathname.find("libv8") != std::string::npos ||
            r.pathname.find("libcoreclr") != std::string::npos) {
            isJitRuntime = true;
            break;
        }
    }
#if defined(NOESCAPE_SECURE_BUILD) || defined(NDEBUG)
    const char* testEnv = std::getenv("NOESCAPE_TEST_MODE");
    if (testEnv && (std::strcmp(testEnv, "1") == 0 || strcasecmp(testEnv, "true") == 0)) {
        const char* allowJitEnv = std::getenv("NOESCAPE_ALLOW_JIT");
        if (allowJitEnv && (std::strcmp(allowJitEnv, "1") == 0 || strcasecmp(allowJitEnv, "true") == 0)) {
            isJitRuntime = true;
        }
    }
#else
    const char* allowJitEnv = std::getenv("NOESCAPE_ALLOW_JIT");
    if (allowJitEnv && (std::strcmp(allowJitEnv, "1") == 0 || strcasecmp(allowJitEnv, "true") == 0)) {
        isJitRuntime = true;
    }
#endif

    for (const auto& r : regions) {
        if (!r.executable) continue;
        if (r.pathname == "[vsyscall]" || r.pathname == "[vdso]") continue;

        bool suspicious = false;
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
                r.pathname.find("tracy") != std::string::npos ||
                r.pathname.find(".so") != std::string::npos
            ));
            if (!isLegitRuntimeTemp) {
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
                r.pathname.find("tracy") != std::string::npos ||
                r.pathname.find(".so") != std::string::npos
            ));
            if (!isLegitRuntimeTemp) {
                suspicious = true;
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
            ev.severity = isRwx ? core::Severity::FATAL_BAN : core::Severity::HIGH;
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
            ev.threat_score = isRwx ? 100 : 75;

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

#if !defined(_WIN32)
    SafeScanGuard safeGuard;
#endif

    for (const auto& r : regions) {
        // Skip special kernel mapped regions, device memory, or unreadable/empty segments
        if (!r.readable || r.size == 0) continue;
        if (r.pathname.rfind("[vvar", 0) == 0 || r.pathname == "[vsyscall]" || 
            r.pathname == "[vectors]" || r.pathname == "[vdso]") continue;
        if (r.pathname.rfind("/dev/", 0) == 0) continue;
        // Non-executable heap and thread stacks contain normal runtime allocations, local variables,
        // and string tables. Skip non-executable heap/stack regions to eliminate false positives.
        if (!r.executable && (r.pathname == "[heap]" || r.pathname.rfind("[stack", 0) == 0)) continue;

        const bool genuineFile = r.is_backed_by_file && !r.pathname.empty() && r.pathname[0] == '/' &&
                                 r.pathname.find("(deleted)") == std::string::npos;

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
        std::set<std::pair<uintptr_t, const CheatSignature*>> seenMatches;

        while (offset < r.size) {
            size_t currentChunkSize = std::min(kChunkSize, r.size - offset);
            uintptr_t chunkStart = r.start + offset;

            std::vector<PatternScanner::SignatureMatchResult> matches;
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

    return events;
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

std::vector<core::DetectionEvent> MemoryScanner::DetectModifiedModules() {
    std::vector<core::DetectionEvent> events;
#if defined(_WIN32)
    return events; // PE relocation-aware comparison not implemented yet
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
    char magic[4]{};
    f.read(magic, 4);
    if (f.gcount() != 4 || std::memcmp(magic, "\x7f""ELF", 4) != 0) return events;

    std::vector<uint8_t> disk(r.size);
    f.seekg(static_cast<std::streamoff>(r.file_offset));
    f.read(reinterpret_cast<char*>(disk.data()), static_cast<std::streamsize>(r.size));
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
