#include "noescape/security/integrity.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/core/obfuscation.hpp"

#if defined(_WIN32)
#include <windows.h>
#else
#include <link.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#endif

namespace noescape::security {

IntegrityChecker& IntegrityChecker::Instance() {
    static IntegrityChecker* instance = new IntegrityChecker();
    return *instance;
}

bool IntegrityChecker::LocateTextSection(uintptr_t& outStart, size_t& outSize) {
#if defined(_WIN32)
    HMODULE hModule = nullptr;
    // Resolve the exact module (DLL or EXE) hosting this anti-cheat instance
    if (!GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | 
                            GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCSTR>(&IntegrityChecker::Instance), 
                            &hModule) || !hModule) {
        hModule = GetModuleHandleA(nullptr);
    }
    if (!hModule) return false;

    auto base = reinterpret_cast<uintptr_t>(hModule);
    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(base + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) return false;

    auto section = IMAGE_FIRST_SECTION(ntHeaders);
    for (WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".text", 5) == 0 || 
            (section->Characteristics & IMAGE_SCN_MEM_EXECUTE)) {
            outStart = base + section->VirtualAddress;
            outSize = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
#else
    // Determine the base address of the module hosting IntegrityChecker (so or exe)
    Dl_info dlinfo{};
    void* targetBase = nullptr;
    if (dladdr(reinterpret_cast<void*>(&IntegrityChecker::Instance), &dlinfo) && dlinfo.dli_fbase) {
        targetBase = dlinfo.dli_fbase;
    }

    struct CallbackData {
        void* targetBase{nullptr};
        uintptr_t start{0};
        size_t size{0};
        bool found{false};
    };

    CallbackData cbData;
    cbData.targetBase = targetBase;

    auto callback = [](struct dl_phdr_info* info, size_t, void* data) -> int {
        auto pData = static_cast<CallbackData*>(data);
        bool isTarget = false;

        if (pData->targetBase) {
            isTarget = (reinterpret_cast<void*>(info->dlpi_addr) == pData->targetBase);
        } else {
            // Main binary fallback
            isTarget = (info->dlpi_name == nullptr || info->dlpi_name[0] == '\0');
        }

        if (isTarget) {
            for (int i = 0; i < info->dlpi_phnum; ++i) {
                if (info->dlpi_phdr[i].p_type == PT_LOAD && 
                    (info->dlpi_phdr[i].p_flags & PF_X)) {
                    pData->start = info->dlpi_addr + info->dlpi_phdr[i].p_vaddr;
                    pData->size = info->dlpi_phdr[i].p_memsz;
                    pData->found = true;
                    return 1;
                }
            }
        }
        return 0;
    };

    dl_iterate_phdr(callback, &cbData);
    if (cbData.found && cbData.size > 0) {
        outStart = cbData.start;
        outSize = cbData.size;
        return true;
    }

    // Fallback: Read /proc/self/maps for primary r-xp mapping
    std::ifstream maps(NOESCAPE_XOR("/proc/self/maps"));
    if (maps.is_open()) {
        std::string line;
        while (std::getline(maps, line)) {
            if (line.find(" r-xp ") != std::string::npos || line.find(" r--p ") != std::string::npos) {
                uintptr_t s = 0, e = 0;
                char dash = 0;
                std::istringstream iss(line);
                if (iss >> std::hex >> s >> dash >> e) {
                    if (line.find("r-xp") != std::string::npos) {
                        outStart = s;
                        outSize = e - s;
                        return true;
                    }
                }
            }
        }
    }
    return false;
#endif
}

bool IntegrityChecker::Initialize() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (initialized_) return true;

    if (!LocateTextSection(text_start_, text_size_)) {
        return false;
    }

    baseline_hash_ = ComputeCurrentTextHash();
    if (baseline_hash_.empty()) {
        return false;
    }

    initialized_ = true;
    return true;
}

std::string IntegrityChecker::ComputeCurrentTextHash() const {
    if (text_start_ == 0 || text_size_ == 0) return "";
    return network::CryptoUtil::Sha256(reinterpret_cast<const uint8_t*>(text_start_), text_size_);
}

std::optional<core::DetectionEvent> IntegrityChecker::VerifyIntegrity() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!initialized_) {
        if (!Initialize()) return std::nullopt;
    }

    std::string currentHash = ComputeCurrentTextHash();
    if (currentHash != baseline_hash_) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::SELF_INTEGRITY_VIOLATION;
        ev.severity = core::Severity::FATAL_BAN;
        ev.component = "IntegrityChecker::TextSection";
        ev.details = "Executable text segment hash mismatch. Expected: " + 
                     baseline_hash_.substr(0, 16) + "... Actual: " + currentHash.substr(0, 16) + "...";
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 100;
        return ev;
    }

    return std::nullopt;
}

} // namespace noescape::security
