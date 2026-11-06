#include "noescape/security/integrity.hpp"
#include "noescape/network/crypto_util.hpp"
#include "noescape/core/obfuscation.hpp"

#include <cstring>

#if defined(_WIN32)
#include <windows.h>
#else
#include <link.h>
#include <dlfcn.h>
#include <unistd.h>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <elf.h>
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
    // The runtime baseline only catches changes *after* initialisation. Also compare the loaded
    // code against the file on disk so a patch applied before we started (e.g. by an injector
    // that loaded first) does not become part of the "trusted" baseline.
    pre_baseline_mismatch_ = !TextMatchesDisk();

    initialized_ = true;
    return true;
}

bool IntegrityChecker::TextMatchesDisk() const {
#if defined(_WIN32)
    return true; // PE images are rebased in place; relocation-aware comparison is done by the Unhooker
#else
    Dl_info info{};
    if (!dladdr(reinterpret_cast<void*>(text_start_), &info) || !info.dli_fname || info.dli_fname[0] != '/' ||
        !info.dli_fbase) {
        return true; // no file to compare against (e.g. memfd): nothing to prove either way
    }
    std::ifstream f(info.dli_fname, std::ios::binary);
    if (!f.is_open()) return true;
    ElfW(Ehdr) eh{};
    f.read(reinterpret_cast<char*>(&eh), sizeof(eh));
    if (f.gcount() != static_cast<std::streamsize>(sizeof(eh)) || std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0) return true;
    const uintptr_t vaddr = text_start_ - reinterpret_cast<uintptr_t>(info.dli_fbase);
    for (uint16_t i = 0; i < eh.e_phnum && i < 512; ++i) {
        ElfW(Phdr) ph{};
        f.seekg(static_cast<std::streamoff>(eh.e_phoff + static_cast<uint64_t>(i) * eh.e_phentsize));
        f.read(reinterpret_cast<char*>(&ph), sizeof(ph));
        if (f.gcount() != static_cast<std::streamsize>(sizeof(ph))) return true;
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_X) || ph.p_vaddr != vaddr) continue;
        size_t n = std::min<size_t>(static_cast<size_t>(ph.p_filesz), text_size_);
        std::vector<char> disk(n);
        f.seekg(static_cast<std::streamoff>(ph.p_offset));
        f.read(disk.data(), static_cast<std::streamsize>(n));
        if (static_cast<size_t>(f.gcount()) != n) return true;
        return std::memcmp(disk.data(), reinterpret_cast<const void*>(text_start_), n) == 0;
    }
    return true;
#endif
}

std::string IntegrityChecker::ComputeCurrentTextHash() const {
    if (text_start_ == 0 || text_size_ == 0) return "";
    return network::CryptoUtil::Sha256(reinterpret_cast<const uint8_t*>(text_start_), text_size_);
}

bool IntegrityChecker::Attest(const std::string& secret_key, const std::string& id, const std::string& nonce,
                              uint64_t offset, uint64_t length, std::string& out_hex) {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!initialized_ && !Initialize()) return false;
    constexpr uint64_t kMaxAttestBytes = 1u << 20;
    if (length == 0 || length > kMaxAttestBytes || offset > text_size_ || length > text_size_ - offset) {
        return false;
    }
    std::string msg = id + ":" + nonce + ":";
    msg.append(reinterpret_cast<const char*>(text_start_ + offset), static_cast<size_t>(length));
    out_hex = network::CryptoUtil::HmacSha256(secret_key, msg);
    return true;
}

std::optional<core::DetectionEvent> IntegrityChecker::VerifyIntegrity() {
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    if (!initialized_) {
        if (!Initialize()) return std::nullopt;
    }

    if (pre_baseline_mismatch_) {
        pre_baseline_mismatch_ = false; // report once; the runtime baseline covers later changes
        core::DetectionEvent ev;
        ev.type = core::DetectionType::SELF_INTEGRITY_VIOLATION;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "IntegrityChecker::DiskImage";
        ev.details = "Anti-cheat code in memory differs from its on-disk image (patched before initialisation)";
        ev.timestamp = static_cast<uint64_t>(time(nullptr));
        ev.threat_score = 90;
        return ev;
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
