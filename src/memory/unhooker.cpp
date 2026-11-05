#include "noescape/memory/unhooker.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>
#include <iomanip>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <elf.h>
#include <sys/mman.h>
#include <unistd.h>
#endif

namespace noescape::memory {

Unhooker& Unhooker::Instance() {
    static Unhooker* instance = new Unhooker();
    return *instance;
}

namespace {

bool IsReadableAddress(uintptr_t target, size_t len = sizeof(uintptr_t)) {
    if (target < 0x10000) return false;
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(target), &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD)) {
            return (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)) != 0;
        }
    }
    return false;
#else
    auto regions = MemoryScanner::Instance().QueryMemoryRegions();
    for (const auto& r : regions) {
        if (r.readable && target >= r.start && (target + len) <= r.end) {
            return true;
        }
    }
    return false;
#endif
}

} // namespace

std::optional<HookInfo> Unhooker::InspectFunction(const char* name, void* function_ptr) {
    if (!function_ptr) return std::nullopt;

    uintptr_t addr = reinterpret_cast<uintptr_t>(function_ptr);
    if (addr < 0x10000 || !IsReadableAddress(addr, 16)) {
        return std::nullopt;
    }

    const auto* code = static_cast<const uint8_t*>(function_ptr);

    // Pattern 1: E9 xx xx xx xx -> JMP rel32
    if (code[0] == 0xE9) {
        int32_t relOffset = 0;
        std::memcpy(&relOffset, code + 1, sizeof(relOffset));
        uintptr_t dest = addr + 5 + relOffset;

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "JMP_REL32 (0xE9)";
        info.target_destination = dest;
        info.patched_bytes.assign(code, code + 5);
        return info;
    }

    // Pattern 2: EB xx -> JMP rel8 (short jump to hook stub)
    if (code[0] == 0xEB) {
        int8_t rel = static_cast<int8_t>(code[1]);
        uintptr_t dest = addr + 2 + rel;

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "JMP_REL8 (0xEB)";
        info.target_destination = dest;
        info.patched_bytes.assign(code, code + 2);
        return info;
    }

    // Pattern 3: FF 25 xx xx xx xx -> JMP [RIP + disp32] (x64 indirect jump)
    if (code[0] == 0xFF && code[1] == 0x25) {
        int32_t disp = 0;
        std::memcpy(&disp, code + 2, sizeof(disp));
        uintptr_t targetPtr = addr + 6 + disp;
        uintptr_t dest = 0;
        // Verify address mapping safely before dereferencing to prevent SIGSEGV
        if (IsReadableAddress(targetPtr, sizeof(dest))) {
            std::memcpy(&dest, reinterpret_cast<const void*>(targetPtr), sizeof(dest));
        }

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "JMP_RIP_DISP32 (0xFF 0x25)";
        info.target_destination = dest;
        info.patched_bytes.assign(code, code + 6);
        return info;
    }

    // Pattern 4: 48 B8 [imm64] FF E0 -> MOV RAX, imm64; JMP RAX
    if (code[0] == 0x48 && code[1] == 0xB8 && code[10] == 0xFF && code[11] == 0xE0) {
        uint64_t dest = 0;
        std::memcpy(&dest, code + 2, sizeof(dest));

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "MOV_RAX_JMP_RAX (0x48 0xB8 ... 0xFF 0xE0)";
        info.target_destination = static_cast<uintptr_t>(dest);
        info.patched_bytes.assign(code, code + 12);
        return info;
    }

    // Pattern 5: 49 BA [imm64] 41 FF E2 -> MOV R10, imm64; JMP R10 (MinHook / Detours 64-bit jump)
    if (code[0] == 0x49 && code[1] == 0xBA && code[10] == 0x41 && code[11] == 0xFF && code[12] == 0xE2) {
        uint64_t dest = 0;
        std::memcpy(&dest, code + 2, sizeof(dest));

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "MOV_R10_JMP_R10 (0x49 0xBA ... 0x41 0xFF 0xE2)";
        info.target_destination = static_cast<uintptr_t>(dest);
        info.patched_bytes.assign(code, code + 13);
        return info;
    }

    // Pattern 6: 49 BB [imm64] 41 FF E3 -> MOV R11, imm64; JMP R11
    if (code[0] == 0x49 && code[1] == 0xBB && code[10] == 0x41 && code[11] == 0xFF && code[12] == 0xE3) {
        uint64_t dest = 0;
        std::memcpy(&dest, code + 2, sizeof(dest));

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "MOV_R11_JMP_R11 (0x49 0xBB ... 0x41 0xFF 0xE3)";
        info.target_destination = static_cast<uintptr_t>(dest);
        info.patched_bytes.assign(code, code + 13);
        return info;
    }

    // Pattern 7: 68 [imm32_low] C7 44 24 04 [imm32_high] C3 -> Push-Ret x64 Jump
    if (code[0] == 0x68 && code[5] == 0xC7 && code[6] == 0x44 && code[7] == 0x24 && code[8] == 0x04 && code[13] == 0xC3) {
        uint32_t low = 0, high = 0;
        std::memcpy(&low, code + 1, sizeof(low));
        std::memcpy(&high, code + 9, sizeof(high));
        uint64_t dest = (static_cast<uint64_t>(high) << 32) | low;

        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "PUSH_RET_X64 (0x68 ... 0xC3)";
        info.target_destination = static_cast<uintptr_t>(dest);
        info.patched_bytes.assign(code, code + 14);
        return info;
    }

    // Pattern 8: CC -> Software Breakpoint (INT 3)
    if (code[0] == 0xCC) {
        HookInfo info;
        info.function_name = name ? name : "Unknown";
        info.function_address = addr;
        info.hook_type = "SOFTWARE_BREAKPOINT (0xCC)";
        info.target_destination = 0;
        info.patched_bytes.assign(code, code + 1);
        return info;
    }

    return std::nullopt;
}

std::vector<core::DetectionEvent> Unhooker::AuditSystemHooks() {
    std::vector<core::DetectionEvent> events;

    std::vector<std::pair<const char*, void*>> apisToCheck;

#if defined(_WIN32)
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll) {
        apisToCheck.emplace_back("NtQueryInformationProcess", GetProcAddress(hNtdll, "NtQueryInformationProcess"));
        apisToCheck.emplace_back("NtSetInformationThread", GetProcAddress(hNtdll, "NtSetInformationThread"));
        apisToCheck.emplace_back("NtProtectVirtualMemory", GetProcAddress(hNtdll, "NtProtectVirtualMemory"));
    }
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32) {
        apisToCheck.emplace_back("CreateRemoteThread", GetProcAddress(hKernel32, "CreateRemoteThread"));
        apisToCheck.emplace_back("VirtualProtect", GetProcAddress(hKernel32, "VirtualProtect"));
    }
#else
    apisToCheck.emplace_back("read", dlsym(RTLD_DEFAULT, "read"));
    apisToCheck.emplace_back("write", dlsym(RTLD_DEFAULT, "write"));
    apisToCheck.emplace_back("open", dlsym(RTLD_DEFAULT, "open"));
    apisToCheck.emplace_back("mprotect", dlsym(RTLD_DEFAULT, "mprotect"));
    apisToCheck.emplace_back("ptrace", dlsym(RTLD_DEFAULT, "ptrace"));
#endif

    for (const auto& [apiName, pfn] : apisToCheck) {
        if (!pfn) continue;

        auto hook = InspectFunction(apiName, pfn);
        if (hook) {
            bool restored = AutoRestoreHook(*hook);

            core::DetectionEvent ev;
            ev.type = core::DetectionType::INLINE_HOOK_DETECTED;
            ev.severity = core::Severity::CRITICAL;
            ev.component = "Unhooker::InlineInterceptor";

            std::ostringstream ss;
            ss << "Inline hook detected on routine '" << hook->function_name 
               << "' [0x" << std::hex << hook->function_address << "] "
               << "Hook Type: " << hook->hook_type 
               << " -> Target: 0x" << hook->target_destination;
            if (restored) {
                ss << " [RESTORATION SUCCESS: Function prologue neutralized and restored to clean state]";
            }
            ev.details = ss.str();
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
            ev.threat_score = 90;
            events.push_back(ev);
        }
    }

    return events;
}

bool Unhooker::RestoreHook(const HookInfo& hook, const uint8_t* original_bytes, size_t length) {
    if (hook.function_address == 0 || !original_bytes || length == 0) return false;

    void* targetAddr = reinterpret_cast<void*>(hook.function_address);

#if defined(_WIN32)
    DWORD oldProtect = 0;
    if (!VirtualProtect(targetAddr, length, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return false;
    }
    std::memcpy(targetAddr, original_bytes, length);
    VirtualProtect(targetAddr, length, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), targetAddr, length);
    return true;
#else
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;

    uintptr_t pageStart = hook.function_address & ~(pageSize - 1);
    size_t mappingLen = (hook.function_address + length - pageStart + pageSize - 1) & ~(pageSize - 1);

    int originalProt = PROT_READ | PROT_EXEC;
    for (const auto& reg : MemoryScanner::Instance().QueryMemoryRegions()) {
        if (hook.function_address >= reg.start && hook.function_address < reg.end) {
            originalProt = 0;
            if (reg.readable) originalProt |= PROT_READ;
            if (reg.writable) originalProt |= PROT_WRITE;
            if (reg.executable) originalProt |= PROT_EXEC;
            break;
        }
    }

    if (mprotect(reinterpret_cast<void*>(pageStart), mappingLen, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
        return false;
    }

    std::memcpy(targetAddr, original_bytes, length);

    mprotect(reinterpret_cast<void*>(pageStart), mappingLen, originalProt);
    __builtin___clear_cache(static_cast<char*>(targetAddr), static_cast<char*>(targetAddr) + length);
    return true;
#endif
}

bool Unhooker::AutoRestoreHook(const HookInfo& hook) {
    if (hook.function_address == 0) return false;

#if defined(_WIN32)
    // PE file offsets differ from RVAs (section alignment); restoring from a naive
    // offset would corrupt code, so automatic restoration is disabled until a
    // section-aware mapping is implemented.
    return false;
#else
    Dl_info dlinfo{};
    if (!dladdr(reinterpret_cast<void*>(hook.function_address), &dlinfo) || !dlinfo.dli_fname || !dlinfo.dli_fbase) {
        return false;
    }

    std::ifstream diskFile(dlinfo.dli_fname, std::ios::binary);
    if (!diskFile.is_open()) return false;

    Elf64_Ehdr eh{};
    diskFile.read(reinterpret_cast<char*>(&eh), sizeof(eh));
    if (diskFile.gcount() != static_cast<std::streamsize>(sizeof(eh)) ||
        std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64) {
        return false;
    }

    // Translate virtual address -> file offset through PT_LOAD program headers
    const uint64_t vaddr = hook.function_address - reinterpret_cast<uintptr_t>(dlinfo.dli_fbase);
    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph{};
        diskFile.seekg(static_cast<std::streamoff>(eh.e_phoff + static_cast<uint64_t>(i) * eh.e_phentsize));
        diskFile.read(reinterpret_cast<char*>(&ph), sizeof(ph));
        if (diskFile.gcount() != static_cast<std::streamsize>(sizeof(ph))) return false;
        if (ph.p_type != PT_LOAD || vaddr < ph.p_vaddr || vaddr + 16 > ph.p_vaddr + ph.p_filesz) continue;

        uint8_t originalBytes[16]{};
        diskFile.seekg(static_cast<std::streamoff>(ph.p_offset + (vaddr - ph.p_vaddr)));
        diskFile.read(reinterpret_cast<char*>(originalBytes), sizeof(originalBytes));
        if (diskFile.gcount() != static_cast<std::streamsize>(sizeof(originalBytes))) return false;
        return RestoreHook(hook, originalBytes, sizeof(originalBytes));
    }
    return false;
#endif
}

} // namespace noescape::memory
