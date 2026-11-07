#include "noescape/memory/unhooker.hpp"
#include "noescape/memory/memory_scanner.hpp"
#include "noescape/core/envutil.hpp"
#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <mutex>
#include <sstream>
#include <iomanip>

#if defined(_WIN32)
#include <windows.h>
#else
#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>
#endif

namespace noescape::memory {

Unhooker& Unhooker::Instance() {
    static Unhooker* instance = new Unhooker();
    return *instance;
}

namespace {

constexpr size_t kPrologueLen = 16;

bool IsReadableAddress(uintptr_t target, size_t len = sizeof(uintptr_t)) {
    if (target < 0x10000) return false;
#if defined(_WIN32)
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(reinterpret_cast<LPCVOID>(target), &mbi, sizeof(mbi)) != 0) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & PAGE_NOACCESS) && !(mbi.Protect & PAGE_GUARD)) {
            uintptr_t regionEnd = reinterpret_cast<uintptr_t>(mbi.BaseAddress) + mbi.RegionSize;
            return target + len <= regionEnd &&
                   (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ |
                                   PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0;
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

std::string BaseNameOf(const std::string& p) {
    size_t s = p.find_last_of("/\\");
    return s == std::string::npos ? p : p.substr(s + 1);
}

std::string Hex(uintptr_t v) {
    std::ostringstream ss;
    ss << "0x" << std::hex << v;
    return ss.str();
}

// Original on-disk bytes of a function prologue. `mask[i] == false` means "do not compare /
// restore this byte" (it is patched by the loader through a base relocation).
struct DiskPrologue {
    bool valid{false};
    uint8_t bytes[kPrologueLen]{};
    bool mask[kPrologueLen]{};
};

std::mutex g_cacheMutex;
std::map<uintptr_t, DiskPrologue> g_diskCache;

#if defined(_WIN32)

std::string ModuleOfAddress(uintptr_t addr, std::wstring* widePath = nullptr) {
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(addr), &mod) || !mod) {
        return "";
    }
    wchar_t path[MAX_PATH * 2]{};
    if (!GetModuleFileNameW(mod, path, MAX_PATH * 2)) return "";
    if (widePath) *widePath = path;
    char utf8[MAX_PATH * 4]{};
    WideCharToMultiByte(CP_UTF8, 0, path, -1, utf8, sizeof(utf8), nullptr, nullptr);
    return utf8;
}

// Reads the function's bytes from the PE file on disk, translating RVA -> file offset through
// the section table and masking every byte touched by a base relocation.
DiskPrologue ReadDiskPrologue(uintptr_t addr) {
    DiskPrologue out;
    std::wstring path;
    if (ModuleOfAddress(addr, &path).empty()) return out;
    HMODULE mod = nullptr;
    if (!GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                            reinterpret_cast<LPCWSTR>(addr), &mod)) {
        return out;
    }
    const uint32_t rva = static_cast<uint32_t>(addr - reinterpret_cast<uintptr_t>(mod));

    HANDLE f = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_DELETE, nullptr,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (f == INVALID_HANDLE_VALUE) return out;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart <= 0 || sz.QuadPart > (512ll << 20)) { CloseHandle(f); return out; }
    std::vector<uint8_t> file(static_cast<size_t>(sz.QuadPart));
    DWORD got = 0;
    bool ok = ReadFile(f, file.data(), static_cast<DWORD>(file.size()), &got, nullptr) && got == file.size();
    CloseHandle(f);
    if (!ok || file.size() < sizeof(IMAGE_DOS_HEADER)) return out;

    auto rd = [&](size_t off, size_t len) { return off + len <= file.size(); };
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(file.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || !rd(static_cast<size_t>(dos->e_lfanew), sizeof(IMAGE_NT_HEADERS64))) return out;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(file.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE || nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return out;

    const size_t secOff = static_cast<size_t>(dos->e_lfanew) + offsetof(IMAGE_NT_HEADERS64, OptionalHeader) +
                          nt->FileHeader.SizeOfOptionalHeader;
    const WORD nsec = nt->FileHeader.NumberOfSections;
    if (!rd(secOff, static_cast<size_t>(nsec) * sizeof(IMAGE_SECTION_HEADER))) return out;
    auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(file.data() + secOff);

    auto rvaToOff = [&](uint32_t r, size_t len, size_t& offOut) {
        for (WORD i = 0; i < nsec; ++i) {
            const auto& s = sections[i];
            uint32_t vsz = std::max<uint32_t>(s.Misc.VirtualSize, s.SizeOfRawData);
            if (r >= s.VirtualAddress && r + len <= s.VirtualAddress + vsz &&
                r + len <= s.VirtualAddress + s.SizeOfRawData) {
                offOut = static_cast<size_t>(s.PointerToRawData) + (r - s.VirtualAddress);
                return rd(offOut, len);
            }
        }
        return false;
    };

    size_t codeOff = 0;
    if (!rvaToOff(rva, kPrologueLen, codeOff)) return out;
    std::memcpy(out.bytes, file.data() + codeOff, kPrologueLen);
    for (bool& m : out.mask) m = true;

    // Mask bytes covered by base relocations (absolute addresses rebased by the loader)
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
                    if (byteRva >= rva && byteRva < rva + kPrologueLen) out.mask[byteRva - rva] = false;
                }
            }
            p += blk->SizeOfBlock;
        }
    }
    out.valid = true;
    return out;
}

#else // Linux

void* LibcHandle() {
    static void* h = []() -> void* {
        void* x = dlopen("libc.so.6", RTLD_NOW | RTLD_NOLOAD);
        return x;
    }();
    return h;
}

std::string ModuleOfAddress(uintptr_t addr) {
    Dl_info info{};
    if (dladdr(reinterpret_cast<void*>(addr), &info) && info.dli_fname && info.dli_fname[0]) {
        return info.dli_fname;
    }
    // dladdr only knows ELF objects; fall back to the mapping's backing file
    for (const auto& r : MemoryScanner::Instance().QueryMemoryRegions()) {
        if (addr >= r.start && addr < r.end) {
            return r.is_backed_by_file ? r.pathname : "";
        }
    }
    return "";
}

DiskPrologue ReadDiskPrologue(uintptr_t addr) {
    DiskPrologue out;
    Dl_info dlinfo{};
    if (!dladdr(reinterpret_cast<void*>(addr), &dlinfo) || !dlinfo.dli_fname || !dlinfo.dli_fbase ||
        dlinfo.dli_fname[0] != '/') {
        return out; // vDSO / anonymous: no on-disk reference
    }
    std::ifstream diskFile(dlinfo.dli_fname, std::ios::binary);
    if (!diskFile.is_open()) return out;

    Elf64_Ehdr eh{};
    diskFile.read(reinterpret_cast<char*>(&eh), sizeof(eh));
    if (diskFile.gcount() != static_cast<std::streamsize>(sizeof(eh)) ||
        std::memcmp(eh.e_ident, ELFMAG, SELFMAG) != 0 || eh.e_ident[EI_CLASS] != ELFCLASS64 ||
        eh.e_phentsize < sizeof(Elf64_Phdr) || eh.e_phnum > 512) {
        return out;
    }
    const uint64_t vaddr = (eh.e_type == ET_EXEC)
        ? static_cast<uint64_t>(addr)
        : static_cast<uint64_t>(addr - reinterpret_cast<uintptr_t>(dlinfo.dli_fbase));
    for (uint16_t i = 0; i < eh.e_phnum; ++i) {
        Elf64_Phdr ph{};
        diskFile.seekg(static_cast<std::streamoff>(eh.e_phoff + static_cast<uint64_t>(i) * eh.e_phentsize));
        diskFile.read(reinterpret_cast<char*>(&ph), sizeof(ph));
        if (diskFile.gcount() != static_cast<std::streamsize>(sizeof(ph))) return out;
        if (ph.p_type != PT_LOAD || vaddr < ph.p_vaddr || vaddr + kPrologueLen > ph.p_vaddr + ph.p_filesz) continue;
        diskFile.seekg(static_cast<std::streamoff>(ph.p_offset + (vaddr - ph.p_vaddr)));
        diskFile.read(reinterpret_cast<char*>(out.bytes), kPrologueLen);
        if (diskFile.gcount() != static_cast<std::streamsize>(kPrologueLen)) return out;
        for (bool& m : out.mask) m = true; // PIC text carries no load-time relocations
        out.valid = true;
        return out;
    }
    return out;
}

// Writes through /proc/self/mem: the kernel performs the write with FOLL_FORCE, so read-only
// text can be patched without ever making the page writable+executable (no RWX window that
// another thread or a cheat could abuse).
bool WriteViaProcMem(uintptr_t addr, const uint8_t* data, size_t len) {
    int fd = core::OpenProcSelfWithDumpableFallback("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    ssize_t w = pwrite(fd, data, len, static_cast<off_t>(addr));
    close(fd);
    if (w != static_cast<ssize_t>(len)) return false;
    __builtin___clear_cache(reinterpret_cast<char*>(addr), reinterpret_cast<char*>(addr + len));
    return true;
}

#endif

DiskPrologue CachedDiskPrologue(uintptr_t addr) {
    {
        std::lock_guard<std::mutex> l(g_cacheMutex);
        auto it = g_diskCache.find(addr);
        if (it != g_diskCache.end()) return it->second;
    }
    DiskPrologue d = ReadDiskPrologue(addr);
    std::lock_guard<std::mutex> l(g_cacheMutex);
    if (g_diskCache.size() > 4096) g_diskCache.clear();
    g_diskCache[addr] = d;
    return d;
}

bool IsWhitelistedInterposer(const std::string& module) {
    std::string b = BaseNameOf(module);
    for (const char* ok : {"libasan", "libtsan", "libubsan", "liblsan", "libhwasan", "libnoescape",
                           "libmangohud", "libgamemode", "gameoverlayrenderer", "libvkbasalt",
                           "libc.so", "libpthread", "ld-linux", "libdl.so", "linux-vdso", "[vdso]"}) {
        if (b.rfind(ok, 0) == 0) return true;
    }
    return false;
}

} // namespace

std::optional<HookInfo> Unhooker::InspectFunction(const char* name, void* function_ptr) {
    if (!function_ptr) return std::nullopt;

    uintptr_t addr = reinterpret_cast<uintptr_t>(function_ptr);
    if (addr < 0x10000 || !IsReadableAddress(addr, 16)) {
        return std::nullopt;
    }

    const auto* code = static_cast<const uint8_t*>(function_ptr);
    HookInfo info;
    info.function_name = name ? name : "Unknown";
    info.function_address = addr;

    auto matchAt = [&](size_t off) -> bool {
        const uint8_t* p = code + off;
        const uintptr_t insnAddr = addr + off;
        const size_t avail = (off == 0) ? 16 : (IsReadableAddress(addr + off, 16) ? 16 : (16 - off));

        // Pattern 1: E9 xx xx xx xx -> JMP rel32
        if (avail >= 5 && p[0] == 0xE9) {
            int32_t relOffset = 0;
            std::memcpy(&relOffset, p + 1, sizeof(relOffset));
            info.hook_type = "JMP_REL32 (0xE9)";
            info.target_destination = insnAddr + 5 + static_cast<intptr_t>(relOffset);
            info.patched_bytes.assign(code, code + off + 5);
            return true;
        }
        // Pattern 2: EB xx -> JMP rel8
        if (avail >= 2 && p[0] == 0xEB) {
            int8_t rel = static_cast<int8_t>(p[1]);
            info.hook_type = "JMP_REL8 (0xEB)";
            info.target_destination = insnAddr + 2 + rel;
            info.patched_bytes.assign(code, code + off + 2);
            return true;
        }
        // Pattern 3: FF 25 disp32 -> JMP [RIP + disp32] (and REX.W 48 FF 25 disp32)
        if (avail >= 6 && p[0] == 0xFF && p[1] == 0x25) {
            int32_t disp = 0;
            std::memcpy(&disp, p + 2, sizeof(disp));
            uintptr_t targetPtr = insnAddr + 6 + static_cast<intptr_t>(disp);
            uintptr_t dest = 0;
            if (IsReadableAddress(targetPtr, sizeof(dest))) {
                std::memcpy(&dest, reinterpret_cast<const void*>(targetPtr), sizeof(dest));
            }
            info.hook_type = "JMP_RIP_DISP32 (0xFF 0x25)";
            info.target_destination = dest;
            info.patched_bytes.assign(code, code + off + 6);
            return true;
        }
        if (avail >= 7 && p[0] == 0x48 && p[1] == 0xFF && p[2] == 0x25) {
            int32_t disp = 0;
            std::memcpy(&disp, p + 3, sizeof(disp));
            uintptr_t targetPtr = insnAddr + 7 + static_cast<intptr_t>(disp);
            uintptr_t dest = 0;
            if (IsReadableAddress(targetPtr, sizeof(dest))) {
                std::memcpy(&dest, reinterpret_cast<const void*>(targetPtr), sizeof(dest));
            }
            info.hook_type = "JMP_RIP_DISP32 (0xFF 0x25)";
            info.target_destination = dest;
            info.patched_bytes.assign(code, code + off + 7);
            return true;
        }
        // Pattern 4: 48 B8 imm64 FF E0 -> MOV RAX, imm64; JMP RAX
        if (avail >= 12 && p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && p[11] == 0xE0) {
            uint64_t dest = 0;
            std::memcpy(&dest, p + 2, sizeof(dest));
            info.hook_type = "MOV_RAX_JMP_RAX (0x48 0xB8 ... 0xFF 0xE0)";
            info.target_destination = static_cast<uintptr_t>(dest);
            info.patched_bytes.assign(code, code + off + 12);
            return true;
        }
        // Pattern 5: 49 BA imm64 41 FF E2 -> MOV R10, imm64; JMP R10
        if (avail >= 13 && p[0] == 0x49 && p[1] == 0xBA && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE2) {
            uint64_t dest = 0;
            std::memcpy(&dest, p + 2, sizeof(dest));
            info.hook_type = "MOV_R10_JMP_R10 (0x49 0xBA ... 0x41 0xFF 0xE2)";
            info.target_destination = static_cast<uintptr_t>(dest);
            info.patched_bytes.assign(code, code + off + 13);
            return true;
        }
        // Pattern 6: 49 BB imm64 41 FF E3 -> MOV R11, imm64; JMP R11
        if (avail >= 13 && p[0] == 0x49 && p[1] == 0xBB && p[10] == 0x41 && p[11] == 0xFF && p[12] == 0xE3) {
            uint64_t dest = 0;
            std::memcpy(&dest, p + 2, sizeof(dest));
            info.hook_type = "MOV_R11_JMP_R11 (0x49 0xBB ... 0x41 0xFF 0xE3)";
            info.target_destination = static_cast<uintptr_t>(dest);
            info.patched_bytes.assign(code, code + off + 13);
            return true;
        }
        // Pattern 7: 68 imm32 C7 44 24 04 imm32 C3 -> push/ret 64-bit jump
        if (avail >= 14 && p[0] == 0x68 && p[5] == 0xC7 && p[6] == 0x44 && p[7] == 0x24 && p[8] == 0x04 && p[13] == 0xC3) {
            uint32_t low = 0, high = 0;
            std::memcpy(&low, p + 1, sizeof(low));
            std::memcpy(&high, p + 9, sizeof(high));
            info.hook_type = "PUSH_RET_X64 (0x68 ... 0xC3)";
            info.target_destination = static_cast<uintptr_t>((static_cast<uint64_t>(high) << 32) | low);
            info.patched_bytes.assign(code, code + off + 14);
            return true;
        }
        // Pattern 8: CC -> software breakpoint
        if (avail >= 1 && p[0] == 0xCC) {
            info.hook_type = "SOFTWARE_BREAKPOINT (0xCC)";
            info.target_destination = 0;
            info.patched_bytes.assign(code, code + off + 1);
            return true;
        }
        return false;
    };

    if (matchAt(0)) {
        return info;
    }
    // Intel CET (endbr64: F3 0F 1E FA, endbr32: F3 0F 1E FB): CET-aware hook frameworks
    // place their detour at +4 so indirect branch tracking does not fault with #CP.
    if (code[0] == 0xF3 && code[1] == 0x0F && code[2] == 0x1E &&
        (code[3] == 0xFA || code[3] == 0xFB) && matchAt(4)) {
        return info;
    }
    return std::nullopt;
}

std::vector<core::DetectionEvent> Unhooker::AuditSystemHooks() {
    std::vector<core::DetectionEvent> events;

    struct Api { const char* name; void* ptr; bool restorable; };
    std::vector<Api> apis;

#if defined(_WIN32)
    auto add = [&](HMODULE m, const char* fn, bool restorable) {
        if (!m) return;
        if (void* p = reinterpret_cast<void*>(GetProcAddress(m, fn))) apis.push_back({fn, p, restorable});
    };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    HMODULE kbase = GetModuleHandleA("kernelbase.dll");
    HMODULE k32 = GetModuleHandleA("kernel32.dll");
    for (const char* fn : {"NtQueryInformationProcess", "NtSetInformationThread", "NtProtectVirtualMemory",
                           "NtReadVirtualMemory", "NtWriteVirtualMemory", "NtQueryVirtualMemory",
                           "NtCreateThreadEx", "LdrLoadDll", "NtQueryPerformanceCounter"}) add(ntdll, fn, true);
    for (const char* fn : {"VirtualProtect", "ReadProcessMemory", "WriteProcessMemory",
                           "QueryPerformanceCounter", "GetTickCount64"}) add(kbase, fn, true);
    for (const char* fn : {"CreateRemoteThread", "VirtualProtect"}) add(k32, fn, true);
#else
    void* libc = LibcHandle();
    // Resolve the implementation inside libc itself: dlsym(RTLD_DEFAULT) would return the first
    // interposer in the global scope (LD_PRELOAD libraries, sanitizer interceptors).
    auto resolve = [&](const char* fn) -> void* {
        return libc ? dlsym(libc, fn) : dlsym(RTLD_DEFAULT, fn);
    };
    for (const char* fn : {"read", "write", "open", "openat", "mmap", "mprotect", "ptrace",
                           "clock_gettime", "gettimeofday", "nanosleep", "clock_nanosleep",
                           "connect", "send", "recv", "sendto", "recvfrom",
                           "process_vm_readv", "process_vm_writev", "dlopen", "dlsym"}) {
        if (void* p = resolve(fn)) apis.push_back({fn, p, true});
    }

    // Symbol interposition: an LD_PRELOAD'ed library overriding time / memory / tracing APIs
    // (classic Linux speedhack and memory-hiding technique).
    if (libc) {
        for (const char* fn : {"clock_gettime", "gettimeofday", "time", "nanosleep", "clock_nanosleep",
                               "process_vm_readv", "process_vm_writev", "ptrace"}) {
            void* real = dlsym(libc, fn);
            void* seen = dlsym(RTLD_DEFAULT, fn);
            if (!real || !seen || real == seen) continue;
            std::string mod = ModuleOfAddress(reinterpret_cast<uintptr_t>(seen));
            if (IsWhitelistedInterposer(mod)) continue;
            core::DetectionEvent ev;
            ev.type = core::DetectionType::INLINE_HOOK_DETECTED;
            ev.severity = core::Severity::HIGH;
            ev.component = "Unhooker::SymbolInterposition";
            ev.details = std::string("Libc routine '") + fn + "' is interposed by " +
                         (mod.empty() ? std::string("anonymous memory") : BaseNameOf(mod));
            ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
            ev.threat_score = mod.empty() ? 90 : 60;
            events.push_back(ev);
        }
    }
#endif

    for (const auto& api : apis) {
        uintptr_t addr = reinterpret_cast<uintptr_t>(api.ptr);
        if (!IsReadableAddress(addr, kPrologueLen)) continue;
        const auto* mem = reinterpret_cast<const uint8_t*>(addr);

        DiskPrologue disk = CachedDiskPrologue(addr);
        bool modified = false;
        if (disk.valid) {
            for (size_t i = 0; i < kPrologueLen; ++i) {
                if (disk.mask[i] && mem[i] != disk.bytes[i]) { modified = true; break; }
            }
            // Identical to the on-disk image: a jmp/stub prologue is the function's genuine code
            // (e.g. kernel32 forwarders "jmp [rip+X]", musl/glibc tail calls).
            if (!modified) continue;
        }

        auto hook = InspectFunction(api.name, api.ptr);
        if (!modified && !hook) continue; // no disk reference and no hook pattern

        HookInfo info;
        if (hook) {
            info = *hook;
        } else {
            info.function_name = api.name;
            info.function_address = addr;
            info.hook_type = "PROLOGUE_MODIFIED (differs from on-disk image)";
            info.patched_bytes.assign(mem, mem + kPrologueLen);
        }

        // Classify where the detour leads. A detour into another signed/installed module is
        // typically an overlay, AV/EDR or accessibility hook; a detour into anonymous memory is
        // the hallmark of injected code.
        std::string selfModule = ModuleOfAddress(addr);
        std::string targetModule;
        if (info.target_destination) {
            targetModule = ModuleOfAddress(info.target_destination);
        }
        // When no on-disk reference exists (e.g. kernel vDSO functions resolved via STT_GNU_IFUNC
        // such as gettimeofday/clock_gettime) and the jump stays inside the same module or a
        // whitelisted system module, it is normal kernel/runtime code rather than a hook.
        if (!disk.valid && !targetModule.empty() &&
            (targetModule == selfModule || IsWhitelistedInterposer(targetModule))) {
            continue;
        }
        const bool intoModule = !targetModule.empty();
        const bool intoExternalModule = intoModule && targetModule != selfModule;
        const bool breakpoint = info.hook_type.rfind("SOFTWARE_BREAKPOINT", 0) == 0;

        core::DetectionEvent ev;
        ev.type = core::DetectionType::INLINE_HOOK_DETECTED;
        ev.component = "Unhooker::InlineInterceptor";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        if (!disk.valid || intoExternalModule) {
            // unconfirmed (no on-disk reference) or a detour into another installed module
            ev.severity = core::Severity::MEDIUM;
            ev.threat_score = 30;
        } else if (breakpoint) {
            ev.severity = core::Severity::HIGH;     // debugger software breakpoint
            ev.threat_score = 60;
        } else {
            ev.severity = core::Severity::CRITICAL; // detour into unbacked memory / unknown patch
            ev.threat_score = 90;
        }

        bool restored = false;
        // Only neutralise patches according to the configured repair policy; never "unhook" another
        // installed module unless REPAIR_ALL is explicitly enabled.
        if (repair_policy_ != UnhookRepairPolicy::DETECT_ONLY && disk.valid && api.restorable) {
            if (!intoExternalModule || repair_policy_ == UnhookRepairPolicy::REPAIR_ALL) {
                restored = AutoRestoreHook(info);
            }
        }

        std::ostringstream ss;
        ss << "Inline hook detected on routine '" << info.function_name << "' [" << Hex(info.function_address)
           << "] Hook Type: " << info.hook_type;
        if (info.target_destination) {
            ss << " -> Target: " << Hex(info.target_destination)
               << (intoModule ? " (" + BaseNameOf(targetModule) + ")" : std::string(" (unbacked memory)"));
        }
        if (restored) ss << " [RESTORED to on-disk prologue]";
        ev.details = ss.str();
        events.push_back(ev);
    }

    auto tableEvents = AuditImportExportTables();
    events.insert(events.end(), tableEvents.begin(), tableEvents.end());

    return events;
}

std::optional<core::DetectionEvent> Unhooker::InspectTableEntry(
    const std::string& table_type,
    const std::string& symbol_name,
    uintptr_t slot_address,
    uintptr_t resolved_target
) {
    if (resolved_target < 0x10000ULL) return std::nullopt;

    auto regions = MemoryScanner::Instance().QueryMemoryRegions();
    for (const auto& r : regions) {
        if (resolved_target >= r.start && resolved_target < r.end) {
            if (r.pathname == "[vdso]" || r.pathname == "[vsyscall]") {
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
                ev.type = core::DetectionType::IAT_GOT_HOOK_DETECTED;
                ev.severity = core::Severity::CRITICAL;
                ev.component = "Unhooker::TableIntegrity";
                std::ostringstream ss;
                ss << table_type << " slot for '" << symbol_name << "' [" << Hex(slot_address)
                   << "] redirects to non-executable region " << Hex(resolved_target);
                ev.details = ss.str();
                ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
                ev.threat_score = 95;
                return ev;
            }
            if (!genuineBacked && !MemoryScanner::Instance().HostUsesJit()) {
                core::DetectionEvent ev;
                ev.type = core::DetectionType::IAT_GOT_HOOK_DETECTED;
                ev.severity = core::Severity::CRITICAL;
                ev.component = "Unhooker::TableIntegrity";
                std::ostringstream ss;
                ss << table_type << " slot for '" << symbol_name << "' [" << Hex(slot_address)
                   << "] hijacked to unbacked anonymous executable memory " << Hex(resolved_target);
                ev.details = ss.str();
                ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
                ev.threat_score = 95;
                return ev;
            }
            return std::nullopt;
        }
    }

    core::DetectionEvent ev;
    ev.type = core::DetectionType::IAT_GOT_HOOK_DETECTED;
    ev.severity = core::Severity::HIGH;
    ev.component = "Unhooker::TableIntegrity";
    std::ostringstream ss;
    ss << table_type << " slot for '" << symbol_name << "' [" << Hex(slot_address)
       << "] points to unmapped address " << Hex(resolved_target);
    ev.details = ss.str();
    ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
    ev.threat_score = 80;
    return ev;
}

std::vector<core::DetectionEvent> Unhooker::AuditImportExportTables() {
    std::vector<core::DetectionEvent> events;

#if defined(_WIN32)
    HMODULE hMain = GetModuleHandleW(nullptr);
    if (!hMain) return events;
    auto base = reinterpret_cast<uintptr_t>(hMain);
    auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return events;
    auto nt = reinterpret_cast<const IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return events;

    const auto& impDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (impDir.VirtualAddress && impDir.Size) {
        auto desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(base + impDir.VirtualAddress);
        for (; desc->Name != 0 && desc->FirstThunk != 0; ++desc) {
            const char* dllName = reinterpret_cast<const char*>(base + desc->Name);
            auto thunk = reinterpret_cast<const IMAGE_THUNK_DATA*>(base + desc->FirstThunk);
            auto origThunk = desc->OriginalFirstThunk
                ? reinterpret_cast<const IMAGE_THUNK_DATA*>(base + desc->OriginalFirstThunk)
                : thunk;
            for (; thunk->u1.Function != 0; ++thunk, ++origThunk) {
                uintptr_t slotAddr = reinterpret_cast<uintptr_t>(&thunk->u1.Function);
                uintptr_t fnTarget = static_cast<uintptr_t>(thunk->u1.Function);
                std::string symName = dllName ? dllName : "IAT";
                if (!(origThunk->u1.Ordinal & IMAGE_ORDINAL_flag)) {
                    auto byName = reinterpret_cast<const IMAGE_IMPORT_BY_NAME*>(base + origThunk->u1.AddressOfData);
                    symName += std::string("!") + reinterpret_cast<const char*>(byName->Name);
                }
                auto ev = InspectTableEntry("PE_IAT", symName, slotAddr, fnTarget);
                if (ev.has_value()) events.push_back(*ev);
            }
        }
    }
#else
    struct GotWalkCtx {
        Unhooker* self;
        std::vector<core::DetectionEvent>* outEvents;
    };
    GotWalkCtx ctx{this, &events};

    dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* data) -> int {
        // Inspect the main executable's GOT/PLT table (dlpi_name is empty for main binary)
        if (!info->dlpi_name || info->dlpi_name[0] != '\0') return 0;
        auto* c = static_cast<GotWalkCtx*>(data);
        uintptr_t base = static_cast<uintptr_t>(info->dlpi_addr);

        const ElfW(Dyn)* dyn = nullptr;
        for (int i = 0; i < info->dlpi_phnum; ++i) {
            if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
                dyn = reinterpret_cast<const ElfW(Dyn)*>(base + info->dlpi_phdr[i].p_vaddr);
                break;
            }
        }
        if (!dyn) return 0;

        uintptr_t jmprel = 0;
        size_t pltrelsz = 0;
        uintptr_t symtab = 0;
        uintptr_t strtab = 0;
        uintptr_t pltgot = 0;

        for (const ElfW(Dyn)* d = dyn; d->d_tag != DT_NULL; ++d) {
            switch (d->d_tag) {
                case DT_JMPREL:   jmprel = static_cast<uintptr_t>(d->d_un.d_ptr); break;
                case DT_PLTRELSZ: pltrelsz = static_cast<size_t>(d->d_un.d_val); break;
                case DT_SYMTAB:   symtab = static_cast<uintptr_t>(d->d_un.d_ptr); break;
                case DT_STRTAB:   strtab = static_cast<uintptr_t>(d->d_un.d_ptr); break;
                case DT_PLTGOT:   pltgot = static_cast<uintptr_t>(d->d_un.d_ptr); break;
                default: break;
            }
        }
        // On glibc, d_ptr in memory is already relocated; if not (< base), add base
        if (jmprel && jmprel < base) jmprel += base;
        if (symtab && symtab < base) symtab += base;
        if (strtab && strtab < base) strtab += base;
        if (pltgot && pltgot < base) pltgot += base;

        if (!jmprel || !pltrelsz || !IsReadableAddress(jmprel, pltrelsz)) return 0;

        size_t count = pltrelsz / sizeof(ElfW(Rela));
        const auto* relas = reinterpret_cast<const ElfW(Rela)*>(jmprel);
        for (size_t i = 0; i < count && i < 512; ++i) {
            uintptr_t gotSlot = base + relas[i].r_offset;
            if (!IsReadableAddress(gotSlot, sizeof(uintptr_t))) continue;
            uintptr_t resolved = *reinterpret_cast<const uintptr_t*>(gotSlot);
            if (resolved == 0) continue;

            std::string symName = "plt_slot_" + std::to_string(i);
#if defined(ELF64_R_SYM)
            uint32_t symIdx = static_cast<uint32_t>(ELF64_R_SYM(relas[i].r_info));
            if (symtab && strtab && symIdx > 0 && symIdx < 4096) {
                uintptr_t symAddr = symtab + symIdx * sizeof(ElfW(Sym));
                if (IsReadableAddress(symAddr, sizeof(ElfW(Sym)))) {
                    const auto* sym = reinterpret_cast<const ElfW(Sym)*>(symAddr);
                    if (sym->st_name > 0 && IsReadableAddress(strtab + sym->st_name, 1)) {
                        symName = reinterpret_cast<const char*>(strtab + sym->st_name);
                    }
                }
            }
#endif
            auto ev = c->self->InspectTableEntry("ELF_GOT_PLT", symName, gotSlot, resolved);
            if (ev.has_value()) {
                c->outEvents->push_back(*ev);
            }
        }
        return 1;
    }, &ctx);
#endif

    return events;
}

bool Unhooker::RestoreHook(const HookInfo& hook, const uint8_t* original_bytes, size_t length) {
    if (hook.function_address == 0 || !original_bytes || length == 0 || length > 64) return false;
    void* targetAddr = reinterpret_cast<void*>(hook.function_address);

#if defined(_WIN32)
    // WriteProcessMemory adjusts protection internally and restores it atomically from our view
    SIZE_T written = 0;
    if (!WriteProcessMemory(GetCurrentProcess(), targetAddr, original_bytes, length, &written) || written != length) {
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), targetAddr, length);
    return true;
#else
    if (WriteViaProcMem(hook.function_address, original_bytes, length)) {
        return true;
    }

    // Fallback (e.g. /proc unavailable): briefly add write permission, never dropping exec so
    // concurrently running threads keep executing.
    long pageSize = sysconf(_SC_PAGESIZE);
    if (pageSize <= 0) pageSize = 4096;
    uintptr_t pageStart = hook.function_address & ~(static_cast<uintptr_t>(pageSize) - 1);
    size_t mappingLen = (hook.function_address + length - pageStart + pageSize - 1) & ~(static_cast<uintptr_t>(pageSize) - 1);

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
    DiskPrologue disk = CachedDiskPrologue(hook.function_address);
    if (!disk.valid) return false;

    // Restore byte-by-byte only where the disk image is authoritative (relocated bytes keep the
    // loader's value), coalescing contiguous runs into single writes.
    const auto* mem = reinterpret_cast<const uint8_t*>(hook.function_address);
    bool any = false, ok = true;
    size_t i = 0;
    while (i < kPrologueLen) {
        if (!disk.mask[i] || mem[i] == disk.bytes[i]) { ++i; continue; }
        size_t j = i;
        while (j < kPrologueLen && disk.mask[j]) ++j;
        HookInfo part = hook;
        part.function_address = hook.function_address + i;
        ok = RestoreHook(part, disk.bytes + i, j - i) && ok;
        any = true;
        i = j;
    }
    return any && ok;
}

} // namespace noescape::memory
