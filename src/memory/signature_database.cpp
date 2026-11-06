#include "noescape/memory/signature_database.hpp"
#include <mutex>
#include <algorithm>

namespace noescape::memory {

const char* CheatSignature::CategoryToString(SignatureCategory cat) {
    switch (cat) {
        case SignatureCategory::HOOK_FRAMEWORK: return "HOOK_FRAMEWORK";
        case SignatureCategory::INJECTOR_STUB: return "INJECTOR_STUB";
        case SignatureCategory::DMA_TOOL: return "DMA_TOOL";
        case SignatureCategory::DEBUGGER_INTERFACE: return "DEBUGGER_INTERFACE";
        case SignatureCategory::SHELLCODE_PROLOGUE: return "SHELLCODE_PROLOGUE";
        case SignatureCategory::OVERLAY_HOOK: return "OVERLAY_HOOK";
        case SignatureCategory::PACKER_PROTECTOR: return "PACKER_PROTECTOR";
        case SignatureCategory::SPEEDHACK_WRAPPER: return "SPEEDHACK_WRAPPER";
        case SignatureCategory::GENERIC:
        default: return "GENERIC";
    }
}

const char* CheatSignature::RuleToString(MemoryTargetRule rule) {
    switch (rule) {
        case MemoryTargetRule::UNBACKED_ONLY: return "UNBACKED_ONLY";
        case MemoryTargetRule::ALL_EXECUTABLE: return "ALL_EXECUTABLE";
        case MemoryTargetRule::ANONYMOUS_DATA: return "ANONYMOUS_DATA";
        case MemoryTargetRule::ANY_ANONYMOUS: return "ANY_ANONYMOUS";
        case MemoryTargetRule::ALL_REGIONS: return "ALL_REGIONS";
        default: return "UNKNOWN";
    }
}

bool CheatSignature::IsTargetMatched(MemoryTargetRule rule, bool isGenuineFile, bool isExecutable, bool isReadable) {
    if (!isReadable) return false;
    switch (rule) {
        case MemoryTargetRule::UNBACKED_ONLY:
            return !isGenuineFile && isExecutable;
        case MemoryTargetRule::ALL_EXECUTABLE:
            return isExecutable;
        case MemoryTargetRule::ANONYMOUS_DATA:
            return !isGenuineFile && !isExecutable;
        case MemoryTargetRule::ANY_ANONYMOUS:
            return !isGenuineFile;
        case MemoryTargetRule::ALL_REGIONS:
            return true;
        default:
            return !isGenuineFile && isExecutable;
    }
}

namespace {
    std::mutex g_dbMutex;
    std::vector<CheatSignature> g_signatures;
    bool g_initialized = false;
}

std::vector<CheatSignature> SignatureDatabase::CreateDefaultSignatures() {
    std::vector<CheatSignature> list;
    list.reserve(48);

    // =========================================================================
    // 1. Hooking Libraries and Trampolines (HOOK_FRAMEWORK)
    // =========================================================================
    list.emplace_back(
        "48 B8 ? ? ? ? ? ? ? ? FF E0",
        "Generic_X64_Jmp_Trampoline",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Generic x64 absolute jump trampoline (mov rax, imm64; jmp rax)"
    );

    list.emplace_back(
        "49 BB ? ? ? ? ? ? ? ? 41 FF E3",
        "Generic_X64_R11_Jmp",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Generic x64 register jump trampoline (mov r11, imm64; jmp r11)"
    );

    list.emplace_back(
        "68 ? ? ? ? C7 44 24 04 ? ? ? ? C3",
        "PushRet_X64_Hook",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Generic x64 push-ret indirect jump trampoline"
    );

    list.emplace_back(
        "49 BA ? ? ? ? ? ? ? ? 41 FF E2",
        "MinHook_X64_R10_Trampoline",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "MinHook x64 relay trampoline (mov r10, imm64; jmp r10)"
    );

    list.emplace_back(
        "FF 25 00 00 00 00 ? ? ? ? ? ? ? ?",
        "MinHook_X64_RipIndirect",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "MinHook / Detours 14-byte RIP-relative absolute jump (jmp qword [rip+0])"
    );

    list.emplace_back(
        "48 FF 25 00 00 00 00 ? ? ? ? ? ? ? ?",
        "Microsoft_Detours_RipIndirect",
        SignatureCategory::HOOK_FRAMEWORK,
        95,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Microsoft Detours x64 RIP-relative detour stub"
    );

    list.emplace_back(
        "EB F9 55 8B EC",
        "Microsoft_Detours_Hotpatch32",
        SignatureCategory::HOOK_FRAMEWORK,
        95,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Microsoft Detours 32-bit hotpatch detour pattern"
    );

    list.emplace_back(
        "50 48 B8 ? ? ? ? ? ? ? ? 48 87 04 24 C3",
        "PolyHook_X64_PushXchgRet",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "PolyHook x64 push-mov-xchg-ret hook stub"
    );

    list.emplace_back(
        "50 48 B8 ? ? ? ? ? ? ? ? 48 89 04 24 C3",
        "PolyHook_X64_PushRet",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "PolyHook x64 push-mov-mov-ret hook stub"
    );

    list.emplace_back(
        "48 B8 ? ? ? ? ? ? ? ? 50 C3",
        "Substrate_X64_PushRet",
        SignatureCategory::HOOK_FRAMEWORK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Cydia Substrate x64 mov-push-ret trampoline"
    );

    // =========================================================================
    // 2. Known Cheat Injectors and Shellcodes (INJECTOR_STUB)
    // =========================================================================
    list.emplace_back(
        "48 83 EC 20 B8 01 00 00 00 89 ? ? ? FF D2 48 83 C4 20",
        "ManualMap_DllMain_Invocation",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "ManualMap injector shellcode invoking DllMain with DLL_PROCESS_ATTACH"
    );

    list.emplace_back(
        "48 83 EC 28 48 89 4C 24 20 48 89 54 24 28 4C 89 44 24 30",
        "ManualMap_X64_LoaderStub",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "ManualMap loader stack frame setup and parameter preservation"
    );

    list.emplace_back(
        "48 8B ? 8B ? ? ? ? ? 48 03 ? 48 89 ? 48 83 C0",
        "ManualMap_Relocation_Loop",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "ManualMap PE image base relocation delta applicator loop"
    );

    list.emplace_back(
        "42 6C 61 63 6B 62 6F 6E 65", // "Blackbone"
        "BlackBone_Driver_Signature",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "BlackBone kernel/userland memory hacking and injection library identifier"
    );

    list.emplace_back(
        "48 83 EC 28 48 89 4C 24 20 48 89 54 24 28 48 8B",
        "BlackBone_APC_Injection_Stub",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "BlackBone APC execution trampoline stub"
    );

    list.emplace_back(
        "58 65 6E 6F 73 49 6E 6A 65 63 74", // "XenosInject"
        "Xenos_Injector_Header",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Xenos injector memory payload marker"
    );

    list.emplace_back(
        "48 83 EC 28 49 89 C8 48 89 D1 48 8B 05",
        "SystemInformer_Hook_Stub",
        SignatureCategory::INJECTOR_STUB,
        85,
        core::Severity::HIGH,
        MemoryTargetRule::UNBACKED_ONLY,
        "Process Hacker / System Informer userland hook stub"
    );

    list.emplace_back(
        "4B 53 44 75 6D 70 65 72", // "KSDumper"
        "KsDumper_Driver_Signature",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "KsDumper ring0 memory dumper device identifier"
    );

    list.emplace_back(
        "81 FA 00 22 22 00 74",
        "KsDumper_IOCTL_Dispatch",
        SignatureCategory::INJECTOR_STUB,
        90,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "KsDumper memory copy IOCTL verification dispatch"
    );

    list.emplace_back(
        "52 65 66 6C 65 63 74 69 76 65 4C 6F 61 64 65 72", // "ReflectiveLoader"
        "Reflective_Loader_Export",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Reflective DLL injection exported loader stub marker"
    );

    list.emplace_back(
        "48 83 EC 28 65 48 8B 04 25 60 00 00 00 48 8B 50 18",
        "ManualMap_LdrLoadDll_Resolver",
        SignatureCategory::INJECTOR_STUB,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "ManualMap PE loader resolving LdrLoadDll from PEB_LDR_DATA"
    );

    // =========================================================================
    // 3. Direct Memory Access (DMA) Tools (DMA_TOOL)
    // =========================================================================
    // NOTE: text-string signatures scan ordinary data pages, where attacker-controlled strings
    // (player names, chat) can legitimately appear. They are low-weight, corroborating evidence only.
    list.emplace_back(
        "4C 43 5F 4D 45 4D", // "LC_MEM"
        "LeechCore_Memory_Header",
        SignatureCategory::DMA_TOOL,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "LeechCore PCIe DMA physical memory snapshot banner"
    );

    list.emplace_back(
        "4C 45 45 43 48 43 4F 52 45", // "LEECHCORE"
        "LeechCore_Device_Config",
        SignatureCategory::DMA_TOOL,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "LeechCore hardware configuration and interface header"
    );

    list.emplace_back(
        "56 4D 4D 44 4C 4C", // "VMMDLL"
        "MemProcFS_VmmDll",
        SignatureCategory::DMA_TOOL,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "MemProcFS PCIe DMA virtual memory exploration engine tag"
    );

    list.emplace_back(
        "4D 45 4D 50 52 4F 43 46 53", // "MEMPROCFS"
        "MemProcFS_Vfs_Header",
        SignatureCategory::DMA_TOOL,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "MemProcFS DMA filesystem mount header"
    );

    // =========================================================================
    // 4. Debugger & Hypervisor Interfaces (DEBUGGER_INTERFACE)
    // =========================================================================
    list.emplace_back(
        "0F 01 DA 48 89 C8",
        "CheatEngine_DBVM_Call",
        SignatureCategory::DEBUGGER_INTERFACE,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "Cheat Engine Dark Byte Virtual Machine hypercall sequence (vmcall; mov rax, rcx)"
    );

    list.emplace_back(
        "44 42 4B 36 34", // "DBK64"
        "CheatEngine_DBK_Driver",
        SignatureCategory::DEBUGGER_INTERFACE,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Cheat Engine Dbk64 kernel driver device string"
    );

    list.emplace_back(
        "43 45 4C 75 61 53 65 72 76 65 72", // "CELuaServer"
        "CheatEngine_Lua_Core",
        SignatureCategory::DEBUGGER_INTERFACE,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Cheat Engine Lua scripting engine communication pipe"
    );

    list.emplace_back(
        "66 72 69 64 61 2D 61 67 65 6E 74", // "frida-agent"
        "Frida_Agent_Signature",
        SignatureCategory::DEBUGGER_INTERFACE,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Frida dynamic binary instrumentation runtime agent library"
    );

    list.emplace_back(
        "50 48 B8 ? ? ? ? ? ? ? ? 48 89 04 24 C3",
        "Frida_Gum_Interceptor",
        SignatureCategory::DEBUGGER_INTERFACE,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "Frida Gum dynamic inline interceptor replacement stub"
    );

    list.emplace_back(
        "50 53 51 52 41 50 41 51 41 52 41 53 48 B8",
        "Frida_Stalker_Prologue",
        SignatureCategory::DEBUGGER_INTERFACE,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "Frida Stalker execution tracing register spill sequence"
    );

    list.emplace_back(
        "43 45 5F 56 45 48", // "CE_VEH"
        "CheatEngine_VEH_Debugger",
        SignatureCategory::DEBUGGER_INTERFACE,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Cheat Engine Vectored Exception Handling (VEH) debugger marker"
    );

    // =========================================================================
    // 5. Shellcode Prologues (SHELLCODE_PROLOGUE)
    // =========================================================================
    list.emplace_back(
        "E8 00 00 00 00 58",
        "Generic_EggHunter_CallPop",
        SignatureCategory::SHELLCODE_PROLOGUE,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Position-independent shellcode delta-offset resolution (call $+5; pop rax)"
    );

    list.emplace_back(
        "48 31 C0 65 48 8B 04 25 60 00 00 00",
        "Generic_Win64_Peb_Lookup",
        SignatureCategory::SHELLCODE_PROLOGUE,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Injected shellcode walking PEB from GS:[0x60]"
    );

    list.emplace_back(
        "48 31 C0 48 31 FF 48 31 F6 0F 05",
        "Generic_Linux_Syscall_Stub",
        SignatureCategory::SHELLCODE_PROLOGUE,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Raw unbacked direct syscall invocation shellcode"
    );

    // =========================================================================
    // 6. Overlay & Rendering Hooks (OVERLAY_HOOK)
    // =========================================================================
    list.emplace_back(
        "49 6D 47 75 69 20 4F 76 65 72 6C 61 79", // "ImGui Overlay"
        "ImGui_Overlay_Header",
        SignatureCategory::OVERLAY_HOOK,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Injected Dear-ImGui overlay render identity"
    );

    list.emplace_back(
        "44 65 61 72 20 49 6D 47 75 69", // "Dear ImGui"
        "ImGui_DearImGui_Banner",
        SignatureCategory::OVERLAY_HOOK,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Dear-ImGui framework signature in unbacked memory allocation"
    );

    list.emplace_back(
        "48 89 5C 24 08 48 89 74 24 10 57 48 83 EC 30 48 8B D9 49 8B F8",
        "D3D_SwapChain_Present_Hook",
        SignatureCategory::OVERLAY_HOOK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "IDXGISwapChain Present inline rendering hook prologue"
    );

    list.emplace_back(
        "48 B8 ? ? ? ? ? ? ? ? 48 89 05 ? ? ? ? 48 8D 05",
        "D3D11_Present_VTable_Trampoline",
        SignatureCategory::OVERLAY_HOOK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Direct3D 11 Present VTable hook redirector"
    );

    list.emplace_back(
        "48 89 5C 24 10 48 89 6C 24 18 48 89 74 24 20 57 48 83 EC 20 41 8B D8",
        "D3D12_CommandQueue_Hook",
        SignatureCategory::OVERLAY_HOOK,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "Direct3D 12 ExecuteCommandLists detour relay trampoline"
    );

    // =========================================================================
    // 7. Cheat Packers and Protectors (PACKER_PROTECTOR)
    // =========================================================================
    list.emplace_back(
        "55 50 58 30", // "UPX0"
        "UPX_Section_0",
        SignatureCategory::PACKER_PROTECTOR,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "UPX packer header segment 0 in anonymous allocation"
    );

    list.emplace_back(
        "55 50 58 31", // "UPX1"
        "UPX_Section_1",
        SignatureCategory::PACKER_PROTECTOR,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "UPX packer header segment 1 in anonymous allocation"
    );

    list.emplace_back(
        "48 8D 64 24 F8 48 89 04 24 48 B8 ? ? ? ? ? ? ? ? 50 C3",
        "VMProtect_X64_Entry",
        SignatureCategory::PACKER_PROTECTOR,
        95,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "VMProtect x64 virtual machine dispatcher entry point"
    );

    list.emplace_back(
        "54 68 65 6D 69 64 61", // "Themida"
        "ThemIDA_SDK_Marker",
        SignatureCategory::PACKER_PROTECTOR,
        80,
        core::Severity::HIGH,
        MemoryTargetRule::UNBACKED_ONLY,
        "ThemIDA / WinLicense protected payload indicator"
    );

    list.emplace_back(
        "55 50 58 32", // "UPX2"
        "UPX_Section_2",
        SignatureCategory::PACKER_PROTECTOR,
        70,
        core::Severity::HIGH,
        MemoryTargetRule::UNBACKED_ONLY,
        "UPX packer header segment 2 in unbacked allocation"
    );

    list.emplace_back(
        "2E 76 6D 70 30", // ".vmp0"
        "VMProtect_Section_Tag",
        SignatureCategory::PACKER_PROTECTOR,
        90,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "VMProtect virtual machine section tag in unbacked memory"
    );

    list.emplace_back(
        "2E 74 68 65 6D 69 64 61", // ".themida"
        "ThemIDA_Section_Tag",
        SignatureCategory::PACKER_PROTECTOR,
        85,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::UNBACKED_ONLY,
        "ThemIDA protected section header tag in unbacked memory"
    );

    // =========================================================================
    // 8. Speedhack Wrappers (SPEEDHACK_WRAPPER)
    // =========================================================================
    list.emplace_back(
        "53 70 65 65 64 68 61 63 6B 2E 64 6C 6C", // "Speedhack.dll"
        "Speedhack_CE_ModuleName",
        SignatureCategory::SPEEDHACK_WRAPPER,
        30,
        core::Severity::MEDIUM,
        MemoryTargetRule::ANY_ANONYMOUS,
        "Cheat Engine Speedhack DLL reference string"
    );

    list.emplace_back(
        "48 89 5C 24 08 57 48 83 EC 20 ? ? ? ? 48 85 C0 74",
        "Speedhack_QPC_Detour",
        SignatureCategory::SPEEDHACK_WRAPPER,
        100,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "Speedhack QueryPerformanceCounter timing detour wrapper"
    );

    list.emplace_back(
        "48 83 EC 28 E8 ? ? ? ? 48 85 C0 74 ? 48 8B 00 48 83 C4 28 C3",
        "Speedhack_TimeGetTime_Detour",
        SignatureCategory::SPEEDHACK_WRAPPER,
        90,
        core::Severity::FATAL_BAN,
        MemoryTargetRule::ALL_EXECUTABLE,
        "Speedhack timeGetTime hook wrapper multiplying delta ticks"
    );

    return list;
}

std::vector<CheatSignature> SignatureDatabase::GetAllSignatures() {
    std::lock_guard<std::mutex> lock(g_dbMutex);
    if (!g_initialized) {
        g_signatures = CreateDefaultSignatures();
        g_initialized = true;
    }
    return g_signatures;
}

std::vector<CheatSignature> SignatureDatabase::GetByCategory(SignatureCategory category) {
    auto all = GetAllSignatures();
    std::vector<CheatSignature> filtered;
    for (const auto& sig : all) {
        if (sig.GetCategory() == category) {
            filtered.push_back(sig);
        }
    }
    return filtered;
}

std::vector<CheatSignature> SignatureDatabase::GetByTargetRule(MemoryTargetRule rule) {
    auto all = GetAllSignatures();
    std::vector<CheatSignature> filtered;
    for (const auto& sig : all) {
        if (sig.GetTargetRule() == rule) {
            filtered.push_back(sig);
        }
    }
    return filtered;
}

std::optional<CheatSignature> SignatureDatabase::FindByName(std::string_view name) {
    auto all = GetAllSignatures();
    for (const auto& sig : all) {
        if (sig.GetName() == name) {
            return sig;
        }
    }
    return std::nullopt;
}

void SignatureDatabase::RegisterCustomSignature(CheatSignature signature) {
    std::lock_guard<std::mutex> lock(g_dbMutex);
    if (!g_initialized) {
        g_signatures = CreateDefaultSignatures();
        g_initialized = true;
    }
    // Update existing if matching name, otherwise push
    auto it = std::find_if(g_signatures.begin(), g_signatures.end(), [&](const CheatSignature& s) {
        return s.GetName() == signature.GetName();
    });
    if (it != g_signatures.end()) {
        *it = std::move(signature);
    } else {
        g_signatures.push_back(std::move(signature));
    }
}

void SignatureDatabase::Reset() {
    std::lock_guard<std::mutex> lock(g_dbMutex);
    g_signatures = CreateDefaultSignatures();
    g_initialized = true;
}

size_t SignatureDatabase::Count() {
    std::lock_guard<std::mutex> lock(g_dbMutex);
    if (!g_initialized) {
        g_signatures = CreateDefaultSignatures();
        g_initialized = true;
    }
    return g_signatures.size();
}

std::vector<Pattern> SignatureDatabase::ToPatterns(const std::vector<CheatSignature>& signatures) {
    std::vector<Pattern> patterns;
    patterns.reserve(signatures.size());
    for (const auto& sig : signatures) {
        patterns.push_back(sig);
    }
    return patterns;
}

std::vector<std::pair<uintptr_t, uintptr_t>> SignatureDatabase::GetInternalSpans() {
    std::lock_guard<std::mutex> lock(g_dbMutex);
    std::vector<std::pair<uintptr_t, uintptr_t>> spans;
    if (!g_initialized) {
        g_signatures = CreateDefaultSignatures();
        g_initialized = true;
    }
    if (!g_signatures.empty()) {
        uintptr_t vecStart = reinterpret_cast<uintptr_t>(g_signatures.data());
        uintptr_t vecEnd = vecStart + g_signatures.size() * sizeof(CheatSignature);
        spans.emplace_back(vecStart, vecEnd);
    }
    for (const auto& sig : g_signatures) {
        uintptr_t objStart = reinterpret_cast<uintptr_t>(&sig);
        spans.emplace_back(objStart, objStart + sizeof(CheatSignature));
        if (!sig.GetName().empty()) {
            uintptr_t s = reinterpret_cast<uintptr_t>(sig.GetName().data());
            spans.emplace_back(s, s + sig.GetName().size() + 1);
        }
        if (!sig.GetDescription().empty()) {
            uintptr_t s = reinterpret_cast<uintptr_t>(sig.GetDescription().data());
            spans.emplace_back(s, s + sig.GetDescription().size() + 1);
        }
        if (!sig.GetBytes().empty()) {
            uintptr_t s = reinterpret_cast<uintptr_t>(sig.GetBytes().data());
            spans.emplace_back(s, s + sig.GetBytes().size() * sizeof(PatternByte));
        }
    }
    return spans;
}

} // namespace noescape::memory
