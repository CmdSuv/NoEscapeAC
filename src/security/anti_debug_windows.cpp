#if defined(_WIN32)

#include "noescape/security/anti_debug.hpp"
#include "noescape/core/obfuscation.hpp"
#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <intrin.h>
#include <algorithm>
#include <cctype>
#include <ctime>
#include "noescape/core/envutil.hpp"

#if defined(_MSC_VER)
#pragma comment(lib, "ntdll.lib")
#endif

namespace noescape::security {

namespace {

std::string ToLower(const std::string& str) {
    std::string s = str;
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return s;
}

typedef NTSTATUS(NTAPI* pfnNtSetInformationThread)(
    HANDLE ThreadHandle,
    ULONG ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength
);

typedef NTSTATUS(NTAPI* pfnNtQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

} // namespace

bool AntiDebug::IsDebuggerAttached() {
    // 1. Direct Win32 API Check
    if (IsDebuggerPresent()) return true;

    // 2. Remote Debugger Attached Check
    BOOL isRemotePresent = FALSE;
    if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &isRemotePresent) && isRemotePresent) {
        return true;
    }

    // 3. PEB BeingDebugged & NtGlobalFlag verification
#if defined(_M_X64) || defined(__x86_64__)
    auto peb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
    auto peb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
    if (peb) {
        if (peb->BeingDebugged) return true;

        // NtGlobalFlag check (offset 0xBC on x64, 0x68 on x86)
        // Flags: FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) | FLG_HEAP_VALIDATE_PARAMETERS (0x40)
#if defined(_M_X64) || defined(__x86_64__)
        DWORD ntGlobalFlag = *reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(peb) + 0xBC);
#else
        DWORD ntGlobalFlag = *reinterpret_cast<PDWORD>(reinterpret_cast<PBYTE>(peb) + 0x68);
#endif
        (void)ntGlobalFlag; // heap-debug flags are set by gflags/AppVerifier too: not used as proof
    }

    // 4. NtQueryInformationProcess (ProcessDebugPort = 7)
    HMODULE hNtdll = GetModuleHandleA(NOESCAPE_XOR("ntdll.dll"));
    if (hNtdll) {
        auto pNtQuery = reinterpret_cast<pfnNtQueryInformationProcess>(reinterpret_cast<void*>(
            GetProcAddress(hNtdll, NOESCAPE_XOR("NtQueryInformationProcess"))
        ));
        if (pNtQuery) {
            DWORD_PTR debugPort = 0;
            NTSTATUS status = pNtQuery(GetCurrentProcess(), 7, &debugPort, sizeof(debugPort), nullptr);
            if (status == 0 && debugPort != 0) return true;
        }
    }

    return false;
}

bool AntiDebug::CheckHardwareBreakpoints() {
    DWORD currentPid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0x000000FF));
        }
        return false;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    bool foundBreakpoint = false;

    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == currentPid) {
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) {
                    CONTEXT ctx{};
                    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(hThread, &ctx)) {
                        if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3 || (ctx.Dr7 & 0x000000FF)) {
                            foundBreakpoint = true;
                            CloseHandle(hThread);
                            break;
                        }
                    }
                    CloseHandle(hThread);
                }
            }
        } while (Thread32Next(snap, &te));
    }

    CloseHandle(snap);
    return foundBreakpoint;
}

bool AntiDebug::CheckTracerPid(int& outPid) {
    outPid = 0;
    return false;
}

bool AntiDebug::CheckWchanWait() {
    return false;
}

bool AntiDebug::HideCurrentThread() {
    HMODULE hNtdll = GetModuleHandleA(NOESCAPE_XOR("ntdll.dll"));
    if (!hNtdll) return false;

    auto pNtSetInfo = reinterpret_cast<pfnNtSetInformationThread>(reinterpret_cast<void*>(
        GetProcAddress(hNtdll, NOESCAPE_XOR("NtSetInformationThread"))
    ));
    if (!pNtSetInfo) return false;

    // ThreadHideFromDebugger = 0x11
    NTSTATUS status = pNtSetInfo(GetCurrentThread(), 0x11, nullptr, 0);
    return status == 0;
}

bool AntiDebug::CheckKnownDebuggerProcesses(const std::vector<std::string>& blacklist, std::string& detectedName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            char nameBuf[MAX_PATH]{};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameBuf, MAX_PATH, nullptr, nullptr);
            std::string exeName = ToLower(nameBuf);
            if (exeName.size() > 4 && exeName.compare(exeName.size() - 4, 4, ".exe") == 0) {
                exeName.resize(exeName.size() - 4);
            }

            for (const auto& target : blacklist) {
                if (core::NameMatchesEntry(exeName, ToLower(target))) {
                    detectedName = nameBuf;
                    CloseHandle(snap);
                    return true;
                }
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return false;
}

std::vector<core::DetectionEvent> AntiDebug::PerformAudit(const std::vector<std::string>& blacklist) {
    std::vector<core::DetectionEvent> events;

    if (IsDebuggerAttached()) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ANTI_DEBUG_TRACER;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "AntiDebug::WindowsDebugger";
        ev.details = "Active debugger detected via PEB / RemoteDebugger / ProcessDebugPort";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 60;
        events.push_back(ev);
    }

    if (CheckHardwareBreakpoints()) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ANTI_DEBUG_HARDWARE_BP;
        ev.severity = core::Severity::CRITICAL;
        ev.component = "AntiDebug::HardwareRegisters";
        ev.details = "Hardware breakpoint detected in CPU debug registers (DR0-DR7)";
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 90;
        events.push_back(ev);
    }

    std::string detectedTool;
    if (CheckKnownDebuggerProcesses(blacklist, detectedTool)) {
        core::DetectionEvent ev;
        ev.type = core::DetectionType::ANTI_DEBUG_TOOL;
        ev.severity = core::Severity::HIGH;
        ev.component = "AntiDebug::ProcessScanner";
        ev.details = "Known debugger / memory dumper running: " + detectedTool;
        ev.timestamp = static_cast<uint64_t>(std::time(nullptr));
        ev.threat_score = 20; // also scored by ProcessAnalyzer
        events.push_back(ev);
    }

    return events;
}

} // namespace noescape::security

#endif
