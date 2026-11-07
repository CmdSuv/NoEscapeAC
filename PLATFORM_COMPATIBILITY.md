# NoEscapeAC — Cross-Platform Compatibility Specification

**Version:** 7.0 / Release 1.3  
**Supported Platforms:** Windows 10/11 x64, Linux x86_64 (glibc 2.31+), Proton/Wine  
**Attribution:** Omar Yiğitcan Mengü (`@CmdSuv`) & `OnlyCosmos` (`@OnlyCosmos`)

---

## 1. Operating System Abstraction Architecture

NoEscapeAC maintains strict parity between Windows and Linux without introducing OS-specific spaghetti code:

```
                              [NoEscape High-Level Subsystems]
                                             |
                  +--------------------------+--------------------------+
                  |                                                     |
                  v                                                     v
      [Windows x64 Native Subsystems]                       [Linux x86_64 Native Subsystems]
    - VirtualQueryEx / RPM / WPM                          - /proc/self/maps & /proc/self/mem
    - Toolhelp32 & NT Native APIs                         - /proc filesystem traversal & ptrace
    - PE Relocation & Section Parsing                     - ELF64 Dynsym & Rela.dyn Parsing
    - WinHTTP TLS & CryptoAPI / OpenSSL                   - POSIX Sockets & OpenSSL TLS
    - Registry Kernel DMA Protection                      - /sys/class/iommu & kernel cmdline
    - SetProcessMitigationPolicy                          - prctl(PR_SET_DUMPABLE, 0)
```

---

## 2. Windows 10 / 11 x64 Subsystem Implementation

| Security Capability | Windows Implementation Vector | Fallback / Error Handling |
|---|---|---|
| **Memory Segment Walk** | `VirtualQueryEx` iterating `MEMORY_BASIC_INFORMATION`. Filters `MEM_IMAGE`, `MEM_MAPPED`, `MEM_PRIVATE`. | Skips guarded and no-access pages cleanly. |
| **Code Unhooking** | Reads clean DLL image from `System32`, parses PE headers (`IMAGE_NT_HEADERS64`, `IMAGE_EXPORT_DIRECTORY`, `IMAGE_BASE_RELOCATION`), applies relocation masks, restores via `WriteProcessMemory`. | Preserves page protection using `VirtualProtect` RAII guards. |
| **Anti-Debugging** | `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, PEB `BeingDebugged` flag, `NtQueryInformationProcess(ProcessDebugPort)`. | Hardware breakpoint inspection via `GetThreadContext(CONTEXT_DEBUG_REGISTERS)`. |
| **DMA & IOMMU Inspection** | Queries Windows Registry for Kernel DMA Protection: `SYSTEM\CurrentControlSet\Control\DmaSecurity\AllowedBuses` and `SOFTWARE\Policies\Microsoft\Windows\Kernel DMA Protection`. | Gracefully returns `iommu_present=false` on legacy Windows 7/8. |
| **Secure Network Transport** | WinHTTP API supporting TLS 1.2 and TLS 1.3 with X.509 SPKI public key hash pinning. | Falls back to static OpenSSL library if WinHTTP is unavailable. |

---

## 3. Linux x86_64 Subsystem Implementation

| Security Capability | Linux Implementation Vector | Fallback / Error Handling |
|---|---|---|
| **Memory Segment Walk** | Parses `/proc/self/maps` parsing VMA address ranges, permissions (`rwxp`), device major/minor, and file inodes. | Validates against deleted binaries and anonymous heaps. |
| **Code Unhooking** | Reads ELF64 clean image from disk (`/lib/x86_64-linux-gnu` or `/usr/lib64`), parses ELF header, Program Headers, `.dynsym`, `.dynstr`, and `.rela.dyn` relocations. Restores via `/proc/self/mem` writing. | Avoids `mprotect(PROT_WRITE)` on read-only executable text to evade interposer hooks. |
| **Anti-Debugging** | `ptrace(PTRACE_TRACEME)`, `/proc/self/status` `TracerPid` inspection, hardware debug registers via `perf_event_open` (`HW_BREAKPOINT_X`). | Skips `PTRACE_TRACEME` cleanly when running under test harnesses (`NOESCAPE_TEST_MODE=1`). |
| **DMA & IOMMU Inspection** | Scans `/sys/class/iommu`, `/sys/kernel/iommu_groups`, and parses `/proc/cmdline` for `intel_iommu=on`, `amd_iommu=on`, and `iommu=pt`. | Returns safe defaults on virtual machines without physical PCI buses. |
| **Process Lockdown** | Invokes `prctl(PR_SET_DUMPABLE, 0)` to prevent unprivileged external process inspection. | Preserved cleanly across thread lifecycles. |

---

## 4. Proton / Steam Play & Wine Compatibility

Because many competitive gamers run Windows games under Proton on Linux:
1. **No Kernel Drivers:** Standard Windows kernel anti-cheats (Vanguard, Easy Anti-Cheat Driver, BattlEye Driver) fail or require complex VM compatibility under Wine. NoEscapeAC runs seamlessly under Wine.
2. **Wine Test Suite Verification:** The entire Windows test suite has been cross-compiled with MinGW Clang/GCC and verified under Wine, achieving **100% test pass rate**.
3. **NT API Emulation:** Wine's implementation of `VirtualQueryEx`, `ReadProcessMemory`, and `Toolhelp32` is fully supported.
