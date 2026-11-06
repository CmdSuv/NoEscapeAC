# 🛡️ NoEscape Anti-Cheat Engine (v7.0 / Release 1.2)

[![GitHub Release](https://img.shields.io/badge/Release-NoEscapeAC%201.2-red?style=for-the-badge&logo=github)](https://github.com/CmdSuv/NoEscapeAC/releases/tag/v1.2)
[![Download Zip](https://img.shields.io/badge/Download-Source%20Code%20(.zip)-darkred?style=for-the-badge&logo=github)](https://github.com/CmdSuv/NoEscapeAC/archive/refs/tags/v1.2.zip)
[![License: Non-Commercial Share-Alike](https://img.shields.io/badge/License-Non--Commercial%20Share--Alike-blue?style=for-the-badge)](LICENSE)

**NoEscape Anti-Cheat (NoEscapeAC)** is a modern, lightweight, and unified user-mode (Ring-3) anti-cheat and runtime integrity framework engineered in **C++20** for Linux and Windows. Designed to safeguard competitive multiplayer games and custom game launchers without intrusive kernel drivers, NoEscapeAC delivers defense-in-depth security: AVX2 SIMD byte pattern scanning, unbacked memory forensics with JVM/JIT HotSpot awareness, automatic inline API unhooking, PCIe DMA anomaly detection, statistical mouse kinematics (silent-aim / instant-snap heuristics), ESP fake-window overlay interception, and a standalone crimson security ban enforcement UI.

---

### 📦 Latest Release: NoEscapeAC 1.2
> **[Direct Download: NoEscapeAC 1.2 Source Code (.zip)](https://github.com/CmdSuv/NoEscapeAC/archive/refs/tags/v1.2.zip)**  
> **Release Tag**: `v1.2` | **Changelog & Release Notes**: [View on GitHub Releases](https://github.com/CmdSuv/NoEscapeAC/releases/tag/v1.2)

---

### ✨ Key Subsystems & Features

1. **Cross-Platform Architecture (Linux & Windows Ring-3)**:
   - Linux: `/proc` subsystem audit, `/proc/self/maps` page analysis, `dl_iterate_phdr` ELF parsing, and `mprotect` inline unhooking.
   - Windows: Win32/NTAPI direct PEB inspection, `NtQueryInformationProcess`, `Toolhelp32`, and `VirtualQueryEx`.
   - Compile-time XOR string obfuscation (`NOESCAPE_XOR`) and FNV-1a hashing (`NOESCAPE_HASH`).

2. **SIMD Pattern Scanner (AVX2 / SSE2 / Scalar)**:
   - High-throughput byte signature search utilizing AVX2 256-bit vector registers with automatic runtime CPU dispatch (AVX2 → SSE2 → scalar; the library loads on CPUs without AVX2).
   - Supports IDA-style wildcard patterns (`48 B8 ? ? ? ? ? ? ? ? FF E0`) and batch scanning in a single pass.

3. **Memory & Injection Analysis**:
   - **Unbacked Executable Memory Scanner**: Detects anonymous `RX`/`RWX` pages, reflective DLL / SO injection, deleted binary execution (`/proc/<pid>/exe (deleted)`), and memory-ghosted modules.
   - **Inline Hook Detector & Unhooker**: Identifies `0xE9` (JMP rel32), `0xEB` (JMP rel8), `0xFF 0x25` (JMP indirect), `MOV RAX; JMP RAX`, `PUSH/RET`, and `0xCC` (INT3) hooks on core system APIs and automatically restores clean instructions into memory.

4. **Overlay & ESP/Wallhack Detector (Rendering Hook & Fake Window Scanner)**:
   - **Fake Window Hijack Scanner**: Detects transparent/layered top-most fake windows (`WS_EX_LAYERED`, `WS_EX_TRANSPARENT`, `WS_EX_TOPMOST`) matching the game viewport bounding rect.
   - **Rendering Pipeline Integrity**: Inspects DirectX / Vulkan / OpenGL `Present`, `SwapBuffers`, and dynamic swapchain vtables to ensure function pointers reside strictly within loaded module address spaces and have not been redirected to unbacked trampolines or inline-hooked.
   - Linux overlay process detection across X11/Wayland display environments.

5. **Blackbox Crash/Violation Dumper**:
   - When a fatal security event occurs or threat score exceeds threshold, captures a compact, authenticated diagnostic snapshot:
     - Real-time timestamp & Hardware ID fingerprint.
     - Violating component & reason.
     - Stack backtrace return addresses (`backtrace()` on Linux / `CaptureStackBackTrace` on Windows).
     - Recent input kinematics circular trail buffer.
     - Sample of loaded executable modules.
   - Encrypted with AES/SHA-256 CTR stream cipher and authenticated with HMAC-SHA256 signature for tamper-evident offline diagnostics and backend telemetry.

6. **Industry-Standard C-API & Game Engine SDK (`noescape_sdk.h`)**:
   - Clean C-compatible ABI (`extern "C"`) enabling 2-line integration in Unity (P/Invoke), Unreal Engine, and custom C/C++ game engines:
     - `NoEscape_Init(const NoEscapeConfig* config)`
     - `NoEscape_Shutdown()`
     - `NoEscape_Tick()`
     - `NoEscape_PushMouseEvent(float delta_yaw, float delta_pitch, uint64_t timestamp_ms)`
     - `NoEscape_GetThreatScore()`
     - `NoEscape_SetViolationCallback(void (*cb)(int type, int score, const char* details))`
   - Exports both static (`libnoescape.a` / `noescape_static.lib`) and dynamic shared (`libnoescape.so` / `noescape.dll`) libraries.

7. **PCIe DMA Hardware & Bus Latency Detection**:
   - Micro-architectural cache eviction & memory bus contention latency jitter profiling (`rdtsc`, `clflushopt`, `mfence`) to detect external FPGA DMA cards (e.g., Screamer, CaptainDMA, Enigma X1).
   - Direct bus enumeration for known FTDI FT601 USB3 FIFO bridges and Xilinx Artix-7 PCIe VID/PID signatures.

8. **Input Kinematics & Aimbot Trajectory Analysis**:
   - Biomechanical mouse movement heuristics: computes angular velocity ($\omega$), acceleration ($\alpha$), and jerk ($j$).
   - **Instant Snap Detection**: Identifies 1-tick silent-aim flick shots ($\ge 20^\circ$ in $\le 35\text{ms}$) followed by immediate dead stops.
   - **Linearity & Smoothing Analysis**: Detects sub-millidegree robotic linear interpolation ($R^2 \approx 1.0$) and constant-velocity aimbot smoothing without natural physiological tremors.

---

### 🚀 Build & Verification

#### Prerequisites
- **Linux**: GCC 11+ or Clang 13+ with C++20 support, CMake 3.20+, `make`/`ninja`.
- **Windows**: MSVC v143+ (Visual Studio 2022) with C++20 standard `/std:c++20`.

#### Build Commands
```bash
# Configure and build
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j$(nproc)

# Run Comprehensive Unit Test Suite (105 test cases across all subsystems)
./build/noescape_tests

# Run Interactive Subsystem Demo
./build/noescape_demo

# Run Standalone Anti-Cheat Engine (Single Audit)
./build/noescape_app --once
```

---

### ⚖️ What this is — and is not

NoEscapeAC is a **user-mode (Ring-3) detection and deterrence layer**. It runs with the same privileges as the game, so be realistic about its limits:

- A cheat running *inside* the process (or with higher privileges: kernel drivers, hypervisors, DMA hardware) can in principle tamper with any client-side check. Self-integrity, hook and memory checks raise the cost; they do not make bypass impossible.
- Purely **external, read-only** cheats (most ESP/radar tools) cannot be observed from user mode at all.
- Pattern/name based detections are signatures: they catch off-the-shelf tools and lazy modifications, not custom builds.
- Therefore the client should be one signal among several. For competitive titles, pair it with **server-side** validation (fog-of-war culling, movement/aim statistics, mandatory signed heartbeats) and treat client reports as evidence, not verdicts.
- Roll new rules out in *report-only* mode first (`enforce_ban = false`) and watch false-positive telemetry before enabling bans.

### 🔐 Integration Notes

- **Always set a unique `secret_key` and `panel_url`.** The built-in default key is public; a warning is logged when it is used.
- `https://` panel URLs are refused (TLS is not implemented yet) instead of silently falling back to cleartext. Terminate TLS at a reverse proxy on a trusted network or add a TLS client.
- Detections are scored **once per distinct finding**; persistent conditions no longer snowball into a ban. Network I/O runs on its own thread so slow/hostile panels cannot trip the watchdog.
- `NoEscape_Tick()` works without `NoEscape_Start()`; it runs a full synchronous audit on the calling thread (do not call it every frame).
- Weakening environment overrides (`NOESCAPE_ENFORCE_BAN=0`, `NOESCAPE_BAN_THRESHOLD`, …) are honoured only when `NOESCAPE_TEST_MODE=1`.
- `bool` fields in `NoEscapeConfig` are 1 byte: use `[MarshalAs(UnmanagedType.U1)]` in C# P/Invoke.
- Build with `-DNOESCAPE_WERROR=ON` in CI to treat warnings as errors.

---

### 📂 Directory Layout

```
NoEscapeAC/
├── include/
│   ├── noescape_sdk.h        # Clean C-ABI & C++ SDK layer
│   └── noescape/
│       ├── core/             # Types, Logger, ThreadPool, Engine, Blackbox, Obfuscation
│       ├── security/         # AntiDebug, Self-Integrity, TSC Timing
│       ├── memory/           # SIMD PatternScanner, MemoryScanner, Unhooker
│       ├── overlay/          # OverlayDetector (Window scanner & Swapchain validator)
│       ├── forensics/        # ProcessAnalyzer, ArtifactAnalyzer
│       ├── dma/              # DmaDetector (PCIe Leech & Latency Jitter)
│       ├── kinematics/       # AimAnalyzer (Snap, Linearity, Smoothing)
│       ├── network/          # CryptoUtil (SHA-256 / HMAC), PanelClient
│       └── sdk/              # SDK forwarding header
├── src/                      # Subsystem implementations (Linux + Windows)
│   ├── core/
│   ├── security/
│   ├── memory/
│   ├── overlay/
│   ├── forensics/
│   ├── dma/
│   ├── kinematics/
│   ├── network/
│   └── sdk/
├── demo/                     # Interactive demonstration program
├── tests/                    # 105 unit & regression tests
└── CMakeLists.txt            # Exports libnoescape.a, libnoescape.so, and executables
```

---

### 👥 Contributors & Core Team

- **Omar Yiğitcan Mengü** ([@CmdSuv](https://github.com/CmdSuv)) — Lead Architect & Creator
- **OnlyCosmos** ([@OnlyCosmos](https://github.com/OnlyCosmos)) — Co-Developer & Contributor

---

### 📄 License & Copyright

**Copyright (c) 2026 Omar Yiğitcan Mengü ([github.com/CmdSuv](https://github.com/CmdSuv)). All Rights Reserved.**
**Contributors:** OnlyCosmos ([github.com/OnlyCosmos](https://github.com/OnlyCosmos))

This software is distributed under the custom **NoEscape Non-Commercial Share-Alike Source Available License (v1.0)**:
- **Commercial Use & Sale Strictly Forbidden**: You may **NOT** sell, resell, sublicense, monetize, commercialize, or profit from this software or any derivative works thereof in any form.
- **Modification & Public Showcase Permitted**: You are welcome to inspect, study, modify, fork, and showcase/demonstrate the software for non-commercial, personal, and educational purposes.
- **Strict License Preservation (Copyleft)**: Any copy, fork, redistribution, or showcase of this software (in source or binary form) **MUST** retain the original [LICENSE](LICENSE) file completely unmodified.
- **Mandatory Attribution**: You must visibly credit **Omar Yiğitcan Mengü** and maintain an active link to the author's GitHub profile: [https://github.com/CmdSuv](https://github.com/CmdSuv).

For full legal terms and conditions, please consult the complete [LICENSE](LICENSE) file.

---

### ⚠️ Disclaimer
*This project is provided strictly for educational research, system administration, and defensive application security hardening purposes.*
