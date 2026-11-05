# 🛡️ NoEscape Anti-Cheat Engine (v7.0 / Release 1.1)

[![GitHub Release](https://img.shields.io/badge/Release-NoEscapeAC%201.1-red?style=for-the-badge&logo=github)](https://github.com/CmdSuv/NoEscapeAC/releases/tag/v1.1)
[![Download Zip](https://img.shields.io/badge/Download-Source%20Code%20(.zip)-darkred?style=for-the-badge&logo=github)](https://github.com/CmdSuv/NoEscapeAC/archive/refs/tags/v1.1.zip)
[![License: Non-Commercial Share-Alike](https://img.shields.io/badge/License-Non--Commercial%20Share--Alike-blue?style=for-the-badge)](LICENSE)

**NoEscape** is a cross-platform (Linux + Windows Ring-3), high-performance anti-cheat framework re-engineered in modern **C++20**. Designed for high-integrity game and application security, it incorporates forensic memory analysis, SIMD-accelerated pattern scanning, PCIe DMA hardware detection, statistical input kinematics, ESP overlay detection, encrypted blackbox crash dumpers, and an industry-standard C-ABI SDK.

---

### 📦 Latest Release: NoEscapeAC 1.1
> **[Direct Download: NoEscapeAC 1.1 Source Code (.zip)](https://github.com/CmdSuv/NoEscapeAC/archive/refs/tags/v1.1.zip)**  
> **Release Tag**: `v1.1` | **Full Release Notes**: [View on GitHub Releases](https://github.com/CmdSuv/NoEscapeAC/releases/tag/v1.1)
> 
> **Key Highlights in Release 1.1:**
> - **Unified C++20 Ring-3 Architecture**: Zero external dependencies beyond glibc / Win32.
> - **Riot Vanguard-Style Crimson Ban Overlay**: Standalone GUI dialog with detailed English forensic report and immediate process kick (`tools/noescape_ban_ui.py`).
> - **JVM / JIT Runtime Guard**: Native HotSpot CodeCache awareness preventing false positives on Minecraft / Fabric / Java games.
> - **Full Verification Suite**: 86 automated unit tests + 5 Scenario B preload verification tests passing with 100% rate.

---

### ✨ Key Subsystems & Features

1. **Cross-Platform Architecture (Linux & Windows Ring-3)**:
   - Linux: `/proc` subsystem audit, `/proc/self/maps` page analysis, `dl_iterate_phdr` ELF parsing, and `mprotect` inline unhooking.
   - Windows: Win32/NTAPI direct PEB inspection, `NtQueryInformationProcess`, `Toolhelp32`, and `VirtualQueryEx`.
   - Compile-time XOR string obfuscation (`NOESCAPE_XOR`) and FNV-1a hashing (`NOESCAPE_HASH`).

2. **SIMD Pattern Scanner (AVX2 / SSE2 / Scalar)**:
   - High-throughput byte signature search utilizing AVX2 256-bit vector registers with scalar fallback (up to 35+ GB/s throughput).
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

# Run Comprehensive Unit Test Suite (48 test cases across all subsystems)
./build/noescape_tests

# Run Interactive Subsystem Demo
./build/noescape_demo

# Run Standalone Anti-Cheat Engine (Single Audit)
./build/noescape_app --once
```

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
├── tests/                    # 48 Comprehensive unit tests
└── CMakeLists.txt            # Exports libnoescape.a, libnoescape.so, and executables
```

---

### 📄 License & Copyright

**Copyright (c) 2026 Omar Yiğitcan Mengü ([github.com/CmdSuv](https://github.com/CmdSuv)). All Rights Reserved.**

This software is distributed under the custom **NoEscape Non-Commercial Share-Alike Source Available License (v1.0)**:
- **Commercial Use & Sale Strictly Forbidden**: You may **NOT** sell, resell, sublicense, monetize, commercialize, or profit from this software or any derivative works thereof in any form.
- **Modification & Public Showcase Permitted**: You are welcome to inspect, study, modify, fork, and showcase/demonstrate the software for non-commercial, personal, and educational purposes.
- **Strict License Preservation (Copyleft)**: Any copy, fork, redistribution, or showcase of this software (in source or binary form) **MUST** retain the original [LICENSE](LICENSE) file completely unmodified.
- **Mandatory Attribution**: You must visibly credit **Omar Yiğitcan Mengü** and maintain an active link to the author's GitHub profile: [https://github.com/CmdSuv](https://github.com/CmdSuv).

For full legal terms and conditions, please consult the complete [LICENSE](LICENSE) file.

---

### ⚠️ Disclaimer
*This project is provided strictly for educational research, system administration, and defensive application security hardening purposes.*
