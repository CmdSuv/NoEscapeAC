# 🛡️ NoEscape Anti-Cheat Engine (v7.0 / Release 1.4)

[![GitHub Release](https://img.shields.io/badge/Release-NoEscapeAC%201.4-red?style=for-the-badge&logo=github)](https://github.com/CmdSuv/NoEscapeAC/releases/tag/v1.4)
[![Download Zip](https://img.shields.io/badge/Download-Source%20Code%20(.zip)-darkred?style=for-the-badge&logo=github)](https://github.com/CmdSuv/NoEscapeAC/archive/refs/tags/v1.4.zip)
[![License: Non-Commercial Share-Alike](https://img.shields.io/badge/License-Non--Commercial%20Share--Alike-blue?style=for-the-badge)](LICENSE)

**NoEscape Anti-Cheat (NoEscapeAC)** is a modern, lightweight, and unified user-mode (Ring-3) anti-cheat and runtime integrity framework engineered in **C++20** for Linux and Windows. Designed to safeguard competitive multiplayer games and custom game launchers without intrusive kernel drivers, NoEscapeAC delivers defense-in-depth security: 20+ GB/s AVX2 SIMD byte pattern scanning, unbacked memory forensics with JVM/JIT HotSpot awareness, automatic inline API unhooking (with Intel CET `endbr64` +4 offset support), PCIe DMA anomaly & hardware controller detection, statistical mouse kinematics (silent-aim / instant-snap heuristics), ESP fake-window overlay interception, runtime rolling-key memory value obfuscation, and a standalone crimson security ban enforcement UI.

---

### 📦 Latest Release: NoEscapeAC 1.4
> **[Direct Download: NoEscapeAC 1.4 Source Code (.zip)](https://github.com/CmdSuv/NoEscapeAC/archive/refs/tags/v1.4.zip)**  
> **Release Tag**: `v1.4` | **Changelog & Release Notes**: [View on GitHub Releases](https://github.com/CmdSuv/NoEscapeAC/releases/tag/v1.4)

---

### ✨ Key Subsystems & Features

1. **Cross-Platform Architecture (Linux & Windows Ring-3)**:
   - Linux: `/proc` subsystem audit, `/proc/self/maps` page analysis, `dl_iterate_phdr` ELF parsing, ELF relocation masking (`.rela.dyn`, `.rela.plt`), direct raw `syscall` invocation, and `mprotect` inline unhooking.
   - Windows: Win32/NTAPI direct PEB inspection, `NtQueryInformationProcess`, `Toolhelp32`, `VirtualQueryEx`, PE base relocation masking (`IMAGE_DIRECTORY_ENTRY_BASERELOC`), and cross-compilation support via `llvm-mingw` (`-DNOESCAPE_WERROR=ON`).
   - Compile-time CBC stream cipher XOR string obfuscation (`NOESCAPE_XOR`) and 64-bit FNV-1a hashing (`NOESCAPE_HASH`).

2. **SIMD Pattern Scanner (AVX2 / SSE2 / Grouped First-Byte Buckets)**:
   - High-throughput byte signature search utilizing AVX2 256-bit vector registers with automatic runtime CPU dispatch (>20 GB/s throughput).
   - Grouped first-byte SIMD indexing: searches all active signatures in a single vectorized pass rather than looping linearly.
   - Supports IDA-style wildcard patterns (`48 B8 ? ? ? ? ? ? ? ? FF E0`) and batch scanning in a single pass.

3. **Memory & Injection Analysis**:
   - **Unbacked Executable Memory Scanner**: Detects anonymous `RX`/`RWX` pages, reflective DLL / SO injection, deleted binary execution (`/proc/<pid>/exe (deleted)`), and memory-ghosted modules.
   - **Inline Hook Detector & Self-Healing Unhooker**: Identifies `0xE9` (JMP rel32), `0xEB` (JMP rel8), `0xFF 0x25` (JMP indirect), `MOV RAX; JMP RAX`, `PUSH/RET`, `0xCC` (INT3), and **Intel CET `endbr64` (`F3 0F 1E FA`) offset +4** hooks on core system APIs and automatically restores clean instructions from pristine disk binaries into memory.

4. **Overlay & ESP/Wallhack Defense**:
   - **Fake Window Hijack Scanner**: Detects transparent/layered top-most fake windows (`WS_EX_LAYERED`, `WS_EX_TRANSPARENT`, `WS_EX_TOPMOST`) matching or enclosing the game viewport bounding rect.
   - **Title Spoofing & Owning PID Verification**: Verifies whether processes claiming to be whitelisted overlays (e.g. Discord, Steam, MangoHud) originate from legitimate binaries or volatile/cheat paths (`/tmp`, `/dev/shm`, `Temp`), and detects DLL hijacking inside legitimate overlay hosts.
   - **Rendering Pipeline Integrity**: Inspects DirectX / Vulkan / OpenGL `Present`, `SwapBuffers`, and dynamic swapchain vtables to ensure function pointers reside strictly within loaded module address spaces and have not been redirected to unbacked trampolines or inline-hooked.

5. **Ring-0 Environment, BYOVD & External Handle Forensics**:
   - **Kernel Integrity Audit**: Queries `NtQuerySystemInformation` on Windows for `SystemCodeIntegrityInformation` (catches `TestSigning` / DSE bypass) and `SystemKernelDebuggerInformation`. On Linux, correlates `/sys/module` with `/proc/modules` to catch hidden LKM rootkits and forced-load (`F`) tainted modules.
   - **Expanded BYOVD Driver Watch**: Active blacklist of 27 vulnerable/exploit drivers (`iqvw64e`, `capcom`, `gdrv`, `rtc64`, `dbutil_2_3`, `mhyprot2`, `dbk64`, `winring0`, `ksdumper`, `leechcore`, `diamorphine`, `reptile`, etc.).
   - **External Memory Handle Audit**: Scans open file descriptors in `/proc/*/fd` to detect any external user-mode processes holding read/write handles to protected game memory (`/proc/<self>/mem` or `/proc/<self>/pagemap`).

6. **Runtime Value Encryption (Anti-DMA & Anti-CheatEngine)**:
   - **`ObfuscatedValue<T>`**: In-memory rolling-key cipher using SplitMix64 keyed by variable memory address and rotating per-write nonces. Prevents Cheat Engine scans, memory freezing, and DMA memory-dump analysis from locating plaintext values.
   - **Opaque Predicates (`OpaqueTrue`)**: Hardens execution flow against static decompilation in IDA Pro and Ghidra.

7. **PCIe DMA Hardware, Spoofed Firmware & KMBox Detection**:
   - Micro-architectural cache eviction & memory bus contention latency jitter profiling (`rdtsc`, `clflush`, `mfence`) to detect external FPGA DMA cards.
   - Direct bus enumeration for known FTDI FT601 USB3 FIFO bridges and Xilinx/Altera FPGA endpoints.
   - **Spoofed Firmware Subsystem Audit**: Catches spoofed DMA firmware that forged primary vendor IDs but left underlying Xilinx (`0x10ee`) or Altera (`0x1172`) Subsystem Vendor IDs in PCI configuration space.
   - **Hardware Aimbot Controller Detection**: Flags USB hardware aimbot devices including KMBox (`1A86:55D3`, `VID_8888`) and MAKCU controllers.

8. **Input Kinematics & Aimbot Trajectory Analysis**:
   - Biomechanical mouse movement heuristics: computes angular velocity ($\omega$), acceleration ($\alpha$), and jerk ($j$).
   - **Instant Snap Detection**: Identifies 1-tick silent-aim flick shots ($\ge 20^\circ$ in $\le 35\text{ms}$) followed by immediate dead stops.
   - **Linearity & Smoothing Analysis**: Detects sub-millidegree robotic linear interpolation ($R^2 \approx 1.0$) and constant-velocity aimbot smoothing without natural physiological tremors.
   - **Phantom Entity Decoy Monitor**: Populates invisible decoy entities into the world table; flags players whose crosshairs lock onto or track phantom coordinates.

9. **Mutual Watchdog Supervision & Blackbox Diagnostics**:
   - **Mutual Watchdog Thread Supervision**: The background audit loop and watchdog monitor each other's timestamps (`heartbeat_mutex_`). Freezing, suspending, or killing either thread immediately triggers tamper enforcement.
   - **Authenticated Blackbox Dumper**: Captures cryptographic crash/violation snapshots encrypted with CTR stream cipher and authenticated with HMAC-SHA256.

10. **Evidence Correlation & Multi-Signal Verification (`EvidenceCorrelator`)**:
   - Classifies findings across 5 confidence tiers (`OBSERVATION`, `SUSPICION`, `CORROBORATED_ANOMALY`, `HIGH_CONFIDENCE_VIOLATION`, `INDEPENDENTLY_VERIFIED`).
   - Enforces heuristic dampening: single weak heuristics (DMA jitter alone, background process name match alone, overlay transparency, single RDTSC anomaly) can never trigger an automated ban.
   - Tracks distinct detection categories and promotes multi-family corroborated evidence.

11. **Server-Authoritative Gameplay Integration (`ServerEspFilter`)**:
   - Server-side 3D AABB raycast occlusion culling (Slab method) that withholds occluded enemy coordinates from client replication streams to defeat client-side wallhacks and external/DMA ESP.
   - Acoustic cue routing: transmits footsteps and gunshot cues when players are within hearing radius while keeping visual coordinates withheld.
   - Authoritative speedhack, teleportation, and solid-wall engagement validation.

12. **Authentic Cryptographic Security & Asymmetric Attestation**:
   - **RFC 8032 Ed25519 Engine**: Genuine elliptic-curve public-key digital signatures (Curve25519) with strict RFC 8032 test-vector compliance and zero insecure fallbacks.
   - **RFC 8439 ChaCha20-Poly1305 AEAD**: Authenticated encryption with associated data protecting flight recorder blackbox snapshots with Poly1305 authentication tags.
   - **Dynamic Server-Verified Sessions**: Server-issued single-use code attestation challenges requiring HMAC computation over pseudorandom executable segments.

---

### 🚀 Build & Verification

#### Prerequisites
- **Linux**: GCC 11+ or Clang 13+ with C++20 support, CMake 3.20+, `make`/`ninja`.
- **Windows**: MSVC v143+ (Visual Studio 2022) with C++20 standard `/std:c++20`, or `llvm-mingw` (`x86_64-w64-mingw32-clang++`).

#### Build Commands
```bash
# Configure and build (Linux)
cmake -B build -DCMAKE_BUILD_TYPE=Release -DNOESCAPE_WERROR=ON
cmake --build build -j$(nproc)

# Run Comprehensive Unit Test Suite (171 test cases across all subsystems)
./build/noescape_tests

# Run Preload Scenario B Verification Suite (6/6 tests)
./tools/verify_preload.sh ./build

# Run Interactive Subsystem Demo
./build/noescape_demo

# Run Standalone Anti-Cheat Engine (Single Audit)
./build/noescape_app --once
```

---

### 📚 Architectural Specifications & Documentation

- [SECURITY_ARCHITECTURE.md](SECURITY_ARCHITECTURE.md) — Subsystem taxonomy, layered defense structure, anti-tamper, and telemetry pipeline.
- [DETECTION_MATRIX.md](DETECTION_MATRIX.md) — Complete detection coverage matrix, bypass difficulty, and test references.
- [FALSE_POSITIVE_STRATEGY.md](FALSE_POSITIVE_STRATEGY.md) — Heuristic dampening, confidence tiers, whitelisting, and dispute workflow.
- [PERFORMANCE_BENCHMARKS.md](PERFORMANCE_BENCHMARKS.md) — AVX2 SIMD throughput (>9.4 GB/s), VMA page walks, and frame-time impact.
- [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) — Windows x64, Linux x86_64, and Proton/Wine execution parity.
- [TEST_STRATEGY.md](TEST_STRATEGY.md) — Unit test suite structure (171 tests), mock injection harnesses, and CI sanitizers.
- [PRIVACY_AND_DATA_POLICY.md](PRIVACY_AND_DATA_POLICY.md) — Zero PII collection policy, one-way HWID hashing, and encrypted blackbox dumps.
- [CHANGELOG.md](CHANGELOG.md) — Full release history from v1.0 through v1.4.
- [CURRENT_PROJECT_STATE.md](CURRENT_PROJECT_STATE.md) — Active project state, build verification, and deployment handoff.
- [AUDIT_REPORT.md](AUDIT_REPORT.md) — Comprehensive technical security audit report.
- [RING3_THREAT_MODEL.md](RING3_THREAT_MODEL.md) — Ring-3 threat modeling, threat vectors, and architectural mitigations.
- [DETECTION_GAP_ANALYSIS.md](DETECTION_GAP_ANALYSIS.md) — Gap analysis and technical countermeasure analysis.
- [FILE_INVENTORY.md](FILE_INVENTORY.md) — Exhaustive source file catalog, public APIs, calling graphs, and ownership.
- [ARCHITECTURE_MAP.md](ARCHITECTURE_MAP.md) — 9-layer architectural map and cross-cutting security boundaries.
- [DEPENDENCY_GRAPH.md](DEPENDENCY_GRAPH.md) — Component dependency topology, acyclic validation, and coupling metrics.
- [SECURITY_FINDINGS.md](SECURITY_FINDINGS.md) — Critical vulnerability registry (SEC-01 through SEC-11) and verification.
- [CRYPTOGRAPHY_REVIEW.md](CRYPTOGRAPHY_REVIEW.md) — Cryptographic architecture audit (RFC 8032 Ed25519 & RFC 8439 AEAD).
- [EVIDENCE_MODEL.md](EVIDENCE_MODEL.md) — Temporal correlation, state transitions, decay models, and confidence calibration.
- [SDK_INTEGRATION_GUIDE.md](SDK_INTEGRATION_GUIDE.md) — C-ABI and C++ SDK integration manual and thread safety contract.
- [SERVER_INTEGRATION_GUIDE.md](SERVER_INTEGRATION_GUIDE.md) — Authoritative server integration, AABB occlusion culling, and attestation.

---

### ⚖️ What this is — and is not

NoEscapeAC is a **user-mode (Ring-3) detection and deterrence layer**. It runs with the same privileges as the game, so be realistic about its limits:

- A cheat running *inside* the process (or with higher privileges: kernel drivers, hypervisors, DMA hardware) can in principle tamper with any client-side check. Self-integrity, hook and memory checks raise the cost; they do not make bypass impossible.
- Purely **external, read-only** cheats (most ESP/radar tools) cannot be observed from user mode at all.
- Pattern/name based detections are signatures: they catch off-the-shelf tools and lazy modifications, not custom builds.
- Therefore the client should be one signal among several. For competitive titles, pair it with **server-side** validation (fog-of-war culling, movement/aim statistics, mandatory signed heartbeats) and treat client reports as evidence, not verdicts.
- Roll new rules out in *report-only* mode first (`enforce_ban = false`) and watch false-positive telemetry before enabling bans.

### 🧷 Self-protection

The audit loop and the watchdog supervise **each other**: the watchdog bans when the audit loop stalls (> 3 s), and the audit loop reports when the watchdog stops answering, so suspending or killing only one of the two threads is detected. Audits are serialized, long scans report progress, and `Tick()` never blocks behind a running background audit.

### 🛰️ Server-verified sessions (recommended for competitive games)

Enable heartbeats (`enable_heartbeat = true` / `NOESCAPE_ENABLE_HEARTBEAT=1`). Each signed heartbeat reply may carry a **code-attestation challenge**: the server names a random byte range of the client's executable segment, the client returns `HMAC(secret, id:nonce:bytes)` and the server recomputes it from the reference build (`NOESCAPE_REF_IMAGE` in `tools/reference_server.py`; ELF in the reference implementation). Your **game server** then asks `GET /api/ac/session?hwid=H` and drops players whose session is not `valid` (no heartbeat, expired TTL, wrong or unanswered attestation). Enforcement therefore lives on the server, where a cheat cannot switch it off. Challenges are random, single-use and signed, so answers cannot be replayed or precomputed.

### 🔐 Integration Notes

- **Always set a unique `secret_key` and `panel_url`.** The built-in default key is public; a warning is logged when it is used.
- `https://` panel URLs are supported via OpenSSL on Linux and WinHTTP on Windows, with optional SPKI SHA-256 public-key pinning (`NoEscape_SetPanelPin` / `NOESCAPE_PANEL_PIN_SHA256`). If built without TLS (`-DNOESCAPE_WITH_TLS=OFF`), `https://` URLs are refused rather than silently downgraded to cleartext.
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
│       ├── core/             # Types, Logger, ThreadPool, Engine, Blackbox, EvidenceCorrelator
│       ├── security/         # AntiDebug, Self-Integrity, TSC Timing
│       ├── memory/           # SIMD PatternScanner, MemoryScanner, Unhooker, CanaryMonitor
│       ├── overlay/          # OverlayDetector (Window scanner & Swapchain validator)
│       ├── forensics/        # ProcessAnalyzer, ArtifactAnalyzer
│       ├── dma/              # DmaDetector (PCIe Leech, Latency Jitter, IOMMU Status)
│       ├── kinematics/       # AimAnalyzer (Snap, Linearity, Smoothing), PhantomMonitor
│       ├── server/           # ServerEspFilter (Authoritative Occlusion Culling & Movement Validation)
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
│   ├── server/
│   ├── network/
│   └── sdk/
├── demo/                     # Interactive demonstration program
├── tests/                    # 171 unit & regression tests
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
