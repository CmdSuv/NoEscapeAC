# NoEscapeAC — Changelog & Release History

All notable technical changes to the NoEscape Anti-Cheat system are documented in this file.

---

## [Release 1.3.0] — 2026-11-07 (Unified Ring-3 Security Architecture)

### Added
- **Evidence Correlator Layer (`EvidenceCorrelator`):**
  - Multi-signal forensic correlation engine that evaluates incoming events across independent detection families (Memory, Behavioral, Hardware, Server, Forensics).
  - Weak heuristic dampening: single weak signals (e.g. DMA bus latency jitter, background process name match, single RDTSC anomaly) are prevented from triggering automated bans.
  - Independent category tracking and server verification promotion.
- **Server-Authoritative Gameplay Integration (`ServerEspFilter`):**
  - Authoritative server-side 3D AABB raycast occlusion culling (Slab method) that withholds occluded entity transforms from client network replication.
  - Acoustic cue routing: transmits sound cues when players make audible noise within hearing radius while keeping visual coordinates withheld.
  - Authoritative movement speed validation detecting speedhacks and teleportation.
- **Hardware & IOMMU Inspection (`DmaDetector`):**
  - OS / hardware IOMMU interrogation: evaluates Intel VT-d, AMD-Vi, and Windows Kernel DMA Protection policies.
  - Multi-signal `EvaluateHardwareConfidence` classifying PCIe/USB devices into verified tiers (`KNOWN_LEGITIMATE`, `SUSPICIOUS_BRIDGE_OR_FPGA`, `KNOWN_CHEAT_HARDWARE`, `CONFIRMED_TOOL_ARTIFACT`).
- **Intel CET `endbr64` & Relocation-Masked Unhooking (`Unhooker`):**
  - Detects modern detour hooks placed after Intel CET `endbr64` (`F3 0F 1E FA`) opcodes.
  - Dynamic PE/ELF base relocation masking preventing false positives on legitimate relocated library code.
- **Runtime Obfuscation Primitive (`ObfuscatedValue<T>`):**
  - Thread-safe rolling XOR key value container protecting runtime game variables and anti-cheat counters against memory scanning tools.
- **Comprehensive Test Suite Expansion:**
  - Expanded test suite to **133 total unit & integration tests**, verified 100% green with zero warnings under `-DNOESCAPE_WERROR=ON`.

---

## [Release 1.2.0] — 2026-11-06 (Hardening & Communications Layer)

### Added
- **Encrypted TLS Communications (`PanelClient`):**
  - TLS 1.2+ socket transport using OpenSSL / WinHTTP with X.509 Subject Public Key Info (SPKI) SHA-256 certificate pinning.
  - HMAC-SHA256 authenticated request payloads with 128-bit random nonces and replay-cache protection.
- **Relocation-Aware Clean Image Unhooker:**
  - Compares in-memory function prologues directly against clean on-disk ELF/PE images.
  - Atomically restores hooked functions via direct `/proc/self/mem` writing (Linux) or `WriteProcessMemory` (Windows) without leaving persistent RWX memory permissions.
- **Honeypot Canary Values (`CanaryMonitor`):**
  - Instantiates randomized memory canaries to trap external memory scanner read/write sweeps.
  - Enforces post-reset rechecks to catch persistent write attempts.
- **SIMD Pattern Scanner Runtime Dispatch:**
  - Vectorized AVX2 (256-bit) pattern matching with automated CPU feature detection (`__cpuidex` + `_xgetbv`) and graceful SSE4.2 fallback.

---

## [Release 1.1.0] — 2026-11-05 (Defensive Hardening & Watchdog Supervision)

### Added
- **Mutual Engine Watchdog Supervision:**
  - Independent watchdog thread executing reciprocal heartbeats with the main audit loop. Suspending or killing either thread triggers an immediate emergency ban alert.
- **Hardware Breakpoint Inspection:**
  - Interrogates x86_64 debug registers DR0-DR3 using `perf_event_open` on Linux and `GetThreadContext` on Windows.
- **VMA Memory Walk Budgeting:**
  - Incremental page scanning limits preventing frame-time hitching in high-FPS games.
- **Standalone Ban Presentation UI:**
  - Independent crimson ban dialog (`tools/noescape_ban_ui.py`) spawned via clean fork/exec, decoupled from game GUI state.

---

## [Release 1.0.0] — 2026-11-04 (Initial Ring-3 Architecture)

### Added
- Initial C++20 unified architecture for user-mode anti-cheat.
- Basic kinematics mouse input analysis (curvature, snap, and linearity metrics).
- In-memory signature scanner and process blacklist enumeration.
- Pre-execution `.text` code section SHA-256 baseline hashing.
- High-level C++ SDK with automated `LD_PRELOAD` initialization hooks.
