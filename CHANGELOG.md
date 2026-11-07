# NoEscapeAC — Changelog & Release History

All notable technical changes to the NoEscape Anti-Cheat system are documented in this file.

---

## [Release 2.0.0] — 2026-11-07 (Ultimate Ring-3 Anti-Cheat Architecture Reengineering)

### Added
- **RFC 8032 Pure Ed25519 Implementation (`ed25519.hpp`, `ed25519.cpp`):**
  - Portable, zero-dependency twisted Edwards field arithmetic over GF($2^{255}-19$) and SHA-512.
  - Replaced critical vulnerability where non-OpenSSL builds used HMAC-SHA256 with the public key as secret.
  - Added official RFC 8032 test vectors 1, 2, 3 and negative forgery tests proving that possession of the public key cannot forge signatures.
- **RFC 8439 ChaCha20-Poly1305 AEAD Flight Recorder (`blackbox.cpp`):**
  - Modernized blackbox diagnostic dump format to Version 2 authenticated encryption using ChaCha20-Poly1305 AEAD with 12-byte CSPRNG nonces and 16-byte Poly1305 tags.
  - Preserved backward compatibility for Version 1 dumps.
- **Temporal Evidence Correlator Reengineering (`evidence_correlator.cpp`):**
  - Implemented 60-second sliding time window (`time_window_ms_ = 60000`) with active category pruning.
  - Added bounded storage capacity (`max_stored_events_ = 512`) with two-phase eviction (expired first, then oldest low-confidence).
  - Integrated root-cause grouping (`DeriveRootCauseId`) to prevent multiple events from the same physical memory span from falsely inflating corroboration.
  - Implemented session and match isolation keys.
- **Overlay Detector Process Trust State (`overlay_detector.cpp`):**
  - Introduced `ProcessTrustState` enum (`TRUSTED`, `UNTRUSTED`, `UNVERIFIED`, `SUSPICIOUS`).
  - Closed fail-open bypass on `pid == 0` and `ERROR_ACCESS_DENIED`. Denied allowlist title exemptions to any unverified or elevated PID.
- **Server ESP Close-Proximity Occlusion Hardening (`server_integration.cpp`):**
  - Fixed 6-meter close-proximity wallhack bypass by strictly enforcing 3D AABB raycast occlusion culling before proximity replication.
  - Occluded targets within close proximity (<6m) are strictly blocked from full transform replication; only acoustic cues are transmitted if audible sound is produced.
- **Full Kinematics Telemetry Connection (`engine.cpp`, `noescape_sdk.cpp`, `aim_analyzer.cpp`):**
  - Exposed and connected raw HID mouse interval quantization analysis (macro detection).
  - Connected triggerbot reaction latency analysis (inhuman sub-45ms responses).
  - Connected recoil compensation per-shot counter-movement analysis.
  - Provided C API and C++ SDK wrappers: `NoEscape_PushRawInput`, `NoEscape_RecordTargetAcquire`, `NoEscape_PushWeaponFire`, `NoEscape_PushRecoilEvent`.
- **Module Provenance Audit Disassociation (`memory_scanner.cpp`):**
  - Disassociated ELF Build-ID from cryptographic digital signatures (`has_build_id` vs `is_signed`).
- **5 Formal Configuration Profiles (`types.hpp`, `noescape_sdk.h`):**
  - `Development`, `Testing`, `ShadowProduction`, `Production`, and `OfflineDiagnostics`.
  - Added `struct_size` and versioning guards ensuring backward compatibility for legacy struct layouts.
- **Complete Test Suite Expansion:**
  - Expanded test suite to **145 total unit & integration tests**, verified 100% green with zero warnings under `-DNOESCAPE_WERROR=ON`.
  - Scenario B Preload Verification verified **6/6 passed (100%)**.

---

## [Release 1.3.0] — 2026-11-07 (Unified Ring-3 Security Architecture)

### Added
- **Evidence Correlator Layer (`EvidenceCorrelator`):**
  - Multi-signal forensic correlation engine evaluating events across independent detection families.
  - Weak heuristic dampening: single weak signals are prevented from triggering automated bans.
- **Server-Authoritative Gameplay Integration (`ServerEspFilter`):**
  - Authoritative server-side 3D AABB raycast occlusion culling (Slab method).
  - Acoustic cue routing: transmits sound cues when players make audible noise within hearing radius while keeping visual coordinates withheld.
  - Authoritative movement speed validation detecting speedhacks and teleportation.
- **Hardware & IOMMU Inspection (`DmaDetector`):**
  - OS / hardware IOMMU interrogation: evaluates Intel VT-d, AMD-Vi, and Windows Kernel DMA Protection policies.
- **Intel CET `endbr64` & Relocation-Masked Unhooking (`Unhooker`):**
  - Detects modern detour hooks placed after Intel CET `endbr64` (`F3 0F 1E FA`) opcodes.
  - Dynamic PE/ELF base relocation masking preventing false positives on legitimate relocated library code.
- **Runtime Obfuscation Primitive (`ObfuscatedValue<T>`):**
  - Thread-safe rolling XOR key value container protecting runtime game variables and anti-cheat counters against memory scanning tools.

---

## [Release 1.2.0] — 2026-11-06 (Hardening & Communications Layer)

### Added
- **Encrypted TLS Communications (`PanelClient`):**
  - TLS 1.2+ socket transport using OpenSSL / WinHTTP with X.509 Subject Public Key Info (SPKI) SHA-256 certificate pinning.
- **Relocation-Aware Clean Image Unhooker:**
  - Compares in-memory function prologues directly against clean on-disk ELF/PE images.
- **Honeypot Canary Values (`CanaryMonitor`):**
  - Instantiates randomized memory canaries to trap external memory scanner read/write sweeps.
- **SIMD Pattern Scanner Runtime Dispatch:**
  - Vectorized AVX2 (256-bit) pattern matching with automated CPU feature detection and graceful SSE4.2 fallback.

---

## [Release 1.1.0] — 2026-11-05 (Defensive Hardening & Watchdog Supervision)

### Added
- **Mutual Engine Watchdog Supervision:**
  - Independent watchdog thread executing reciprocal heartbeats with the main audit loop.
- **Hardware Breakpoint Inspection:**
  - Interrogates x86_64 debug registers DR0-DR3 using `perf_event_open` on Linux and `GetThreadContext` on Windows.
- **VMA Memory Walk Budgeting:**
  - Incremental page scanning limits preventing frame-time hitching in high-FPS games.
- **Standalone Ban Presentation UI:**
  - Independent crimson ban dialog (`tools/noescape_ban_ui.py`) spawned via clean fork/exec, decoupled from game GUI state.
