# NoEscapeAC — Changelog & Release History

All notable technical changes to the NoEscape Anti-Cheat system are documented in this file.

## [Release 1.4.1 / v1.4 Critical Remediation Patch] — 2026-11-08

### Fixed & Remediated
- **P0-1: Timestamp Normalization across Detection Subsystems (`types.hpp`, all producers):**
  - Standardized detection event timestamps across all 15 detection producers using `DetectionEvent::NowMonotonicMs()` for monotonic time-window calculations (`timestamp`) and `DetectionEvent::NowUtcMs()` for human logging and backend telemetry records (`timestamp_utc_ms`).
  - Fixed severe bug where event producers passed `std::time(nullptr)` (seconds ~1.73e9) into a 60,000-millisecond sliding window (`time_window_ms_ = 60000`), effectively inflating the active window to 60,000 seconds (16.6 hours).
  - Added deterministic tests proving the 60-second temporal correlation window is strictly 60,000 milliseconds across all detection subsystems.
- **P0-2: Centralized Enforcement Policy & Multi-Signal Corroboration Bypass Fix (`evidence_correlator.cpp`, `engine.cpp`):**
  - Centralized enforcement decisions within `EvidenceCorrelator::Evaluate` across all enforcement modes (`REPORT_ONLY`, `SHADOW`, `MATCH_RESTRICTION`, `SERVER_SESSION_REJECT`, `ENFORCE`).
  - Closed bypass in `AntiCheatEngine::ProcessDetection` where a single client-side heuristic with `CRITICAL` or `FATAL_BAN` severity bypassed multi-signal corroboration in `strict_corroboration_mode`.
  - Single uncorroborated client-side heuristics are now clamped to telemetry reporting only and cannot trigger automated bans, shadow bans, match restrictions, or session rejections unless corroborated by independent detection categories or server verification.
- **P0-3: Strict RFC 8032 Ed25519 Canonical Scalar & Point Encoding Validation (`ed25519.cpp`):**
  - Implemented complete canonical scalar verification checking all 256 bits for $S < L$ ($L = 2^{252} + 27742317777372353535851937790883648493$), replacing incomplete upper-3-bit check.
  - Implemented canonical field element verification enforcing $y < 2^{255}-19$ on decoded point coordinates for $R$ and $A$.
  - Hardened curve point decompression (`unpackneg`) to reject non-canonical field elements and negative zero ($x = 0$ with sign bit = 1).
  - Integrated OpenSSL `EVP_DigestVerify` as the primary audited cryptographic provider when available, with mathematically equivalent zero-dependency pure software fallback.
  - Added comprehensive negative test suite verifying rejection of non-canonical scalars ($S \ge L$), corrupted signatures, and invalid point encodings.
- **P1-1: Safe Match and Session Lifecycle SDK APIs (`noescape_sdk.h`, `noescape_sdk.cpp`, `engine.cpp`):**
  - Exposed C-linkage APIs `NoEscape_BeginSession`, `NoEscape_EndSession`, `NoEscape_BeginMatch`, `NoEscape_EndMatch` and C++ SDK methods in `noescape::sdk::Client`.
  - Wired lifecycle APIs directly to `AntiCheatEngine` and `EvidenceCorrelator::SetSessionId` / `SetMatchId`, guaranteeing that evidence from prior matches or sessions cannot affect decisions in a new match.
- **P1-2: Bounded Engine History & Scored Keys State Retention (`engine.hpp`, `engine.cpp`):**
  - Bounded `history_` ring buffer using `std::deque` with a default cap of 512 events and `scored_keys_` using FIFO order eviction tracking.
  - Added `SetMaxHistoryCapacity`, `GetMaxHistoryCapacity`, and explicit `PruneHistory` lifecycle APIs, mathematically bounding memory usage during long-running sessions.
- **P1-3: Production SDK Configuration Validation (`noescape_sdk.h`, `noescape_sdk.cpp`):**
  - Removed insecure hardcoded default secrets (`NoEscape_Secret_Key_v2.0`) and loopback URLs from `NoEscape_GetProfileConfig`.
  - Added explicit configuration validation via `NoEscape_ValidateConfig`, preventing production deployments from silently initializing with empty backend URLs, missing secrets, or missing server verification keys.
- **P1-4: Server Authoritative Visibility Adapter Contract (`server_integration.hpp`, `server_integration.cpp`):**
  - Documented that `ServerEspFilter` is a server-side helper library requiring explicit integration into the host game server's network replication tick.
  - Introduced `IAuthoritativeVisibilityAdapter` abstract interface allowing game servers to integrate native authoritative physics and raycast queries (PhysX, Havok, Chaos, Unreal LineTrace).
  - Added explicit `occlusion_unconfigured` flag in `ReplicationDecision` when no occluder boxes or adapter are configured, eliminating silent false-positive visibility assumptions.
- **P1-5: Cryptographic Randomness Audit & CSPRNG Error Propagation (`crypto_util.cpp`, `panel_client.cpp`):**
  - Hardened `CryptoUtil::GenerateRandomBytes` to use direct OS cryptographic random APIs (`getrandom(2)` syscall on Linux with `/dev/urandom` fallback, `BCryptGenRandom` on Windows).
  - Completely eliminated insecure fallback to timestamps / `std::random_device` on entropy failure.
  - Propagated RNG failure booleans and exceptions throughout `GenerateRandomHex`, `GenerateAsymmetricKeyPair`, `BlackboxDumper`, and `PanelClient::RandomNonce`.

---

## [Release 1.4.0 / Architecture v2.0] — 2026-11-07 (Ultimate Ring-3 Anti-Cheat Architecture Reengineering)

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
- **Overlay Detector Process Trust State & Provenance (`overlay_detector.cpp`):**
  - Introduced `ProcessTrustState` enum (`TRUSTED`, `UNTRUSTED`, `UNVERIFIED`, `SUSPICIOUS`).
  - Closed fail-open bypass on `pid == 0` and `ERROR_ACCESS_DENIED`. Denied allowlist title exemptions to any unverified or elevated PID.
  - Removed mock window test backdoor completely from `verifyOverlayProcessAuthentic`.
  - Added `exe_path` to `OverlayWindowInfo` for explicit binary image provenance verification.
  - Eliminated false positive keyword matches on legitimate whitelisted overlays and removed `"overlay"` from generic suspicious keywords.
- **Benign OEM Driver & Environment Anomaly Classification (`artifact_analyzer.cpp`, `process_analyzer.cpp`):**
  - Partitioned driver blacklist into active cheat tools/rootkits (`CRITICAL`, score 85) vs common OEM motherboard utilities (`MEDIUM`, score 30, `ene.sys`, `speedfan`, `asio64`, `msio64`).
  - Downgraded process environment instrumentation detections (`ATTACH_DEBUGGER`, `LD_PRELOAD`) from hardcoded `FATAL_BAN` to `MEDIUM` security anomalies (score 35).
  - Downgraded single-probe text mismatch, unbacked RWX, and LeechCore handle detections to `CRITICAL` requiring multi-signal corroboration before permanent bans.
- **EvidenceCorrelator Timeline Bounds & Deduplication (`evidence_correlator.cpp`):**
  - Deduplicated category timeline entries by `root_cause_id` and strictly capped entries per category to 32.
  - Capped related event IDs collection to 16, preventing $O(N^2)$ lock stalls under high event saturation (>5,000 events/sec).
- **Panel Client Fail-Closed Signature Verification (`panel_client.cpp`):**
  - Refused HMAC verification when neither asymmetric server public key nor secret key is provisioned, eliminating empty-key HMAC signature bypasses.
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
  - Expanded test suite to **157 total unit & integration tests**, verified 100% green with zero warnings under `-DNOESCAPE_WERROR=ON`.
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
