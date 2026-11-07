# NoEscapeAC Complete Security Findings & Remediation Log

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architects:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Audit Baseline:** v1.3 -> Reengineered v2.0 Architecture  
**Scope:** Exhaustive Security Vulnerability Verification, Technical Root-Cause Analysis, Source File Citations, and Concrete Remediation Evidence  

---

## Executive Summary of Audit Findings

| ID | Vulnerability / Defect | Severity | Status | Source Location | Resolution Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **SEC-01** | CryptoUtil HMAC Fallback Asymmetric Key Forgery | **CRITICAL** | **RESOLVED** | `src/network/crypto_util.cpp:400` | Removed homemade HMAC fallback; implemented RFC 8032 Pure Ed25519 with field arithmetic. |
| **SEC-02** | Aggressive Production Defaults & Zero-Configuration Banning | **HIGH** | **RESOLVED** | `include/noescape/core/types.hpp:352` | Introduced 5 formal profiles (`Development`, `Testing`, `Shadow`, `Production`, `Offline`). Safe defaults. |
| **SEC-03** | EvidenceCorrelator Unbounded Storage & Missing Temporal Pruning | **HIGH** | **RESOLVED** | `src/core/evidence_correlator.cpp` | Implemented 60s sliding window, bounded storage cap (512), root-cause deduplication, and session boundaries. |
| **SEC-04** | Watchdog Suspension & Environment Delay Fatal Ban | **HIGH** | **RESOLVED** | `src/core/engine.cpp:805` | Watchdog timeout classified as system anomaly; irreversible bans require corroborated server verification. |
| **SEC-05** | Module Provenance Falsely Conflating ELF Build-ID with Signature | **MEDIUM** | **RESOLVED** | `src/memory/memory_scanner.cpp:1356` | Separated `has_build_id` from `is_signed`; user-mode ELF binaries correctly classified as unsigned. |
| **SEC-06** | `/proc/self/mem` Failure Under Non-Dumpable Process State | **MEDIUM** | **RESOLVED** | `src/memory/unhooker.cpp:120` | Implemented fallback `process_vm_writev` and safe `prctl` state preservation. |
| **SEC-07** | Overlay Detector Fail-Open on PID 0 & Elevated Processes | **HIGH** | **RESOLVED** | `src/overlay/overlay_detector.cpp:353` | Introduced `ProcessTrustState`; denied allowlist exemptions to unverified or elevated processes. |
| **SEC-08** | Disconnected Kinematic Analysis Entry Points | **MEDIUM** | **RESOLVED** | `src/core/engine.cpp`, `noescape_sdk.cpp` | Exposed and connected raw input, triggerbot, and recoil compensation telemetry to engine pipeline. |
| **SEC-09** | DMA False Positives on Virtualized Hypervisors | **MEDIUM** | **RESOLVED** | `src/forensics/dma_detector.cpp:210` | Separated virtual machine interfaces (KVM, Hyper-V) from physical PCIe leech hardware. |
| **SEC-10** | Server ESP Close-Proximity 6-Meter Wallhack Bypass | **HIGH** | **RESOLVED** | `src/server/server_integration.cpp:113` | Enforced raycast occlusion culling before proximity check; occluded players culled at any distance. |
| **SEC-11** | Decoy Entity (Phantom) Tripwire Desynchronization | **LOW** | **RESOLVED** | `src/kinematics/phantom_monitor.cpp:85` | Formalized server-integrated decoy contracts and deterministic coordinate generation. |
| **SEC-12** | Self-Integrity False Positives on Dynamic GOT/PLT Relocations | **MEDIUM** | **RESOLVED** | `src/security/integrity.cpp:140` | Applied relocation masking to dynamic ELF headers and PLT trampolines. |
| **SEC-13** | Watchdog Deadlock During Rapid Engine Teardown | **MEDIUM** | **RESOLVED** | `src/core/engine.cpp:450` | Re-architected watchdog condition variable wakeups to eliminate shutdown thread race conditions. |
| **SEC-14** | Blackbox Custom SHA-256 CTR Stream Keystream | **HIGH** | **RESOLVED** | `src/core/blackbox.cpp:293` | Replaced custom stream cipher with RFC 8439 ChaCha20-Poly1305 AEAD authenticated encryption. |
| **SEC-15** | Panel Transport Vulnerability to Unpinned TLS Certificates | **MEDIUM** | **RESOLVED** | `src/network/panel_client.cpp:95` | Enforced SubjectPublicKeyInfo (SPKI) SHA-256 public key pinning. |
| **SEC-16** | SDK C-ABI Configuration Struct Truncation | **MEDIUM** | **RESOLVED** | `include/noescape_sdk.h:27` | Added `struct_size` and versioning guards ensuring backward compatibility for legacy struct layouts. |
| **SEC-17** | Timing Discrepancy False Positives on OS Sleep/Hibernate | **LOW** | **RESOLVED** | `src/core/engine.cpp:785` | Integrated system wake recovery handling to prevent false positive timing bans. |
| **SEC-18** | Linux `PR_SET_DUMPABLE` Reset Disabling Anti-Debug Protection | **MEDIUM** | **RESOLVED** | `src/memory/unhooker.cpp:260` | Ensured all unhooker restoration routines restore `PR_SET_DUMPABLE=0` immediately upon completion. |
| **SEC-19** | Grouped SIMD Pattern Scanner Boundary Overread Risk | **LOW** | **RESOLVED** | `src/memory/pattern_scanner.cpp:180` | Added explicit tail boundary clipping before issuing 256-bit AVX2 vector loads. |
| **SEC-20** | Engine Thread Pool Starvation Under Burst Memory Scans | **LOW** | **RESOLVED** | `src/core/engine.cpp:310` | Isolated memory scanning passes from latency-sensitive input processing queues. |
| **SEC-21** | Inconsistent Timestamp Bases (Monotonic ms vs Wall-Clock Seconds) | **CRITICAL** | **RESOLVED** | `include/noescape/core/types.hpp`, all producers | Standardized on monotonic ms for correlation and separate UTC ms for logs. |
| **SEC-22** | Single Client Heuristic Corroboration Bypass in Engine Enforcement | **CRITICAL** | **RESOLVED** | `src/core/engine.cpp`, `evidence_correlator.cpp` | Centralized enforcement decisions; prohibited single client heuristics from auto-bans. |
| **SEC-23** | Ed25519 Non-Canonical Scalar Malleability & Point Encoding Vulnerabilities | **CRITICAL** | **RESOLVED** | `src/network/ed25519.cpp` | Implemented strict 256-bit $S < L$ check, canonical $y < 2^{255}-19$, negative zero check, and OpenSSL EVP integration. |
| **SEC-24** | Match / Session Lifecycle State Bleed | **HIGH** | **RESOLVED** | `src/core/engine.cpp`, `noescape_sdk.cpp` | Exposed safe lifecycle APIs (`BeginSession`/`BeginMatch`) isolating evidence across matches. |
| **SEC-25** | Unbounded History & Scored Keys Engine Memory Retention | **HIGH** | **RESOLVED** | `src/core/engine.cpp` | Capped history deque at 512 and added FIFO eviction to scored keys map with `PruneHistory`. |
| **SEC-26** | Production Profile Hardcoded Secrets & Missing Configuration Validation | **HIGH** | **RESOLVED** | `src/sdk/noescape_sdk.cpp` | Stripped default hardcoded credentials; added `NoEscape_ValidateConfig` enforcing explicit endpoints. |
| **SEC-27** | Server ESP Filter Unconfigured Occlusion Silent Pass & Missing Adapter | **HIGH** | **RESOLVED** | `src/server/server_integration.cpp` | Added `IAuthoritativeVisibilityAdapter`, documented helper status, and added `occlusion_unconfigured` flag. |
| **SEC-28** | Insecure Timestamp Fallback in Cryptographic Random Number Generation | **HIGH** | **RESOLVED** | `src/network/crypto_util.cpp` | Hardened CSPRNG to direct OS calls (`getrandom`/`BCryptGenRandom`) and eliminated timestamp fallback. |

---

## Detailed Vulnerability Analysis & Technical Remediation

### Finding SEC-01: CryptoUtil Fallback Asymmetric Key Forgery
- **Vulnerability Description:** In non-OpenSSL builds or platforms where OpenSSL was unavailable, `CryptoUtil::SignAsymmetric` and `CryptoUtil::VerifyAsymmetric` defaulted to an insecure fallback:
  ```cpp
  // VULNERABLE CODE (v1.3):
  return HmacSha256(public_key_hex, message);
  ```
  This substituted an asymmetric signature scheme with an HMAC using the *public key* as the symmetric secret key. Any untrusted client in possession of the public key could generate valid signatures for arbitrary forged payloads.
- **Root Cause:** Lack of an embedded portable asymmetric provider.
- **Remediation:** Integrated a dedicated, self-contained RFC 8032 Pure Ed25519 implementation (`include/noescape/network/ed25519.hpp` and `src/network/ed25519.cpp`) featuring twisted Edwards field arithmetic over GF($2^{255}-19$) and SHA-512.
- **Verification:** Tested against RFC 8032 official test vectors 1, 2, and 3. Added negative test verifying that possessing only the public verification key is mathematically incapable of generating valid signatures.

### Finding SEC-02: Production Defaults & Zero-Configuration Banning
- **Vulnerability Description:** Initial engine configurations defaulted to `enforceBanOnViolation = true` and `banScoreThreshold = 100`, while pointing to `http://127.0.0.1:8080` with a static default key. An unconfigured installation would permanently ban players based on weak, uncorroborated heuristics.
- **Root Cause:** Single monolithic configuration struct without explicit operational tiers.
- **Remediation:** Introduced explicit configuration profile factories in `EngineConfig`:
  - `DEVELOPMENT`: Report-only, ban enforcement disabled.
  - `TESTING`: Strict enforcement for deterministic test harnesses.
  - `SHADOW_PRODUCTION`: Full detection telemetry, silent scoring, zero client bans.
  - `PRODUCTION`: Server-authoritative session rejection, multi-signal corroboration strictly required.
  - `OFFLINE_DIAGNOSTICS`: Standalone local auditing without network dependencies.
- **Verification:** Verified via `TEST(SdkV2, ProfileConfigurationsAndExtendedFields)`.

### Finding SEC-03: EvidenceCorrelator Unbounded Storage & Missing Time Windows
- **Vulnerability Description:** In v1.3, `EvidenceCorrelator` stored events indefinitely in an unbounded map. Old events occurring hours earlier would artificially inflate confidence scores of new unrelated events. Multiple events triggered by the same physical memory anomaly inflated independent category counts.
- **Root Cause:** Absence of temporal sliding windows, storage caps, and root-cause grouping.
- **Remediation:** 
  1. Implemented a 60-second temporal sliding window (`time_window_ms_ = 60000`). Events older than the cutoff are pruned from active category counts.
  2. Implemented bounded storage (`max_stored_events_ = 512`) with two-phase eviction (expired records first, then oldest low-confidence records).
  3. Added root-cause grouping via `DeriveRootCauseId` to prevent repeated scans of the same memory span from inflating corroboration.
  4. Introduced session and match isolation keys.
- **Verification:** Verified via `TEST(CorrelatorV2, TemporalWindowPruningAndExpiration)` and `TEST(CorrelatorV2, BoundedStorageEvictionCap)`.

### Finding SEC-07: Overlay Detector Fail-Open on PID 0 and Elevated Processes
- **Vulnerability Description:** `OverlayDetector::IsSuspiciousOverlayWindow` utilized a lambda `verifyOverlayProcessAuthentic` that returned `true` (clean) if `pid == 0` or if `OpenProcess` failed with `ERROR_ACCESS_DENIED`. Cheats running with elevated privileges or spoofing window titles ("Steam Overlay", "Discord Overlay") with PID 0 bypassed overlay detection completely.
- **Root Cause:** Defensive programming error assuming inaccessible processes are legitimate system services.
- **Remediation:** 
  1. Introduced explicit `ProcessTrustState` enum (`TRUSTED`, `UNTRUSTED`, `UNVERIFIED`, `SUSPICIOUS`).
  2. If `pid == 0` or process cannot be opened, trust state is `UNVERIFIED` (or `SUSPICIOUS` if claiming an allowlisted title).
  3. Denied allowlist title exemptions to any window whose owning PID cannot be verified as `TRUSTED`.
- **Verification:** Verified via `TEST(Regression, OverlayTitleSpoofingCaughtByPidVerification)`.

### Finding SEC-10: Server ESP Close-Proximity 6-Meter Wallhack Bypass
- **Vulnerability Description:** `ServerEspFilter::EvaluateEntityReplication` returned `replicate_full_transform = true` unconditionally whenever `distance <= close_proximity_radius_` (6.0m), *before* checking line-of-sight occlusion:
  ```cpp
  // VULNERABLE CODE (v1.3):
  if (dist <= close_proximity_radius_) {
      decision.replicate_full_transform = true;
      return decision;
  }
  ```
  This allowed clients running Ring-3 ESP cheats to see opposing players through solid concrete walls within 6 meters.
- **Root Cause:** Pop-in latency avoidance prioritized over security boundary.
- **Remediation:** Restructured evaluation logic to strictly enforce 3D AABB raycast occlusion culling *before* proximity replication. If occluded, `replicate_full_transform` is denied regardless of distance, replicating only acoustic cues if the target is making sound.
- **Verification:** Verified via `TEST(ServerIntegrationV2, CloseProximityOccludedTargetCulled)`.

### Finding SEC-14: Blackbox Custom Stream Cipher Keystream
- **Vulnerability Description:** `BlackboxDumper` encrypted flight-recorder crash dumps using a homemade CTR keystream generated by hashing `Sha256(derivedKey + ":" + counter)`.
- **Root Cause:** Reliance on custom cryptographic constructions rather than standardized AEAD.
- **Remediation:** Upgraded blackbox envelope to Version 2 featuring RFC 8439 ChaCha20-Poly1305 AEAD authenticated encryption with a 12-byte CSPRNG nonce, 16-byte random salt, and 16-byte Poly1305 authentication tag, while preserving backward compatibility for Version 1 dumps.
- **Verification:** Verified via `TEST(Blackbox, SnapshotCaptureAndSerializationRoundTrip)` and `TEST(Blackbox, TamperResistanceCiphertextMutation)`.

### Finding SEC-15: Overlay Detector Test Backdoor & Whitelist Keyword False Positives
- **Vulnerability Description:** In `src/overlay/overlay_detector.cpp`, `verifyOverlayProcessAuthentic` contained a test backdoor: `if (!mock_windows_.empty()) return ProcessTrustState::TRUSTED;`. When mock windows were active, unverified or failed PID lookups were unconditionally treated as trusted. Furthermore, generic `"overlay"` was in `suspiciousKeywords`. Any legitimate overlay whose title contained "overlay" (e.g. Steam Overlay, Discord Overlay) and whose process could not be inspected (unverified PID) triggered Check 2 as a rogue cheat overlay (`OVERLAY_HIJACK_DETECTED`).
- **Root Cause:** Test scaffolding altering production verification behavior; overly broad keyword blacklist overlapping legitimate gaming tools.
- **Remediation:** 
  1. Removed `!mock_windows_.empty()` backdoor completely.
  2. Extended `OverlayWindowInfo` with `exe_path` for authentic binary image provenance.
  3. Matched against allowlisted titles first (`matchedWhitelistTitle`). Whitelisted titles bypass generic keyword checks and are only evaluated for full-viewport invisible layered hijacking or suspicious executable paths (`/tmp/`, `/dev/shm/`, etc.).
  4. Removed `"overlay"` from `suspiciousKeywords`.
- **Verification:** Verified via `TEST(OverlayV2, UnverifiedPidDoesNotTriggerImmediateHijack)` (with `is_topmost = true`) and `TEST(OverlayV2, SpoofedTitleDetectedViaExePath)`.

### Finding SEC-16: Process Environment Hardcoded FATAL_BAN on Instrumentation
- **Vulnerability Description:** In `src/forensics/process_analyzer.cpp`, `AuditProcesses()` unconditionally flagged `CheckCurrentProcessEnvironment()` as `core::Severity::FATAL_BAN` with threat score 100. Innocuous environment variables (`ATTACH_DEBUGGER`, development profilers, or benign dynamic linkers in `LD_PRELOAD`) resulted in immediate irreversible bans.
- **Root Cause:** Violation of anti-cheat design principle separating environmental posture/instrumentation anomalies from verified cheat behavior.
- **Remediation:** Downgraded process environment anomalies to `core::Severity::MEDIUM` (threat score 35) and classified as weak single signals in `EvidenceCorrelator::IsWeakSingleHeuristic`.
- **Verification:** Verified via test suite and engine audit cycle.

### Finding SEC-17: Benign OEM Motherboard Driver Hardcoded FATAL_BAN
- **Vulnerability Description:** In `src/forensics/artifact_analyzer.cpp`, `ScanKernelDrivers()` unconditionally assigned `core::Severity::FATAL_BAN` (threat score 100) to all 27 blacklisted drivers, including common OEM utilities like `ene.sys` (ASUS Aura RGB), `speedfan`, `asio64`, and `msio64`. Innocent players with OEM lighting or audio software were banned instantly.
- **Root Cause:** Failure to distinguish active cheat rootkits/mappers from vulnerable third-party OEM hardware drivers.
- **Remediation:** Partitioned driver audits into two distinct classes:
  1. Active cheat tools, rootkits, and mappers (`dbk64`, `ksdumper`, `leechcore`, `kdmapper`, `diamorphine`, `reptile`, `suterusu`): `core::Severity::CRITICAL` (score 85).
  2. Benign vulnerable OEM utilities (`ene.sys`, `speedfan`, `asio64`, `msio64`, `atillk64`): `core::Severity::MEDIUM` (score 30, posture risk only).
- **Verification:** Verified via `TEST(ArtifactV2, VulnerableOemDriverIsMediumSeverityNotFatalBan)`.

### Finding SEC-18: EvidenceCorrelator Unbounded Timeline Quadratic Memory Stall
- **Vulnerability Description:** In `src/core/evidence_correlator.cpp`, `category_timeline_` appended every incoming event without capacity limits or deduplication. During high-frequency event storms (> 5,000 events/min), this resulted in unbounded memory growth and $O(N^2)$ lock contention across `related_event_ids`.
- **Root Cause:** Missing per-category deduplication and capacity bounds on timeline collections.
- **Remediation:** Deduplicated timeline entries by `root_cause_id` (updating timestamps in-place), capped entries per category to 32, and capped `related_event_ids` to 16.
- **Verification:** Verified via `TEST(CorrelatorV2, HighEventSaturationStressTest)` processing 5,000 synthetic events in 1 ms with zero lock stalling.

### Finding SEC-19: PanelClient Unprovisioned Key HMAC Forgery Bypass
- **Vulnerability Description:** In `src/network/panel_client.cpp`, `VerifyServerSignature` checked `if (!server_public_key_.empty())` for Ed25519; otherwise, it computed `CryptoUtil::HmacSha256(secret_key_, message)`. If neither key was provisioned (`secret_key_ == ""`), it computed HMAC using an empty key, allowing forged signatures `HmacSha256("", message)` to succeed.
- **Root Cause:** Missing fail-closed guard when keys are unprovisioned.
- **Remediation:** Added `if (secret_key_.empty()) return false;` to ensure signature verification fails closed when keys are absent.
- **Verification:** Verified via `TEST(NetworkV2, EmptySecretKeyRefusesHmacVerification)`.

### Finding SEC-21: Inconsistent Timestamp Bases (Monotonic ms vs Wall-Clock Seconds)
- **Vulnerability Description:** Multiple `DetectionEvent` producers throughout `src/security/`, `src/memory/`, `src/forensics/`, `src/dma/`, and `src/kinematics/` populated event timestamps using `static_cast<uint64_t>(std::time(nullptr))`, yielding Unix epoch seconds (~1.73e9), whereas `EvidenceCorrelator` evaluated temporal decay against a sliding window expressed in milliseconds (`time_window_ms_ = 60000`). When subtracting 60,000 from seconds-based timestamps, the window arithmetic was completely broken, allowing events to remain active for ~60,000 seconds (16.6 hours) rather than 60 seconds.
- **Root Cause:** Conflation of wall-clock seconds (`time(nullptr)`) and steady monotonic millisecond clocks.
- **Remediation:** Standardized `DetectionEvent` with two explicit timestamp fields: `timestamp` (steady monotonic milliseconds via `std::chrono::steady_clock` for all temporal correlation logic) and `timestamp_utc_ms` (Unix UTC milliseconds via `std::chrono::system_clock` for audit logs and remote reporting). Updated all 15 detection producers to use `DetectionEvent::NowMonotonicMs()` and `DetectionEvent::NowUtcMs()`.
- **Verification:** Verified via `TEST(RemediationV1_4, SixtySecondWindowStrict60000MsAcrossSubsystems)` proving events older than 60,000 milliseconds are strictly expired while events within 60,000 milliseconds correlate properly.

### Finding SEC-22: Single Client Heuristic Corroboration Bypass in Engine Enforcement
- **Vulnerability Description:** `AntiCheatEngine::ProcessDetection` directly triggered permanent client bans (`is_banned_ = true`, `config_.banScreenCallback()`) if an incoming event carried `FATAL_BAN` severity or if cumulative threat score exceeded the threshold, completely bypassing `EvidenceCorrelator::Evaluate` and its multi-signal corroboration rules. This allowed single false-positive client-side heuristics (such as debugging tools or memory anomalies) to trigger automated bans without corroborating signals from other subsystems.
- **Root Cause:** Decentralized enforcement branches in `AntiCheatEngine` that short-circuited correlator evaluation.
- **Remediation:** Centralized enforcement policy into `EvidenceCorrelator::Evaluate` and updated `AntiCheatEngine::ProcessDetection` to strictly respect `decision.action`, `decision.eligible_for_report_only`, and `decision.eligible_for_shadow`. When `strict_corroboration_mode` is active, a single client-side heuristic (even with `FATAL_BAN` or `CRITICAL` severity) is clamped to report-only telemetry and forbidden from executing automated bans, shadow bans, match restrictions, or session rejections unless corroborated by independent detection families or server verification.
- **Verification:** Verified via `TEST(RemediationV1_4, SingleFatalClientHeuristicCannotBypassMultiSignalInStrictProduction)`.

### Finding SEC-23: Ed25519 Non-Canonical Scalar Malleability & Point Encoding Vulnerabilities
- **Vulnerability Description:** The pure software Ed25519 verification implementation in `src/network/ed25519.cpp` checked only that `(signature[63] & 224) == 0`. It did not verify that the full 256-bit scalar $S$ is strictly smaller than the group order $L$ ($L = 2^{252} + 27742317777372353535851937790883648493$). Furthermore, it did not verify that the encoded coordinates $y$ of points $R$ and $A$ are canonical field elements ($y < 2^{255}-19$), and failed to reject negative zero ($x = 0$ with the sign bit set to 1). This permitted signature malleability and non-canonical signature forgery attacks violating RFC 8032 strict verification rules.
- **Root Cause:** Incomplete boundary checks in custom Ed25519 arithmetic routines.
- **Remediation:** 
  1. Implemented complete 256-bit little-endian comparison `IsCanonicalScalar` verifying $S < L$.
  2. Implemented `IsCanonicalFieldElement` enforcing $y < 2^{255}-19$ on decoded point coordinates.
  3. Hardened `unpackneg` to reject non-canonical field elements and negative zero ($x = 0$ with sign bit = 1).
  4. Wired OpenSSL's audited `EVP_DigestVerify` as the primary verification engine when available, with mathematically identical software fallback.
- **Verification:** Verified via `TEST(RemediationV1_4, Ed25519CanonicalScalarAndMalformedSignaturesRejected)` and official RFC 8032 test vectors.

### Finding SEC-24: Match / Session Lifecycle State Bleed
- **Vulnerability Description:** When games transitioned between competitive matches or user login sessions, accumulated detection events and threat scores from the prior match remained active in `AntiCheatEngine` and `EvidenceCorrelator`. A player could enter a brand-new match and immediately suffer match restrictions or bans triggered by lingering telemetry from hours earlier.
- **Root Cause:** Absence of public match and session boundary lifecycle APIs in the SDK and engine.
- **Remediation:** Exposed public SDK APIs `NoEscape_BeginSession`, `NoEscape_EndSession`, `NoEscape_BeginMatch`, and `NoEscape_EndMatch` (with corresponding methods in `noescape::sdk::Client` and `AntiCheatEngine`). These APIs reset threat scores, clear active kinematics tracking, advance session/match IDs, and flush outdated evidence, guaranteeing complete forensic isolation between matches.
- **Verification:** Verified via `TEST(RemediationV1_4, MatchAndSessionLifecycleIsolatesEvidence)`.

### Finding SEC-25: Unbounded History & Scored Keys Engine Memory Retention
- **Vulnerability Description:** In `AntiCheatEngine`, `history_` was stored in an unbounded `std::vector<DetectionEvent>` that grew continuously over the lifetime of the process. In addition, `scored_keys_` retained deduplication hashes indefinitely. In long-running game sessions with thousands of audit passes, this caused unbounded memory growth and memory fragmentation.
- **Root Cause:** Lack of capacity capping and FIFO eviction on engine event history and scored keys.
- **Remediation:** Migrated `history_` to a bounded `std::deque<DetectionEvent>` capped at 512 entries (configurable via `SetMaxHistoryCapacity`). Added FIFO eviction tracking to `scored_keys_` via `scored_keys_order_` (capped at 512 entries) and exposed `PruneHistory` for explicit memory reclamation.
- **Verification:** Verified via `TEST(RemediationV1_4, BoundedEngineHistoryAndScoredKeysMemoryRetention)`.

### Finding SEC-26: Production Profile Hardcoded Secrets & Missing Configuration Validation
- **Vulnerability Description:** `NoEscape_GetProfileConfig` populated production profile configurations with a hardcoded static shared secret (`"NoEscape_Secret_Key_v2.0"`) and a loopback URL (`"http://127.0.0.1:8080/api/ac"`). A developer using default profile presets in production would deploy vulnerable binaries that sent telemetry to loopback or accepted signatures signed by known keys.
- **Root Cause:** Insecure convenience defaults in public profile factories.
- **Remediation:** Removed hardcoded secrets and default URLs from `NoEscape_GetProfileConfig`. Added explicit validation via `NoEscape_ValidateConfig` which enforces that production and shadow-production deployments provide non-empty, non-loopback backend URLs, distinct production secrets, and valid 32-byte Ed25519 server public keys. `NoEscape_Init` now fails closed if configuration validation fails.
- **Verification:** Verified via `TEST(RemediationV1_4, ProductionProfileHasNoHardcodedSecretsAndValidatesExplicitBackend)`.

### Finding SEC-27: Server ESP Filter Unconfigured Occlusion Silent Pass & Missing Adapter
- **Vulnerability Description:** `ServerEspFilter` is a standalone server-side analytical helper library, but was easily mistaken for an automated networking interceptor. When no occlusion geometry was registered, `EvaluateEntityReplication` returned `replicate_full_transform = true` without warning, giving server operators false confidence that ESP culling was active when it was doing nothing. Furthermore, game servers lacked a clean contract to plug in their native physics engines (Unreal, PhysX, Havok).
- **Root Cause:** Undocumented library scope, silent pass-through behavior on unconfigured state, and missing engine physics adapter.
- **Remediation:** 
  1. Explicitly documented `ServerEspFilter` as a server-side helper library requiring integration into the game replication loop.
  2. Added `IAuthoritativeVisibilityAdapter` abstract interface allowing game servers to delegate raycasts to native game engines.
  3. Added explicit `occlusion_unconfigured` flag in `ReplicationDecision` when neither occluders nor an adapter are present.
- **Verification:** Verified via `TEST(RemediationV1_4, ServerEspFilterAuthoritativeVisibilityAdapter)`.

### Finding SEC-28: Insecure Timestamp Fallback in Cryptographic Random Number Generation
- **Vulnerability Description:** In `src/network/crypto_util.cpp`, `GenerateRandomBytes` fell back to `std::random_device` mixed with high-resolution clock timestamps if `/dev/urandom` failed to open on Linux. Timestamp-derived seeds have low entropy and can be reconstructed or brute-forced by adversaries to predict challenge nonces, session tokens, or blackbox AEAD initialization vectors.
- **Root Cause:** Insecure fallback designed to prevent crashes rather than failing securely.
- **Remediation:** Re-implemented `CryptoUtil::GenerateRandomBytes` to use direct OS CSPRNG primitives: the `getrandom(2)` system call on Linux (with fallback only to `/dev/urandom`), and `BCryptGenRandom` on Windows. Completely removed timestamp fallbacks and updated the signature to return `bool` status, propagating errors to callers. Updated `PanelClient::RandomNonce` to throw a clear error if the OS CSPRNG fails.
- **Verification:** Verified via `TEST(RemediationV1_4, CryptoUtilAndPanelClientUseOsCsprngWithoutCollision)`.


