# NoEscapeAC Complete File Inventory & Architectural Index

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architect:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Language Standard:** Modern C++20  
**Target Environments:** Linux (POSIX x86_64) & Microsoft Windows (Win32 / NT x86_64)  
**Security Tier:** Strict Ring-3 Client Hardening & Authoritative Server Integration  

---

## 1. Core Architecture Subsystem (`src/core/`, `include/noescape/core/`)

### `include/noescape/core/types.hpp`
- **Purpose:** Central definition of all security types, detection categories, confidence tiers, evidence states, configuration structures, and profile definitions.
- **Public Interfaces:** `DetectionType`, `Severity`, `ConfidenceLevel`, `EvidenceState`, `ConfigurationProfile`, `EnforcementMode`, `DetectionCategory`, `DetectionEvent`, `EngineConfig`.
- **Internal Dependencies:** `<cstdint>`, `<string>`, `<vector>`, `<chrono>`, `<functional>`.
- **Data Ownership:** Plain-Old-Data (POD) and immutable telemetry state containers passed across threads.
- **Security Responsibility:** Canonical enumeration of all detectable threats and threshold invariants.
- **Platform Dependencies:** Universal (Pure C++20).
- **Error Handling:** Safe defaults; bounded sanitization in string conversions.
- **Test Coverage:** `test_engine.cpp`, `test_audit_v2_reengineering.cpp`, `test_sdk.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/core/engine.hpp` & `src/core/engine.cpp`
- **Purpose:** Primary orchestration engine coordinating memory audits, kinematics, overlays, forensics, watchdog supervision, and evidence routing.
- **Public Interfaces:** `AntiCheatEngine`, `Initialize`, `Start`, `Stop`, `AuditTick`, `ProcessDetection`, `PushInputSample`, `PushRawInput`, `RecordTargetAcquire`, `PushWeaponFire`, `PushRecoilEvent`, `PushViewSample`.
- **Internal Dependencies:** All subsystems (`MemoryScanner`, `Unhooker`, `AimAnalyzer`, `PhantomMonitor`, `OverlayDetector`, `DmaDetector`, `EvidenceCorrelator`, `BlackboxDumper`).
- **Thread Ownership:** Manages background audit thread, watchdog supervision thread, and network heartbeat worker.
- **Data Ownership:** Thread-safe state machines via `std::atomic` and mutexes (`input_mutex_`, `history_mutex_`, `heartbeat_mutex_`).
- **Security Responsibility:** Final threat evaluation, ban callback dispatch, blackbox dump serialization, and tamper detection.
- **Platform Dependencies:** Cross-platform (POSIX threads / Windows threads).
- **Error Handling:** Graceful subsystem failure; non-crashing telemetry degradation.
- **Test Coverage:** `test_engine.cpp`, `test_regressions.cpp`, `test_audit_v2_reengineering.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/core/evidence_correlator.hpp` & `src/core/evidence_correlator.cpp`
- **Purpose:** Temporal multi-signal evidence correlation, root-cause deduplication, session/match isolation, and ban-eligibility verification.
- **Public Interfaces:** `EvidenceCorrelator`, `Evaluate`, `MarkServerVerified`, `SetSessionId`, `SetMatchId`, `SetTimeWindowMs`, `SetMaxStoredEvents`, `GetActiveCategoryCount`, `PruneExpired`, `GetAggregatedEvidence`.
- **Internal Dependencies:** `types.hpp`, `crypto_util.hpp`.
- **Thread Ownership:** Thread-safe; protected by internal `mutable std::mutex`.
- **Data Ownership:** Bounded storage mapping (`max_stored_events_ = 512`), temporal category timeline, and active session identity.
- **Security Responsibility:** Prevents uncorroborated single-heuristic bans; gates irreversible actions behind multi-category corroboration or server verification.
- **Platform Dependencies:** Universal C++20.
- **Error Handling:** Automatic capacity eviction (expired records first, then oldest low-confidence records).
- **Test Coverage:** `test_server_and_correlation.cpp`, `test_audit_v2_reengineering.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/core/blackbox.hpp` & `src/core/blackbox.cpp`
- **Purpose:** Flight-recorder crash and violation diagnostic dumper using RFC 8439 ChaCha20-Poly1305 AEAD authenticated encryption.
- **Public Interfaces:** `BlackboxDumper`, `CaptureSnapshot`, `SerializeAndEncrypt`, `DecryptAndDeserialize`, `WriteDumpToFile`, `RecordInputSample`.
- **Internal Dependencies:** `crypto_util.hpp`, `obfuscation.hpp`.
- **Thread Ownership:** Singleton instance; circular input trail protected by mutex.
- **Data Ownership:** Ephemeral input samples and diagnostic metadata.
- **Security Responsibility:** Tamper-evident, forward-secure post-incident forensics.
- **Platform Dependencies:** POSIX backtrace / Win32 StackWalk64.
- **Error Handling:** Returns false on MAC verification or format failure; does not throw exceptions.
- **Test Coverage:** `test_blackbox.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/core/obfuscation.hpp`
- **Purpose:** Compile-time string encryption, FNV-1a hashing, and runtime variable protection via `ObfuscatedValue<T>`.
- **Public Interfaces:** `OBFUSCATE_STR`, `OBFUSCATE_KEY`, `CompileTimeFnv1a`, `ObfuscatedValue<T>`.
- **Internal Dependencies:** `<type_traits>`, `<cstdint>`, `<array>`.
- **Thread Ownership:** Thread-safe value wrappers with rolling key generation.
- **Data Ownership:** Encrypted scalar representations in memory.
- **Security Responsibility:** Prevents static binary string extraction and direct cheat memory searching (e.g. Cheat Engine float scans).
- **Platform Dependencies:** Universal C++20.
- **Error Handling:** Compile-time static assertions.
- **Test Coverage:** `test_obfuscation.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

---

## 2. Memory & Code Integrity Subsystem (`src/memory/`, `include/noescape/memory/`)

### `include/noescape/memory/memory_scanner.hpp` & `src/memory/memory_scanner.cpp`
- **Purpose:** High-performance Ring-3 memory auditor scanning for unbacked executable pages, sleeping payloads, corrupted module headers, thread IP provenance, and module provenance.
- **Public Interfaces:** `MemoryScanner`, `DetectUnbackedExecutableRegions`, `DetectModifiedModules`, `DetectSleepingPayloads`, `AuditThreadProvenance`, `QueryModuleProvenance`, `AuditModuleProvenance`, `PerformAudit`.
- **Internal Dependencies:** `pattern_scanner.hpp`, `signature_database.hpp`, `crypto_util.hpp`.
- **Thread Ownership:** Called from engine background thread or synchronous audit tick.
- **Data Ownership:** Cached region maps and module hashes.
- **Security Responsibility:** Detects injected DLLs, shellcode stubs, reflective loaders, and manual map injectors.
- **Platform Dependencies:** Linux `/proc/self/maps` & Win32 `VirtualQueryEx`.
- **Error Handling:** Non-dumpable process fallback (`/proc/self/mem`); skips inaccessible pages safely.
- **Test Coverage:** `test_memory.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/memory/unhooker.hpp` & `src/memory/unhooker.cpp`
- **Purpose:** Detection and automatic clean restoration of inline hooks, trampolines, and CET `endbr64` offset hooks on critical system libraries (`ntdll.dll`, `kernel32.dll`, `libc.so.6`, `libdl.so.2`).
- **Public Interfaces:** `Unhooker`, `AuditSystemHooks`, `RestoreHook`, `SetWhitelistModule`.
- **Internal Dependencies:** Pure ELF / PE parsing, `mprotect` / `VirtualProtect`.
- **Thread Ownership:** Singleton accessed during audit cycles.
- **Data Ownership:** Clean on-disk reference text sections.
- **Security Responsibility:** Disarms user-mode API detours installed by external tools or malware.
- **Platform Dependencies:** Linux ELF / Windows PE.
- **Error Handling:** Restores memory permissions safely; handles non-dumpable processes via `/proc/self/mem`.
- **Test Coverage:** `test_memory.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/memory/canary_monitor.hpp` & `src/memory/canary_monitor.cpp`
- **Purpose:** Distributed memory canary tripwires detecting arbitrary memory writes, pointer scans, and memory corruption.
- **Public Interfaces:** `CanaryMonitor`, `Initialize`, `Check`, `Shutdown`.
- **Internal Dependencies:** `crypto_util.hpp`.
- **Thread Ownership:** Thread-safe singleton.
- **Data Ownership:** Encrypted guard values at randomized virtual addresses.
- **Security Responsibility:** Catches memory writes from cheats attempting to alter anti-cheat pointers or game state.
- **Platform Dependencies:** Universal POSIX / Win32 virtual memory allocations.
- **Error Handling:** Controlled degradation if allocations fail.
- **Test Coverage:** `test_memory.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/memory/pattern_scanner.hpp` & `src/memory/pattern_scanner.cpp`
- **Purpose:** AVX2/SSE2 vector-accelerated multi-pattern signature scanner with grouped SIMD bucket matching.
- **Public Interfaces:** `Pattern`, `PatternScanner::Scan`, `PatternScanner::ScanBatch`.
- **Internal Dependencies:** `<immintrin.h>`, C++20 bit operations.
- **Thread Ownership:** Stateless; safe for concurrent execution across worker threads.
- **Data Ownership:** Caller-owned buffers and pattern sets.
- **Security Responsibility:** Ultra-fast detection of known cheat binary byte signatures in memory.
- **Platform Dependencies:** x86_64 AVX2 / SSE2 with scalar fallback.
- **Error Handling:** Strict boundary validation avoiding buffer overreads.
- **Test Coverage:** `test_simd_scanner.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/memory/signature_database.hpp` & `src/memory/signature_database.cpp`
- **Purpose:** Built-in repository of verified cheat signatures (Vape, LiquidBounce, Meteor, CheatEngine, Xenos, Injectors).
- **Public Interfaces:** `SignatureDatabase::GetDefaultSignatures`, `AddCustomSignature`.
- **Internal Dependencies:** `pattern_scanner.hpp`.
- **Data Ownership:** Static signature rules.
- **Security Responsibility:** Immediate matching against prevalent open-source and commercial cheat payloads.
- **Platform Dependencies:** Universal.
- **Test Coverage:** `test_signatures.cpp`.
- **Integration Status:** 100% Integrated.

---

## 3. Kinematics & Behavioral Subsystem (`src/kinematics/`, `include/noescape/kinematics/`)

### `include/noescape/kinematics/aim_analyzer.hpp` & `src/kinematics/aim_analyzer.cpp`
- **Purpose:** Real-time trajectory kinematics analyzer detecting instant snap aimbots, robotic linearity, unnatural smoothing, HID input quantization (macros), triggerbots, and recoil compensation automation.
- **Public Interfaces:** `AimAnalyzer`, `PushSample`, `RecordRawInputSample`, `RecordCrosshairTargetAcquire`, `RecordWeaponFire`, `RecordRecoilCompensation`, `ComputeCurrentMetrics`, `Reset`.
- **Internal Dependencies:** `types.hpp`.
- **Thread Ownership:** Guarded by `input_mutex_` inside `AntiCheatEngine`.
- **Data Ownership:** Circular window of recent angle deltas, raw input intervals, and recoil kick records.
- **Security Responsibility:** Behavioral identification of cheats operating purely via mouse movement or hardware input.
- **Platform Dependencies:** Universal mathematics (spherical angular geometry).
- **Error Handling:** Non-finite (NaN / Inf) input sanitization; boundary normalization (-180..180 deg).
- **Test Coverage:** `test_kinematics.cpp`, `test_audit_v2_reengineering.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/kinematics/phantom_monitor.hpp` & `src/kinematics/phantom_monitor.cpp`
- **Purpose:** Decoy-entity tripwire system deploying invisible, non-collidable, silent virtual targets to catch ESP and aimbot locks.
- **Public Interfaces:** `PhantomMonitor`, `AddPhantom`, `UpdatePhantom`, `Clear`, `GenerateAround`, `PushView`, `SetDecoyMode`.
- **Internal Dependencies:** `types.hpp`.
- **Thread Ownership:** Internal `std::mutex`.
- **Data Ownership:** Registered virtual entities.
- **Security Responsibility:** Irrefutable behavioral detection of memory-reading wallhacks and aimbots targeting invisible entities.
- **Platform Dependencies:** Universal 3D vector geometry.
- **Error Handling:** Finite float checks; angular tolerance clamping.
- **Test Coverage:** `test_kinematics.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

---

## 4. Cryptography & Network Subsystem (`src/network/`, `include/noescape/network/`)

### `include/noescape/network/ed25519.hpp` & `src/network/ed25519.cpp`
- **Purpose:** Zero-dependency, portable RFC 8032 Pure Ed25519 asymmetric signature implementation (twisted Edwards field arithmetic & SHA-512).
- **Public Interfaces:** `ed25519::GenerateKeypair`, `ed25519::Sign`, `ed25519::Verify`.
- **Internal Dependencies:** `<cstdint>`, `<cstring>`, `<array>`.
- **Security Responsibility:** Critical asymmetric verification ensuring untrusted clients possessing only the public key cannot forge signatures.
- **Platform Dependencies:** Universal (zero platform or library dependencies).
- **Error Handling:** Strict signature verification; returns false on invalid points or signature mismatch.
- **Test Coverage:** `test_crypto.cpp` (RFC 8032 test vectors 1, 2, 3 and negative forgery tests).
- **Integration Status:** 100% Integrated.

### `include/noescape/network/crypto_util.hpp` & `src/network/crypto_util.cpp`
- **Purpose:** Core cryptographic utilities: FIPS 180-4 SHA-256, HMAC-SHA256, HKDF (RFC 5869), ChaCha20-Poly1305 AEAD (RFC 8439), Ed25519 wrapper, and HWID fingerprinting.
- **Public Interfaces:** `CryptoUtil::Sha256`, `HmacSha256`, `DeriveKeyHkdf`, `AeadChaCha20Poly1305Encrypt`, `AeadChaCha20Poly1305Decrypt`, `SignAsymmetric`, `VerifyAsymmetric`, `GetMachineHWID`.
- **Internal Dependencies:** `ed25519.hpp`, OpenSSL EVP (when available).
- **Security Responsibility:** Data integrity, communication encryption, and device identity.
- **Platform Dependencies:** Hardware-accelerated OpenSSL on Linux/POSIX; standard portable fallback.
- **Error Handling:** Constant-time comparison to prevent side-channel timing attacks.
- **Test Coverage:** `test_crypto.cpp`, `test_blackbox.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/network/panel_client.hpp` & `src/network/panel_client.cpp`
- **Purpose:** Secure HTTPS client communicating with the central anti-cheat telemetry and ban backend.
- **Public Interfaces:** `PanelClient`, `SendHeartbeat`, `ReportViolation`, `CheckBanStatus`, `SetPinnedKey`.
- **Internal Dependencies:** `crypto_util.hpp`, OpenSSL / WinHTTP.
- **Thread Ownership:** Asynchronous background worker.
- **Data Ownership:** Pinned SPKI public key hash, session tokens.
- **Security Responsibility:** Prevents MITM attacks via strict TLS public-key pinning.
- **Platform Dependencies:** OpenSSL on POSIX; WinHTTP on Windows.
- **Error Handling:** Distinguishes network unavailability from security anomalies.
- **Test Coverage:** `test_engine.cpp`, `test_audit_remediation.cpp`.
- **Integration Status:** 100% Integrated.

---

## 5. Overlay & Rendering Subsystem (`src/overlay/`, `include/noescape/overlay/`)

### `include/noescape/overlay/overlay_detector.hpp` & `src/overlay/overlay_detector.cpp`
- **Purpose:** Detection of external ESP overlays (topmost, transparent, layered windows) and DirectX/Vulkan/OpenGL swapchain vtable hooks.
- **Public Interfaces:** `OverlayDetector`, `DetectSuspiciousWindows`, `InspectRenderingPointer`, `RegisterSwapchainVTable`, `AuditSwapchainHooks`.
- **Internal Dependencies:** `types.hpp`, `memory_scanner.hpp`.
- **Security Responsibility:** Detects Discord/Steam overlay hijacks, ImGui external ESPs, and rendering detours.
- **Platform Dependencies:** Win32 `EnumWindows` & Linux dynamic X11 / `/proc` inspection.
- **Error Handling:** `ProcessTrustState` verification: rejects whitelisting when PID is unverified or spoofed.
- **Test Coverage:** `test_overlay.cpp`, `test_regressions.cpp`, `test_audit_v2_reengineering.cpp`.
- **Integration Status:** 100% Integrated.

---

## 6. Forensics & Hardware Subsystem (`src/forensics/`, `include/noescape/forensics/`)

### `include/noescape/forensics/process_scanner.hpp` & `src/forensics/process_scanner.cpp`
- **Purpose:** Enumeration of hostile processes, debugger tools, external open handles targeting the game, and suspicious executable modules.
- **Public Interfaces:** `ProcessScanner`, `ScanHostileProcesses`, `AuditProcessHandles`.
- **Security Responsibility:** Identifies Cheat Engine, x64dbg, Process Hacker, and unauthorized debuggers.
- **Platform Dependencies:** Linux `/proc` & Win32 Toolhelp32 / NtQuerySystemInformation.
- **Test Coverage:** `test_forensics.cpp`, `test_regressions.cpp`.
- **Integration Status:** 100% Integrated.

### `include/noescape/forensics/dma_detector.hpp` & `src/forensics/dma_detector.cpp`
- **Purpose:** Ring-3 hardware DMA (Direct Memory Access) threat profiling: memory bus latency jitter, suspicious PCIe IDs, serial KMBox controllers, and IOMMU activation state.
- **Public Interfaces:** `DmaDetector`, `ProfileMemoryBusJitter`, `ScanHardwareDevices`, `CheckIommuStatus`, `EvaluateHardwareConfidence`.
- **Security Responsibility:** Detection of physical DMA leech cards (PCILeech, Squirrel, Enigma) and hardware input spoofs.
- **Platform Dependencies:** Linux `/sys/kernel/iommu_groups` & Win32 registry/WMI.
- **Test Coverage:** `test_dma.cpp`.
- **Integration Status:** 100% Integrated.

---

## 7. Server-Authoritative Integration (`src/server/`, `include/noescape/server/`)

### `include/noescape/server/server_integration.hpp` & `src/server/server_integration.cpp`
- **Purpose:** Authoritative server-side ESP occlusion culling (3D AABB raycast slab method), acoustic cue routing, and player movement validation.
- **Public Interfaces:** `ServerEspFilter`, `AddOccluder`, `EvaluateEntityReplication`, `ValidatePlayerMovement`, `ValidateCombatEngagement`.
- **Internal Dependencies:** `types.hpp`.
- **Security Responsibility:** The ultimate defense against client-side wallhacks: occluded target coordinates are never replicated to the client.
- **Platform Dependencies:** Universal (Headless game server compatible).
- **Test Coverage:** `test_server_and_correlation.cpp`, `test_audit_v2_reengineering.cpp`.
- **Integration Status:** 100% Integrated.

---

## 8. Public SDK Interface (`include/noescape_sdk.h`, `src/sdk/`)

### `include/noescape_sdk.h` & `src/sdk/noescape_sdk.cpp`
- **Purpose:** Stable, versioned C and modern C++ API for host game engines (Unreal, Unity, Godot, custom engines).
- **Public Interfaces:** `NoEscape_Init`, `NoEscape_Shutdown`, `NoEscape_Start`, `NoEscape_Stop`, `NoEscape_Tick`, `NoEscape_GetProfileConfig`, `NoEscape_PushRawInput`, `NoEscape_RecordTargetAcquire`, `NoEscape_PushWeaponFire`, `NoEscape_PushRecoilEvent`, `NoEscape_AddPhantom`, `noescape::sdk::Client`.
- **Security Responsibility:** Safe, non-crashing integration boundary with ABI versioning (`struct_size`).
- **Platform Dependencies:** Dynamic/static library linking across Windows and Linux.
- **Test Coverage:** `test_sdk.cpp`, `test_audit_v2_reengineering.cpp`.
- **Integration Status:** 100% Integrated.
