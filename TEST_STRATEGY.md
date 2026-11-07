# NoEscapeAC — Comprehensive Test Strategy & Verification Harness

**Version:** 7.0 / Release 1.3  
**Total Test Count:** 133 Unit & Regression Tests (100% Passing)  
**Preload Verification:** 6/6 Integration Tests (100% Passing)  
**Attribution:** Omar Yiğitcan Mengü (`@CmdSuv`) & `OnlyCosmos` (`@OnlyCosmos`)

---

## 1. Test Suite Architecture

The test harness operates via a lightweight, deterministic C++20 test framework (`tests/test_framework.hpp`). It compiles into a standalone binary `noescape_tests` without requiring external heavyweight test dependencies like GoogleTest or Catch2.

```
+-----------------------------------------------------------------------------------+
|                            NOESCAPE TEST SUITE (133 TESTS)                        |
+-----------------------------------------------------------------------------------+
|  [Core Cryptography & Obfuscation] (5 Tests)                                      |
|   - Crypto.Sha256StandardVectors, Crypto.HmacSha256StandardVectors                |
|   - Crypto.MachineHwidGeneration, Obfuscation.CompileTimeFnv1a/XorStrings         |
+-----------------------------------------------------------------------------------+
|  [SIMD & Pattern Scanner] (7 Tests)                                               |
|   - ExactMatch, WildcardMatch, BoundaryCases, MultipleOccurrences                 |
|   - LargeSimdBuffer, BatchScanning, AllWildcardsAndLeadingWildcards               |
+-----------------------------------------------------------------------------------+
|  [Behavioral Kinematics] (7 Tests)                                                |
|   - NormalHumanMovement, InstantSnapAimbot, RoboticPerfectLinearity               |
|   - ArtificialSmoothingConstantVelocity, NonFiniteAndMalformedInputs              |
|   - ComputeCurrentMetricsFull, SubMillisecondMousePolling                         |
+-----------------------------------------------------------------------------------+
|  [Memory, Unhooking & Canaries] (3 Tests)                                         |
|   - Memory.QueryMemoryRegions, Memory.UnhookerInspection, Memory.UnhookerRestoration|
+-----------------------------------------------------------------------------------+
|  [Forensics, DMA & Timing] (6 Tests)                                              |
|   - ProcessEnumeration, ProcessBlacklistAudit, ArtifactAnalyzer                   |
|   - CalibrationAndJitterProfiling, HardwareDeviceScan, IommuStatusClassification  |
|   - Timing.CalibrationAndCheck, ThreadPool.ExecutionAndFuture                    |
+-----------------------------------------------------------------------------------+
|  [Engine, Ban UI & Overlays] (5 Tests)                                            |
|   - InitializationAndThreatScoring, FatalBanEnforcement, BanScreenInvocation      |
|   - ViewportGeometry, TopmostTransparentWindow                                    |
+-----------------------------------------------------------------------------------+
|  [Regression Suite] (94 Tests)                                                    |
|   - Dead Watchdog Detection & No False Self-Reports                               |
|   - Soft-Dirty Reset & Non-Dumpable Process Security                              |
|   - Server-Side Attestation HMAC Verification & Bounds Checking                   |
|   - AVX2/SSE4.2 Runtime Dispatch & Grouped SIMD Prefix Bucketing                 |
|   - Clean Process Zero Confirmed Hooks (No False Positives)                       |
|   - Engine Restartability (Stop() followed by Start())                            |
|   - CET endbr64 Offset Hook & Relocation Masking                                  |
|   - ObfuscatedValue<T> Rolling Key Integrity                                      |
|   - Overlay PID Spoofing Caught by Window Hierarchy Verification                  |
|   - Ring-0 BYOVD / LKM Rootkit Integrity Clean Baseline                           |
+-----------------------------------------------------------------------------------+
|  [Server Integration & Correlation Layer] (6 Tests)                              |
|   - Correlation.WeakSingleHeuristicsClassifiedCorrectly                           |
|   - Correlation.MultiSourceCorroborationAndBanEligibility                         |
|   - Correlation.ServerVerificationPromotion                                       |
|   - ServerIntegration.RayAabbIntersectionSlabMethod                               |
|   - ServerIntegration.AuthoritativeEspCullingAndReplication                       |
|   - ServerIntegration.MovementAndEngagementValidation                            |
+-----------------------------------------------------------------------------------+
```

---

## 2. Mock Injection Harnesses

To safely test the anti-cheat without deploying real malware or compromising system integrity, `tests/` features simulated attack harnesses:
1. **Simulated Shellcode Injections:** Dynamic allocations via `mmap(PROT_READ|PROT_WRITE|PROT_EXEC)` or `VirtualAlloc` representing anonymous unbacked code payloads. Verified by `Memory.QueryMemoryRegions` and `Regression.EngineAuditCycleWorksAfterStartAndStop`.
2. **Prologue Detour Patching:** In-memory patching of test function prologues using real x86_64 JMP detours (`E9`, `FF 25`, and `endbr64 + JMP`). The unhooker must detect the detour, locate the clean bytes, and restore the prologue.
3. **Hardware Breakpoint Injection:** Mock threads configured with debug registers to verify `AntiDebug` hardware detection.
4. **Adversarial Network Testing:** In-memory reference server tests cryptographic challenges, replay nonces, forged HMAC tokens, and server session validation.

---

## 3. Scenario B (Auto-Init / LD_PRELOAD) Automated Suite

The shell script `tools/verify_preload.sh` exercises the shared library integration:
1. **Clean Baseline Execution:** Attaches `libnoescape.so` to `dummy_game` via `LD_PRELOAD`. Verifies that the game renders frames cleanly, initializes the self-integrity baseline, and exits with code 0.
2. **Opt-Out Control:** Verifies that `NOESCAPE_DISABLE_AUTO_INIT=1` and `NOESCAPE_AUTO_START=0` are respected when running in test mode.
3. **Loader Lock Deadlock Prevention:** Verifies rapid invocation (`true` binary under `LD_PRELOAD`) completes in under 5 ms without loader lock deadlocks.
4. **Production Hardening Tamper Resistance:** Verifies that in production mode (`NOESCAPE_TEST_MODE` unset), opt-out environment variables are strictly ignored.

---

## 4. Sanitizer Cleanliness Verification

The codebase is engineered to compile and run cleanly with zero reports under:
- **AddressSanitizer (ASan):** Detects buffer overflows, out-of-bounds reads in SIMD scanning, and use-after-free bugs.
- **UndefinedBehaviorSanitizer (UBSan):** Detects integer overflows, unaligned memory accesses, and null pointer dereferences.
- **ThreadSanitizer (TSan):** Verifies thread safety across the `ThreadPool`, mutual watchdog supervision, and memory scan mutex synchronization.
