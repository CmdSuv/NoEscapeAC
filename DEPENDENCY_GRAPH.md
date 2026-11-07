# NoEscapeAC Complete Dependency Graph & Coupling Analysis

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architects:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Standard:** Modern C++20  
**Scope:** Subsystem Dependencies, Circularity Auditing, Coupling Elimination, and Dead Code Verification  

---

## 1. Subsystem Level Dependency Graph

```
                                +--------------------+
                                |    noescape_sdk    |
                                +---------+----------+
                                          |
                                          v
                                +--------------------+
                                |  AntiCheatEngine   |
                                +----+---+---+---+---+
                                     |   |   |   |
            +------------------------+   |   |   +-----------------------+
            |                            |   |                           |
            v                            |   |                           v
   +-----------------+                   |   |                  +-----------------+
   |  MemoryScanner  |                   |   |                  |   AimAnalyzer   |
   +--------+--------+                   |   |                  +--------+--------+
            |                            |   |                           |
            +------------+               |   |                           |
            v            v               |   |                           |
     +-----------+ +-----------+         |   |                           |
     |  Unhooker | |  Canary   |         |   |                           |
     +-----+-----+ +-----+-----+         |   |                           |
           |             |               |   |                           |
           +-------+-----+               |   |                           |
                   |                     |   |                           |
                   v                     v   v                           v
          +-----------------+    +-------------------+          +-----------------+
          | PatternScanner  |    | OverlayDetector   |          | PhantomMonitor  |
          +--------+--------+    +---------+---------+          +--------+--------+
                   |                       |                             |
                   +-----------+           |                             |
                               v           v                             v
                        +-------------------------------------------------------+
                        |                   Core Types & Primitives            |
                        |             (DetectionEvent, Severity, Categories)    |
                        +---------------------------+---------------------------+
                                                    |
                                                    v
                                      +---------------------------+
                                      |    EvidenceCorrelator     |
                                      +-------------+-------------+
                                                    |
                                                    v
                                      +---------------------------+
                                      |     CryptoUtil & Ed25519  |
                                      +---------------------------+
```

---

## 2. Component Dependency Table

| Component | Direct Includes / Dependencies | Calling Modules | Called Modules | Potential Circularity Risk | Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`types.hpp`** | None (Leaf) | All components | None | None | Immutable enum and POD definition; strictly leaf-level. |
| **`crypto_util.hpp`** | `ed25519.hpp`, `obfuscation.hpp`, OpenSSL EVP | `engine.cpp`, `blackbox.cpp`, `canary_monitor.cpp`, `panel_client.cpp` | `ed25519.cpp`, OS CSPRNG | Low | Pure cryptographic primitives; no engine references. |
| **`ed25519.hpp`** | Standard C++ headers only | `crypto_util.cpp` | Twisted Edwards Field Arithmetic | None | Completely self-contained RFC 8032 implementation. |
| **`obfuscation.hpp`** | Standard C++ headers only | `crypto_util.cpp`, `unhooker.cpp`, `engine.cpp`, `blackbox.cpp` | None | None | Header-only compile-time template metaprogramming. |
| **`evidence_correlator.hpp`** | `types.hpp`, `crypto_util.hpp` | `engine.cpp`, `test_server_and_correlation.cpp`, `test_audit_v2_reengineering.cpp` | None | None | Evaluator takes `DetectionEvent` by value/const reference; decoupled from detection sensors. |
| **`aim_analyzer.hpp`** | `types.hpp` | `engine.cpp`, `test_kinematics.cpp` | None | None | Angular geometry only; decoupled from game engine coordinates. |
| **`phantom_monitor.hpp`** | `types.hpp` | `engine.cpp`, `test_kinematics.cpp`, `test_regressions.cpp` | None | None | Mathematical 3D raycast and dot product calculations. |
| **`memory_scanner.hpp`** | `types.hpp`, `pattern_scanner.hpp`, `signature_database.hpp`, `crypto_util.hpp` | `engine.cpp`, `test_memory.cpp` | OS Virtual Memory API | None | Autonomous memory auditor. |
| **`unhooker.hpp`** | `types.hpp`, `obfuscation.hpp` | `memory_scanner.cpp`, `engine.cpp`, `test_memory.cpp` | OS Virtual Memory API | None | Direct ELF/PE disk section reader. |
| **`canary_monitor.hpp`** | `types.hpp`, `crypto_util.hpp` | `engine.cpp`, `test_memory.cpp` | OS Virtual Memory API | None | Autonomous memory canary pool. |
| **`pattern_scanner.hpp`** | Standard C++ headers, AVX2/SSE2 | `memory_scanner.cpp`, `signature_database.cpp` | SIMD Intrinsics | None | Pure vector search algorithms. |
| **`overlay_detector.hpp`** | `types.hpp`, `memory_scanner.hpp` | `engine.cpp`, `test_overlay.cpp` | OS Windowing API | None | Desktop window auditor. |
| **`process_scanner.hpp`** | `types.hpp` | `engine.cpp`, `test_forensics.cpp` | OS Process Subsystem | None | Read-only process table auditor. |
| **`dma_detector.hpp`** | `types.hpp` | `engine.cpp`, `test_dma.cpp` | OS Bus & IOMMU Sysfs | None | Hardware bus and IOMMU inspector. |
| **`server_integration.hpp`** | `types.hpp` | Server executable / test suite | None | None | Server-authoritative raycast culler; zero client engine dependencies. |
| **`engine.hpp`** | All subsystems, `types.hpp` | `noescape_sdk.cpp`, CLI application, test suites | Subsystems | Medium | Aggregates all subsystems via forward declarations and composition; no circular calls back to engine. |
| **`noescape_sdk.h`** | Standard C headers | Game Engine Host | `AntiCheatEngine` | Low | C ABI bridge with opaque handles and static wrappers. |

---

## 3. Circular Dependency Audit & Architectural Remediation

During the v1.3 architecture review, three major coupling risks were identified and resolved:

1. **Engine <-> EvidenceCorrelator Circularity**:
   - *Previous Risk:* Correlator attempted to query `engine->GetThreatScore()` directly, creating a bidirectional cyclic dependency.
   - *Resolution:* `EvidenceCorrelator::Evaluate` was made a pure transformer function taking `(raw_event, current_total_score, ban_threshold)` as explicit arguments and returning a `CorrelationDecision`. The correlator has zero compile-time or runtime knowledge of `AntiCheatEngine`.

2. **OverlayDetector <-> ProcessScanner Redundant Scans**:
   - *Previous Risk:* `OverlayDetector` performed independent `/proc` walks on Linux that duplicated `ProcessScanner::ScanHostileProcesses`.
   - *Resolution:* `OverlayDetector` was re-architected to inspect only window owner PIDs via `verifyOverlayProcessAuthentic`, delegating global process enumeration strictly to `ProcessScanner`.

3. **MemoryScanner <-> Unhooker Boundary**:
   - *Previous Risk:* `MemoryScanner` attempted inline hook patching while `Unhooker` performed independent virtual memory mapping scans.
   - *Resolution:* Responsibilities were cleanly divided: `MemoryScanner` audits memory page protections, unbacked execution, and thread IPs; `Unhooker` is the sole authoritative component that parses on-disk reference binaries and restores altered code bytes.

---

## 4. Dead Code & Unreachable Functionality Audit

1. **AimAnalyzer Disconnected Functions**:
   - *Previous Defect:* `RecordRawInputSample`, `RecordCrosshairTargetAcquire`, `RecordWeaponFire`, and `RecordRecoilCompensation` were declared and defined in `aim_analyzer.cpp`, but had no call sites in `AntiCheatEngine` or `noescape_sdk.h`.
   - *Remediation:* Integrated entry points in `AntiCheatEngine`:
     - `AntiCheatEngine::PushRawInput(interval_us, dx, dy)`
     - `AntiCheatEngine::RecordTargetAcquire(timestamp_ms)`
     - `AntiCheatEngine::PushWeaponFire(timestamp_ms)`
     - `AntiCheatEngine::PushRecoilEvent(kick_p, kick_y, input_p, input_y)`
     Exposed via C API (`NoEscape_PushRawInput`, etc.) and C++ SDK (`noescape::sdk::Client`). Fully covered by unit tests in `test_audit_v2_reengineering.cpp`.

2. **Unused Build Artefacts & Mock Handlers**:
   - *Audit Result:* Verified that all mock hooks (`AddMockWindow`, `ClearMockWindows`) are encapsulated in testing interfaces and stripped or dormant during production execution.
