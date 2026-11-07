# NoEscapeAC Complete Architecture Map & System Blueprint

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architects:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Specification Level:** v2.0 Production Blueprint  
**Design Philosophy:** Strict Ring-3 Client Hardening & Authoritative Server Integration  

---

## 1. High-Level Architectural Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                      GAME CLIENT (Ring-3 User Mode)                                |
|                                                                                                    |
|   +-----------------------+     +------------------------+     +-------------------------------+   |
|   |   Host Game Engine    |     | Kinematics / Input     |     |      Memory & Integrity       |   |
|   |  (Unreal/Unity/Custom)|     | - Mouse Delta Feeder   |     | - Unbacked Page Scanner       |   |
|   |  - Transforms / View  |     | - Raw HID Intervals    |     | - Inline Hook Unhooker        |   |
|   |  - Weapon Actions     |     | - Triggerbot Timers    |     | - CET endbr64 Offset Check    |   |
|   |  - Target Acquisition |     | - Recoil Counters      |     | - Canary Tripwires            |   |
|   +-----------+-----------+     +-----------+------------+     +---------------+---------------+   |
|               |                             |                                  |                   |
|               v                             v                                  v                   |
|   +--------------------------------------------------------------------------------------------+   |
|   |                                NoEscape Core Engine Pipeline                               |   |
|   |                                                                                            |   |
|   |   +-------------------+    +--------------------+    +---------------------------------+   |   |
|   |   |  Forensic Audits  |    |  Overlay Detector  |    |     DMA & Hardware Profiler     |   |   |
|   |   | - Process Scans   |    | - Layered Windows  |    | - PCIe Leech Signatures         |   |   |
|   |   | - Open Handles    |    | - Swapchain Hooks  |    | - Bus Latency Jitter Profile    |   |   |
|   |   | - Volatile Modules|    | - PID Image Trust  |    | - IOMMU / VT-d / AMD-Vi State   |   |   |
|   |   +---------+---------+    +---------+----------+    +----------------+----------------+   |   |
|   |             |                        |                                |                    |   |
|   |             +------------------------+-------+------------------------+                    |   |
|   |                                              |                                             |   |
|   |                                              v                                             |   |
|   |                             +---------------------------------+                            |   |
|   |                             |    DetectionEvent Generation    |                            |   |
|   |                             |    (Timestamp, Type, Severity)  |                            |   |
|   |                             +----------------+----------------+                            |   |
|   |                                              |                                             |   |
|   |                                              v                                             |   |
|   |                             +---------------------------------+                            |   |
|   |                             |   Evidence Correlator Layer     |                            |   |
|   |                             |   - Temporal Sliding Window     |                            |   |
|   |                             |   - Session & Match Isolation   |                            |   |
|   |                             |   - Root-Cause Deduplication    |                            |   |
|   |                             |   - Bounded Storage Cap (512)   |                            |   |
|   |                             |   - Independent Category Gating |                            |   |
|   |                             +----------------+----------------+                            |   |
|   |                                              |                                             |   |
|   |                                              v                                             |   |
|   |                             +---------------------------------+                            |   |
|   |                             |     Enforcement Gatekeeper      |                            |   |
|   |                             |   - Multi-Signal Verification   |                            |   |
|   |                             |   - Safe Profile Enforcement    |                            |   |
|   |                             |   - RFC 8439 Blackbox Dumper    |                            |   |
|   |                             +----------------+----------------+                            |   |
|   +----------------------------------------------|---------------------------------------------+   |
|                                                  |                                                 |
|                                                  | HTTPS (TLS Pinned)                              |
|                                                  v                                                 |
+----------------------------------------------------------------------------------------------------+
|                                    CENTRAL / MATCH BACKEND                                         |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   |                                 Server-Authoritative Layer                                 |   |
|   |                                                                                            |   |
|   |   +-----------------------------------+            +-----------------------------------+   |   |
|   |   |   Authoritative ESP Culler        |            |   Authoritative Movement Engine   |   |   |
|   |   |   (ServerEspFilter)               |            |   - Max Speed / Delta T Validator |   |   |
|   |   |   - 3D AABB Raycast Slab Method   |            |   - Teleport / Speedhack Denier   |   |   |
|   |   |   - Solid Wall Occlusion Culling  |            |   - Combat Engagement Range Guard |   |   |
|   |   |   - Acoustic Cue Attenuation Only |            +-----------------------------------+   |   |
|   |   +-----------------------------------+                                                    |   |
|   |                                                                                            |   |
|   |   +------------------------------------------------------------------------------------+   |   |
|   |   |                         Server Attestation & Cryptography                          |   |   |
|   |   |                         - RFC 8032 Pure Ed25519 Verification                       |   |   |
|   |   |                         - HWID Trust & Ban Enforcement                             |   |   |
|   |   |                         - Match Restriction & Session Rejection                    |   |   |
|   |   +------------------------------------------------------------------------------------+   |   |
|   +--------------------------------------------------------------------------------------------+   |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Sensor & Ingestion Subsystems

1. **Memory Integrity Layer (`MemoryScanner`, `Unhooker`, `CanaryMonitor`)**:
   - Inspects virtual address space mappings via `/proc/self/maps` (Linux) and `VirtualQueryEx` (Windows).
   - Identifies non-file-backed executable memory pages (`RWX` or `RX` segments without backing inode/file).
   - Audits system DLL text sections (`ntdll.dll`, `kernel32.dll`, `libc.so.6`) against unmodified disk bytes to detect inline detours, trampolines, and CET `endbr64` offset hooks.
   - Restores modified memory pages directly via `/proc/self/mem` or `VirtualProtect` while preserving process non-dumpable status.
   - Deploys randomized, encrypted virtual memory canaries to detect memory alteration.

2. **Kinematic & Input Layer (`AimAnalyzer`, `PhantomMonitor`)**:
   - Analyzes high-frequency view angle updates for inhuman delta jumps (instant snapping).
   - Computes orthogonal line fit variance across moving windows to detect robotic linear smoothing.
   - Inspects raw HID mouse polling intervals (microseconds) to detect quantized synthetic macros.
   - Computes target acquisition-to-weapon fire latencies to catch sub-45ms triggerbot automation.
   - Compares weapon recoil kick against player counter-movement deltas to flag automated recoil compensation scripts.
   - Spawns invisible, silent, non-collidable decoy entities behind solid walls; flags sustained locks as `PHANTOM_ENTITY_TARGETED`.

3. **Overlay & Rendering Layer (`OverlayDetector`)**:
   - Scans desktop top-level windows for transparent, topmost, layered canvases matching the game viewport.
   - Performs strict `ProcessTrustState` inspection: verifies owning PID image on disk, checks `/proc/<pid>/maps` for injected payloads, and denies allowlist exemptions to unverified or elevated processes.
   - Intercepts swapchain presentation pointers (`Present`, `SwapBuffers`) and checks vtable backing modules to defeat internal rendering hooks.

4. **Hardware & Forensics Layer (`ProcessScanner`, `DmaDetector`)**:
   - Audits running host processes and open process handles targeting the game.
   - Profiles memory bus latency jitter to detect active DMA PCIe devices accessing host physical memory.
   - Inspects OS IOMMU virtualization state (VT-d / AMD-Vi) to classify hardware risk.

---

## 3. The Evidence Pipeline: Sensor to Verdict

```
[ Sensor Detection ]
         │
         ▼
[ DetectionEvent ] ────► Timestamp, Component, Threat Score, Category, RootCauseId
         │
         ▼
[ Evidence Correlator ]
         │
         ├──► 1. Temporal Pruning (Events older than sliding window [e.g. 60s] expired)
         ├──► 2. Root-Cause Deduplication (Multiple reports from same memory span merged)
         ├──► 3. Category Counting (Independent detection categories must be >= 2)
         └──► 4. Confidence Scaling (OBSERVED -> SUSPICIOUS -> CORROBORATED -> SERVER_VERIFIED)
         │
         ▼
[ Correlation Decision ]
         │
         ├── Weak Single Heuristic? ──► Scored as observation, ban disabled
         ├── Corroborated Multi-Source? ──► Eligible for enforcement
         └── Server-Verified Attestation? ──► Direct high-confidence verdict
         │
         ▼
[ Engine Gatekeeper ]
         │
         ├── Production Profile? ──► SERVER_SESSION_REJECT / SHADOW mode
         ├── Testing Profile? ──► Immediate ban callback invocation
         └── Blackbox Dump ──► RFC 8439 ChaCha20-Poly1305 AEAD crash record written
```

---

## 4. Mitigation Boundaries: Ring-3 Client vs Server

| Threat Class | Client-Side Ring-3 Capability | Authoritative Server Defense | Ultimate Resolution |
| :--- | :--- | :--- | :--- |
| **External Memory Reading (ESP)** | Weak (External processes can read memory via driver or DMA) | **ServerEspFilter**: Server raycasts visibility via 3D AABB slabs. Occluded entities are culled from replication. | **Eliminated at Server**: Client never receives coordinates of hidden players. |
| **Aimbot / Micro-Snaps** | Detects angular snaps, synthetic linearity, zero-jitter HID polling. | Validates view angle consistency and server-side hit registration. | **Dual Layer**: Client flags anomaly; server rejects invalid trajectory hits. |
| **Silent Aim / Magic Bullet** | Detects memory tampering in camera matrix and recoil offsets. | Verifies muzzle trace raycast against player view angles and weapon physics. | **Server Authoritative**: Server drops hits that originate outside client orientation. |
| **Speedhack / Tick Manipulation** | Monitors hardware TSC vs OS monotonic clock divergence. | Validates distance traveled per unit time: $v = \frac{\Delta d}{\Delta t} \le v_{max}$. | **Server Authoritative**: Server snaps position back and rejects illegal velocity. |
| **DLL Injection / Shellcode** | Unbacked memory scanner, thread provenance audit, unhooker restoration. | Periodic cryptographic code attestation. | **Client Hardening**: Injected code is identified, unhooked, and reported. |
| **Hardware DMA Leech Cards** | Bus latency jitter profiling, IOMMU status audit, decoy phantoms. | Complete spatial occlusion culling (ESP culling). | **Architectural Mitigation**: DMA cards cannot read data the server never networks. |
