# NoEscapeAC — Security Architecture Specification

**Version:** 7.0 / Release 1.3  
**Status:** Production-Ready Defensive Specification  
**Architecture Paradigm:** Strictly User-Mode (Ring-3) Unified Defensive Framework  
**Primary Authors:** Omar Yiğitcan Mengü (`@CmdSuv`) & `OnlyCosmos` (`@OnlyCosmos`)

---

## 1. Architectural Philosophy & Constraints

NoEscapeAC operates entirely within Ring-3 (user space). Modern competitive esports and client integrity systems increasingly operate under stringent OS platform and anti-tamper constraints:
1. **Zero Kernel Drivers:** No `.sys` or `.ko` drivers, no kernel callbacks (`ObRegisterCallbacks`), no kernel hooks, and no BYOVD (Bring Your Own Vulnerable Driver) exploitation.
2. **Crash Resilience:** Anti-cheat failures must never cause kernel panic (BSOD / Kernel Oops). Faults remain confined to the game process boundary.
3. **Cross-Platform Parity:** Core detection mechanics run natively on both Windows x64 and Linux x86_64 without relying on Windows-only driver signing or proprietary hypervisors.
4. **Defense-in-Depth:** Because Ring-3 code shares the same privilege level as sophisticated user-mode cheat software, security is achieved through **multi-layered validation**, **reciprocal supervision**, **cryptographic code attestation**, **authoritative server cooperation**, and **hardware-level physical measurement**.

---

## 2. Layered Subsystem Taxonomy

```
+-----------------------------------------------------------------------------------+
|                           AUTHORITATIVE GAME SERVER                               |
|   - ServerEspFilter (Occlusion Culling)        - Ephemeral Attestation Challenges |
|   - Server-Authoritative Kinematics           - Verdict & Session Validation      |
+-----------------------------------------------------------------------------------+
                                        |  TLS 1.2+ / SPKI Pinning / HMAC-SHA256
                                        v
+-----------------------------------------------------------------------------------+
|                        NOESCAPE ANTI-CHEAT CORE (RING-3)                          |
+-----------------------------------------------------------------------------------+
|  [Evidence Correlator Layer]                                                      |
|   - Multi-Signal Scoring & Deduplication      - Independent Family Validation     |
|   - Weak Heuristic Dampening                  - Dynamic Ban Eligibility Engine    |
+-----------------------------------------------------------------------------------+
|  [Active Auditing Subsystems]                                                     |
|   * Memory & Code Integrity:                                                      |
|       - Unhooker (Clean image comparison, relocation masking, CET endbr64)        |
|       - MemoryScanner (Chunk-budgeted VMA walk, unbacked code segment scan)       |
|       - PatternScanner (Grouped SIMD AVX2/SSE4.2 runtime-dispatched signatures)   |
|       - CanaryMonitor (Honeypot value alteration & post-reset verification)       |
|   * Process Forensics & Environment:                                              |
|       - ProcessAnalyzer (Direct syscall/proc table audit, handle enumeration)     |
|       - ArtifactAnalyzer (Memory-mapped cheat modules, debugger leftovers)        |
|       - AntiDebug (Hardware debug registers DR0-DR3, tracer status, timing skew)  |
|   * Hardware & Out-of-Band Integrity:                                             |
|       - DmaDetector (PCIe bus contention jitter profiling, FPGA LeechCore audit)  |
|       - IommuStatus (VT-d / AMD-Vi / Windows Kernel DMA Protection evaluation)    |
|   * Behavioral Kinematics:                                                        |
|       - AimAnalyzer (Kinematic curvature, jerk variance, sub-ms polling cadence)  |
|       - PhantomMonitor (Invisible decoy entity telemetry & crosshair locking)     |
|   * Presentation Integrity:                                                       |
|       - OverlayDetector (Window hierarchy verification, top-level transparent Z)  |
+-----------------------------------------------------------------------------------+
|  [Self-Protection & Engine Watchdog]                                             |
|   - Reciprocal Watchdog Thread Supervision (Thread Heartbeat Monitoring)          |
|   - Non-Dumpable Process Security (PR_SET_DUMPABLE / SetProcessMitigationPolicy)   |
|   - ObfuscatedValue<T> (Dynamic XOR keys & compile-time string encryption)        |
|   - AES-256-GCM Diagnostic Blackbox Flight Recorder                               |
+-----------------------------------------------------------------------------------+
```

---

## 3. Subsystem Breakdown & Internal Mechanics

### 3.1. Code Integrity & Relocation-Aware Unhooker
Attackers injecting user-mode cheats hook standard libraries (`ntdll.dll`, `kernel32.dll`, `libc.so`, `libpthread.so`) via:
- 5-byte JMP (`E9 xx xx xx xx`)
- 14-byte 64-bit absolute indirect jump (`FF 25 00 00 00 00 [addr]`)
- Intel CET `endbr64` offset hooks (`F3 0F 1E FA` followed by detour)
- Push-Ret sequences (`68/48 B8 [addr]; C3`)

**Defensive Solution:**
`Unhooker` resolves clean export targets, opens the on-disk clean binary image, parses PE/ELF relocations, masks relocated instruction operands to avoid false-positive mismatches, and inspects the in-memory export prologue. If a detour is identified:
- The hook destination is evaluated (e.g., target resides in an unbacked anonymous allocation).
- Memory protection is stripped using `VirtualProtect` (Windows) or `/proc/self/mem` direct writing (Linux) without leaving wide RWX windows.
- The original prologue bytes are atomicaly restored.

### 3.2. SIMD Pattern Scanner with Runtime AVX2 Dispatch
- Cheat signatures are compiled into grouped SIMD buckets based on initial byte fingerprints.
- Scanner detects CPU instruction capabilities at runtime via `__cpuidex` and `_xgetbv`.
- If AVX2 and OSXSAVE are enabled, the 256-bit vectorized path compares 32 bytes per instruction using `_mm256_cmpeq_epi8` and `_mm256_movemask_epi8`.
- If unsupported, it seamlessly falls back to 128-bit SSE4.2 without crashing on legacy CPUs.

### 3.3. Memory Scanner with Virtual Memory Area (VMA) Budgeting
To prevent frame hitching in competitive games:
- The memory scanner operates incrementally with a strict time and page budget per audit cycle.
- Multi-gigabyte reservations (such as GPU shadow buffers or ASan shadow mappings) are skipped.
- Executable segments are checked against physical file backing. Any `PROT_EXEC` (or `PAGE_EXECUTE_*`) region lacking a valid file mapping (`MEM_IMAGE` / valid `vma->vm_file`) is flagged as unbacked code injection.

### 3.4. Hardware & DMA Bus Contention Profiler
Out-of-band Direct Memory Access (DMA) cheat hardware (e.g., PCIe Screamer, Enigma, CaptainDMA) queries physical memory directly via PCIe TLP packets without host CPU software intervention.
- `DmaDetector` performs micro-benchmarks on memory bus latency using serialized cache-line read cycles (`_mm_clflush` + `_mm_lfence` + `rdtsc`).
- DMA polling creates memory bus arbitration contention, inducing statistically anomalous variance and jitter.
- The detector couples timing jitter with PCIe device tree interrogation (`/sys/bus/pci/devices` or Windows SetupAPI) and OS IOMMU status (VT-d, AMD-Vi, Kernel DMA Protection) to assign confidence levels.

### 3.5. Behavioral Kinematics & Phantom Decoys
Aimbots and triggerbots attempt to conceal artificial mouse input through smoothing algorithms.
- `AimAnalyzer` processes raw mouse deltas $(dx, dy)$ and timestamps, evaluating kinematics:
  - Curvature variance $\kappa(t)$
  - Angular acceleration $\alpha(t)$
  - Jerk $\frac{d\alpha}{dt}$
  - Instant snap detection (0-millisecond angle snapping between discrete frames)
  - Robotic linearity (sub-pixel straight lines without physiological tremor)
- `PhantomMonitor` instantiates server-coordinated invisible decoy targets positioned outside the player's natural line of sight. Legitimate players never track or fire at these entities; client-side ESP and aimbot locks targeting them trigger immediate corroboration.

---

## 4. Telemetry Pipeline & Anti-Tamper Safeguards

1. **Mutual Engine Watchdog:** The audit engine thread and an isolated watchdog thread monitor each other via monotonic atomic ticks. If an attacker terminates or suspends either thread (e.g., via `SuspendThread` or `SIGSTOP`), the survivor triggers an emergency enforcement heartbeat.
2. **Non-Dumpable Hardening:** At initialization, the engine enforces `prctl(PR_SET_DUMPABLE, 0)` (Linux) or `ProcessSignaturePolicy` mitigation (Windows). This prevents unprivileged external tools from reading `/proc/self/mem` or attaching debuggers.
3. **AES-256-GCM Flight Recorder:** Blackbox diagnostic dumps record recent engine telemetry into an encrypted crash dump using a rotating memory buffer, allowing forensic analysis while preventing memory-resident plaintext inspection.
4. **Cryptographic Attestation:** The server issues single-use nonces requiring the client to compute HMAC-SHA256 over pseudorandom segments of its executable memory.

---

## 5. Threat Boundary Matrix

| Attack Vector | Ring-3 Defensive Mechanism |
|---|---|
| DLL / SO Injection | Unbacked executable segment audit + module baseline tracking |
| Function Hooking | On-disk image comparison + prologue restoration |
| Memory Patching | Code text hashing + dynamic server memory attestation |
| Hardware Debuggers | DR0-DR3 register interrogation + `PTRACE_TRACEME` / `NtQueryInformationProcess` |
| DMA Cards | Bus latency jitter profiling + PCIe FPGA scan + IOMMU status |
| Software ESP / Wallhack | Server-side occlusion filtering (`ServerEspFilter`) + Phantom decoy entities |
| Aimbot / Triggerbot | Kinematic curvature, jerk variance, and mouse sample cadence analysis |
| External Memory Peeking | Process non-dumpable lockdown + handle auditing |
