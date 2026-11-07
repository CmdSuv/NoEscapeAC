# NoEscapeAC Evidence Model & Decision State Machine

**Project:** NoEscapeAC — Unified Ring-3 Anti-Cheat Architecture  
**Architects:** Omar Yiğitcan Mengü (`@CmdSuv`) & OnlyCosmos (`@OnlyCosmos`)  
**Standard:** Modern C++20  
**Scope:** Multi-Signal Evidence Fusion, Temporal Sliding Windows, Root-Cause Grouping, and Finite State Transitions  

---

## 1. Philosophical Grounding: Evidence vs Severity

A fundamental mistake in early anti-cheat designs was equating **Severity** with **Corroboration**:
- *Severity* is an assessment of the *potential impact* of a condition (e.g., an unbacked executable region has higher impact than an obscure window title).
- *Confidence* is an empirical measure of the *observational certainty and independence* of the evidence.

An event with `Severity::FATAL_BAN` is **not** automatically verified. A single heuristic observation, regardless of how alarming it appears, may stem from application instrumentation, developer profilers, anti-virus software, or operating system quirks.

NoEscapeAC v2.0 establishes a strict separation:
$$\text{Verdict Eligibility} = f(\text{Confidence Tiers}, \text{Independent Detection Families}, \text{Temporal Freshness}, \text{Server Attestation})$$

---

## 2. Explicit Evidence State Machine

Every piece of forensic evidence progresses through a formal finite state machine:

```
                  +-----------------------+
                  |       OBSERVED        |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |      SUSPICIOUS       | <--------------------+
                  +-----------+-----------+                      |
                              |                                  |
               +--------------+--------------+                   |
               |                             |                   |
               v                             v                   |
     +--------------------+        +--------------------+        |
     |    CORROBORATED    |        |  SERVER_VERIFIED   |        |
     +---------+----------+        +---------+----------+        |
               |                             |                   |
               +--------------+--------------+                   |
                              |                                  |
                              v                                  |
                  +-----------------------+                      |
                  |    HIGH_CONFIDENCE    |                      |
                  +-----------+-----------+                      |
                              |                                  |
               +--------------+--------------+                   |
               |                             |                   |
               v                             v                   |
     +--------------------+        +--------------------+        |
     |      DISPUTED      |        |      EXPIRED       |        |
     +--------------------+        +--------------------+        |
```

### State Definitions & Transition Criteria

1. **`OBSERVED`**:
   - Initial state upon raw sensor ingestion.
   - Represents an unverified telemetry reading (e.g., a process named `cheatengine` is active or a single mouse tick jumped 25 degrees).
   - *Transition to SUSPICIOUS:* Internal anomaly scoring exceeds base heuristic threshold.

2. **`SUSPICIOUS`**:
   - Condition deviates from normal software behavior but lacks corroborating proof from an independent subsystem.
   - Weak heuristics (process names, environment strings, isolated mouse snaps) remain in this state.
   - *Transition to CORROBORATED:* An independent detection family confirms unauthorized tampering within the active time window.
   - *Transition to SERVER_VERIFIED:* Server-authoritative attestation or raycast analysis validates the anomaly.
   - *Transition to EXPIRED:* Time window elapses without corroborating evidence.

3. **`CORROBORATED`**:
   - At least **two** independent detection categories (e.g., `MEMORY_INTEGRITY` + `BEHAVIORAL_KINEMATICS`) validate the threat.
   - Multiple reports originating from the same root cause (same memory span or recurring tick) are deduplicated and do **not** trigger this transition.
   - *Transition to HIGH_CONFIDENCE:* Cumulative corroborated threat score reaches the enforcement threshold.

4. **`SERVER_VERIFIED`**:
   - Cryptographically authenticated server attestation confirms the condition (e.g., authoritative raycast confirms player target was behind two solid walls, or HMAC challenge response fails).
   - Completely immune to client-side heuristic disputes.

5. **`HIGH_CONFIDENCE`**:
   - Threshold reached via corroborated independent signals or server verification.
   - Actionable state: enables server session rejection, match restriction, or shadow flagging.

6. **`DISPUTED`**:
   - Conflicting signals detected (e.g., unbacked memory detected, but host declares an active JIT compiler via `hostUsesJit = true`).
   - Threat score is suppressed; violation is routed to shadow telemetry for human review.

7. **`EXPIRED`**:
   - Temporal sliding window elapses (default: 60,000 ms).
   - Old events are expunged from the active corroboration pool and marked for bounded capacity eviction.

---

## 3. Independent Detection Families

To achieve true corroboration, evidence must originate from disjoint observational domains. Multiple alerts within the same domain cannot corroborate each other:

| Family ID | Category Name | Underlying Observational Mechanism |
| :--- | :--- | :--- |
| **FAM-1** | `MEMORY_INTEGRITY` | Address space structure: unbacked pages, header alterations, memory canaries. |
| **FAM-2** | `MODULE_PROVENANCE` | Disk backing, Authenticode signatures, ephemeral path analysis (`/dev/shm/`, `\temp\`). |
| **FAM-3** | `THREAD_PROVENANCE` | Call stack walk, instruction pointer location, non-module thread execution. |
| **FAM-4** | `API_HOOK` | Disk-vs-RAM code comparison, inline jumps, CET `endbr64` detours. |
| **FAM-5** | `PROCESS_HANDLE` | External process access rights, OpenProcess handle audits. |
| **FAM-6** | `OVERLAY_RENDERING` | Topmost transparent window geometry, swapchain vtable redirection. |
| **FAM-7** | `BEHAVIORAL_KINEMATICS` | View trajectory curvature, raw HID mouse intervals, triggerbot reaction times, recoil compensation. |
| **FAM-8** | `PHANTOM_ESP` | Direct user crosshair lock on invisible decoy entities. |
| **FAM-9** | `HARDWARE_DMA` | PCIe bus latency jitter, physical device vendor IDs, IOMMU translation faults. |
| **FAM-10**| `TIMING_HEARTBEAT` | Hardware TSC vs monotonic OS clock divergence, watchdog execution intervals. |
| **FAM-11**| `SERVER_ATTESTATION` | Authoritative server raycasting, movement validation, cryptographic challenge verification. |

**Corroboration Rule:**
$$\text{IsCorroborated} = \left( \sum_{i \in \text{ActiveFamilies}} 1 \right) \ge 2 \quad \text{within } \Delta t \le \text{TimeWindowMs}$$

---

## 4. Root-Cause Grouping & Deduplication

A common defect in anti-cheat correlators is allowing a single physical bug or cheat to generate dozens of alerts that falsely appear independent.

### 4.1 Memory Span Grouping
If a memory scanner detects an unbacked memory region at `0x7fff0000`, and subsequently flags three thread pointers executing within `[0x7fff0000 - 0x7fff1000]`, these alerts share a single **RootCauseId**:
$$\text{RootCauseId} = \text{Hash}(\text{Category} \mathbin{\Vert} \text{BasePageAddress})$$
Subsequent occurrences increment the occurrence count of the existing record rather than inflating the independent category count.

### 4.2 Kinematic Trajectory Grouping
Recurring mouse ticks occurring within a continuous firing engagement share a trajectory root cause. They increment session anomaly counts but cannot satisfy multi-signal corroboration on their own without external memory, overlay, or server confirmation.

---

## 5. Temporal Sliding Window & Bounded Capacity Eviction

### 5.1 Sliding Window Mechanics
The correlator maintains a temporal sliding window ($W = 60\,000\text{ ms}$):
- Incoming events record `timestamp` (milliseconds since Unix epoch).
- When evaluating category counts or enforcement eligibility, `GetActiveCategoryCount(now_ms)` evaluates:
  $$\text{IsActive}(e) \iff (now\_ms - e.timestamp) \le W$$
- Alerts older than $W$ are excluded from the corroboration threshold.

### 5.2 Bounded Storage Policy
To eliminate denial-of-service or memory bloat from continuous background audits:
1. Hard capacity bound: $N_{max} = 512\text{ records}$.
2. Eviction Priority:
   - **Phase 1:** Purge all records in the `EXPIRED` state.
   - **Phase 2:** If still exceeding capacity, sort remaining records by `(confidence_tier, last_seen_timestamp)` ascending, and evict the oldest, lowest-confidence records first.
   - High-confidence corroborated records and server-verified attestations are permanently pinned until session termination.
