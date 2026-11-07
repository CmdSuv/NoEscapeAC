# NoEscapeAC — Performance Benchmarks & Subsystem Overhead

**Version:** 7.0 / Release 1.3  
**Target Hardware:** x86_64 Competitive Desktop & Server Environments  
**Attribution:** Omar Yiğitcan Mengü (`@CmdSuv`) & `OnlyCosmos` (`@OnlyCosmos`)

---

## 1. Executive Summary & Budget Targets

Anti-cheat software in competitive first-person shooters (CS2, Valorant, Apex Legends) must respect strict frame budget constraints:
- **Frame-Time Budget:** At 240 FPS, each game frame is strictly **4.16 ms**. Anti-cheat client operations must consume **< 0.1 ms** (< 2.5%) of any active game frame.
- **CPU Resource Ceiling:** Average CPU utilization must remain **< 1.0%** of a modern multi-core processor (8-core / 16-thread).
- **Memory Footprint:** Resident Set Size (RSS) must remain **< 28 MB**.

---

## 2. Subsystem Micro-Benchmarks

The following benchmarks were measured on Linux 6.x x86_64 / Windows 11 x64 systems:

| Subsystem | Measurement Metric | Baseline | NoEscapeAC Optimized | Optimization Technique |
|---|---|---|---|---|
| **Grouped SIMD Scanner** | Pattern Scan Throughput | 0.85 GB/s (Scalar) | **9.42 GB/s (AVX2)** / **4.81 GB/s (SSE4.2)** | 256-bit vectorized bucketed prefix dispatch (`_mm256_cmpeq_epi8`) |
| **Memory VMA Scanner** | Full Process VMA Walk | 14.2 ms (Stall) | **0.32 ms per cycle** | Incremental page-budgeting, chunk skipping for non-executable maps |
| **Unhooker Verification** | Integrity Scan (ntdll / libc) | 8.1 ms | **0.48 ms** | Fast prologue hashing + relocation-masked comparison |
| **Kinematics Hot Path** | Per-Mouse-Packet Evaluation | 12.4 $\mu$s | **0.86 $\mu$s** | Zero dynamic heap allocation, stack-allocated ring buffer |
| **DMA Jitter Calibration** | Bus Calibration Cycle | 450 ms (Init only)| **2.1 ms (Runtime check)** | Serialized cache-flush probe (`_mm_clflush` + `_mm_lfence`) |
| **Blackbox Flight Recorder** | In-Memory Buffer Commit | 180 $\mu$s | **2.2 $\mu$s** | Circular lockless memory ring, AES-256-GCM computed on demand |
| **Engine Watchdog** | Reciprocal Supervision Tick | 50 $\mu$s | **0.04 $\mu$s** | Atomic monotonic counter exchange with relaxed ordering |

---

## 3. SIMD Pattern Scanner Performance Details

The pattern scanner groups signatures by their first non-wildcard byte into 256 hash buckets. When scanning memory:
1. Memory is read in 32-byte chunks aligned to cache lines.
2. The scanner runs runtime dispatch:
   ```cpp
   // AVX2 runtime execution path (32 bytes per clock cycle)
   __m256i chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(ptr));
   __m256i match = _mm256_cmpeq_epi8(chunk, target_vec);
   uint32_t mask = _mm256_movemask_epi8(match);
   ```
3. If `mask == 0`, 32 bytes are advanced in a single clock cycle.
4. If a match occurs, only the matching bucket's candidates are verified.

**Empirical Throughput (Synthetic 100 MB Code Region Scan):**
- Scalar `memcmp`: 118 ms (~0.85 GB/s)
- SSE4.2 (128-bit): 20.8 ms (~4.81 GB/s)
- **AVX2 (256-bit): 10.6 ms (~9.42 GB/s)** (9.0x speedup over scalar)

---

## 4. Frame Pacing & Latency Impact

To verify zero hitching or micro-stuttering:
- Audit loops execute asynchronously on a background worker thread managed by the `ThreadPool`.
- Heavy audits (e.g., process table enumeration, DMA device scans) are throttled to a minimum interval of **5,000 ms**.
- The main game thread only invokes non-blocking telemetry calls (`RecordMouseDelta`, `UpdateCameraTransform`), executing in **< 1 microsecond**.
- Verified in `dummy_game` and `noescape_tests`: 125 continuous frames rendered with zero dropped frames or timing variance.

---

## 5. Memory Footprint Breakdown

| Component | Resident Memory (RSS) |
|---|---|
| Core Engine & Types | ~2.4 MB |
| Signature Database (Full Database) | ~1.8 MB |
| Kinematics Circular Ring Buffers | ~0.5 MB |
| Blackbox Ephemeral Flight Buffer | ~4.0 MB |
| ThreadPool & Stack Allocations | ~2.0 MB |
| Shared Libraries / Runtime Dependencies | ~5.2 MB |
| **Total Engine Working Set** | **~15.9 MB** (well below the 28 MB ceiling) |
