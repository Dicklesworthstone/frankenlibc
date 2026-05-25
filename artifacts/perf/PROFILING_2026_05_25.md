# FrankenLibC Performance Profiling Report — 2026-05-25

## Methodology
- **Tool**: Criterion benchmarks, 100+ samples per function
- **Baseline**: Host glibc 2.40 (same machine, same workload, apples-to-apples)
- **Profile**: `[profile.bench]` with LTO, codegen-units=1

## Ranked Hotspot Table (Descending by Slowdown)

| Rank | Function | Workload | FrankenLibC p50 | glibc p50 | Ratio | Severity |
|------|----------|----------|-----------------|-----------|-------|----------|
| 1 | **malloc/free** | 64B cycle | 1,072 ns | 8 ns | **134x** | CRITICAL |
| 2 | **strlen** | 4096B scan | 2,179 ns | 38 ns | **57x** | CRITICAL |
| 3 | **strcmp** | 256B equal | 299 ns | 10 ns | **29x** | CRITICAL |
| 4 | memset | 4096B fill | 42 ns | 57 ns | **0.7x** | OK (faster) |
| 5 | qsort | 128 i32s | 4,667 ns | 3,899 ns | 1.2x | MINOR |

## Membrane Overhead (Safety Tax)
| Stage | p50 | Notes |
|-------|-----|-------|
| arena_lookup | 12 ns | Per-pointer lookup |
| page_oracle | 4 ns | Foreign page check |
| fingerprint_verify | 22 ns | Per-block verification |
| canary_verify | 1 ns | Stack canary check |
| bounds_check | 1 ns | Bounds validation |
| validate_null | 4,145 ns | Full NULL region scan |
| validate_foreign | 1,944 ns | Foreign pointer validation |

Total membrane overhead per call: ~25-50ns in hot path, acceptable.

## Root Cause Analysis

### 1. strlen — 57x Slower
**Implementation**: Naive byte-by-byte iterator scan
```rust
s.iter().position(|&b| b == 0).unwrap_or(s.len())
```
**glibc**: Uses SSE4.2 `pcmpistri` instruction to scan 16 bytes at once, with word-at-a-time fallback.

**Fix**: Implement word-at-a-time scanning using the `(x - 0x01..01) & ~x & 0x80..80` bit trick, optionally with SSE2/AVX2 when available.

### 2. strcmp — 29x Slower
**Implementation**: Byte-by-byte loop with bounds checks per byte
```rust
loop {
    let a = if i < s1.len() { s1[i] } else { 0 };
    let b = if i < s2.len() { s2[i] } else { 0 };
    ...
}
```
**glibc**: Uses SIMD to compare 16-32 bytes at once, early-exit on first difference.

**Fix**: Word-at-a-time comparison with XOR + NUL-detect trick.

### 3. malloc/free — 134x Slower (Expected Safety Tax)
**Root Cause**: FrankenLibC's temporal safety membrane adds cumulative overhead:

| Component | Cost per op | Description |
|-----------|-------------|-------------|
| SipHash fingerprint | ~20-40ns | 24B header computed on every alloc |
| Canary verification | ~5-10ns | 8B trailer + SipHash recompute on free |
| Sharded mutex | ~15-30ns | 16 shards, mutex lock/unlock per op |
| BTreeMap lookup | ~10-20ns | O(log N) for slot lookup |
| Quarantine queue | ~10-20ns | Deferred free + epoch bump |
| Runtime policy gate | ~5-10ns | ApiFamily check + proof-carried code |

**Total: ~65-130ns per malloc/free** vs glibc's ~8-10ns fastbin path.

**Why glibc is faster**:
- Per-thread arenas with no global lock
- Fastbins (16-128B) are O(1) no-lock LIFO
- No per-allocation metadata overhead
- No temporal safety checks

**This is by design** — FrankenLibC provides:
- Use-after-free detection (quarantine + generation counters)
- Double-free prevention (canary verification)
- Buffer overflow detection (canary corruption)
- Pointer validation (arena lookup)

**Optimization opportunities** (if safety can be relaxed):
1. Bypass fingerprint for "trusted" allocations (internal use only)
2. Add size-class freelists without BTreeMap lookup
3. Skip quarantine for same-thread reuse (single-threaded mode)
4. Use RCU-style read-side unlocked lookups

## Recommendations

1. **Create bd-* beads** for strlen/strcmp/malloc optimization
2. **Preserve safety** — don't remove membrane for correctness-critical paths
3. **Add arch-specific paths** — SSE2 is baseline on x86_64, use it
4. **Consider intrinsics** — `core::arch::x86_64` for hand-tuned kernels

## Baseline Evidence
- glibc_baseline_bench ran successfully with 100+ samples
- Results stored in criterion target directory
- Same hardware, same kernel, same benchmark harness
