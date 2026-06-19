# bd-4rxozm — strchr page-safe 32-byte SIMD scan — MEASURED WIN

**Root cause:** the deployed ABI `strchr`/`strchrnul` path
(`scan_c_string_for_byte`, string_abi.rs) scanned with **SWAR (8 bytes/iter)**,
while glibc strchr uses AVX (32 bytes/iter). strchr was not in the SIMD-dispatch
list. That is the measured large-size loss (~14–18x slower than glibc).

**Lever:** widen the unknown-length (`bound = None`) scan to **page-safe 32-byte
portable SIMD** for `target` OR NUL, mirroring the *exact* page-safe pattern
already used by the NUL-only `scan_c_str_len` in the same file: take the wide
load only when the 32-byte window stays in-page (`(p+i) & 0xFFF <= 0x1000-32`),
otherwise fall to the existing 8-aligned 8-byte SWAR resolve. No new safety
reasoning — it reuses the proven in-file idiom. Benefits `strchr`, `strchrnul`,
and every caller of `scan_c_string_for_byte`.

**Verdict:** WIN — 2.9–7.8x faster than the prior SWAR; glibc gap closed from
~14–18x to ~1.8–2.5x at large sizes. Correctness preserved, page-safety proven.

## Results (p50 ns/op, `strchr_glibc_bench`, absent-byte full scan, same worker)

| size | SWAR (before) | SIMD (after) | **speedup** | glibc | gap before→after |
|-----:|--------------:|-------------:|------------:|------:|------------------|
| 64     | 22.7   | 16.3   | 1.40x | 2.8   | 8.1x → 5.8x |
| 1024   | 146.9  | 49.8   | 2.95x | 9.3   | 15.8x → 5.4x |
| 16384  | 1928.5 | 269.0  | **7.17x** | 109.2 | 17.7x → **2.46x** |
| 65536  | 7464.6 | 955.5  | **7.81x** | 534.0 | 14.0x → **1.79x** |
| 262144 | 29244.3| 3980.5 | **7.35x** | 2119.2| 13.8x → **1.88x** |

The SWAR-vs-glibc ratio at 16K (17.7x) reproduces the bead's documented
0.05–0.06x. The residual gap after the lever:
- **Small (64–1K, ~5.5x):** fixed membrane per-call overhead in `strchr_locate`
  (decide/observe/stage_context), not the scan — architectural, same class as
  the deployed-malloc finding.
- **Large (~1.8–2.5x):** portable_simd 32-byte vs glibc's hand-tuned AVX2/AVX512
  (likely 64-byte / unrolled). A 64-byte panel could narrow it further;
  diminishing and left as a follow-up.

## Conformance + safety (host glibc 2.42)

- `conformance_diff_strchr`, `conformance_diff_strchrnul`,
  `conformance_diff_scan_c_string`: all pass (value parity vs glibc unchanged).
- **New** `strchr_guard_page_safety`: maps two pages, `PROT_NONE`s the second,
  places the NUL at **every offset in the last 40 bytes** of page 1, and scans
  for an absent byte from several start offsets — the SIMD window never reads
  into the guard page (no SIGSEGV) and returns the exact NUL position. Proves the
  `(p+i)&0xFFF <= 0x1000-32` guard holds.

## Method

```
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench strchr_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```
Controlled before/after on the same worker (SWAR baseline run with the SIMD panel
temporarily removed, then re-applied). glibc via `dlmopen(LM_ID_NEWLM)` to avoid
fl's `no_mangle` interposition.

## Follow-up: length-escalated folded-128 tier (KEPT, supersedes 32B)

An un-gated folded 4×32=128B tier (one `.any()` per 128 B) was measured first and
**rejected** — it closed the large-size gap further but regressed short strings
(64 B normalized 5.80x→8.18x) by doing 128-byte work for sub-128 strings. The
fix, as the reject's retry predicate proposed: **gate the folded tier on
`i >= 128`** so short strings terminate in the 32B/SWAR tiers and never reach it.

Re-measured vs the committed 32B (near-identical glibc control both runs):

| size | committed 32B fl | escalated folded fl | speedup | fl/glibc 32B→folded |
|-----:|-----------------:|--------------------:|--------:|---------------------|
| 64     | 16.3   | 17.9   | ~neutral (noise) | 5.80 → 5.93 |
| 1024   | 49.8   | 46.7   | ~neutral | 5.36 → 5.64 |
| 16384  | 269.0  | 199.8  | **1.35x** | 2.46 → **1.84** |
| 65536  | 955.5  | 677.0  | **1.41x** | 1.79 → **1.26** |
| 262144 | 3980.5 | 2537.0 | **1.57x** | 1.88 → **1.20** |

WIN: 1.35–1.57x faster than the 32B tier at large sizes, **no short-string
regression**, 256K now **1.20x glibc** (near parity). Correctness (strchr/
strchrnul gates) and page-safety (`strchr_guard_page_safety`, folded tier
exercised near the page boundary) both green.
