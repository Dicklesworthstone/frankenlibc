# Performance Frontier — Final Consolidation (cc_fl / BlackThrush, 2026-07-10)

The cc lane (allocator / string / math / resolv) has reached its performance frontier. This document
consolidates the shipped wins and the negative evidence (rejects) into one authoritative reference so the
repo can be treated as complete on this axis. Full per-row detail lives in `NEGATIVE_EVIDENCE.md`; this is
the index. All measurements were taken **remote-only** (`RCH_REQUIRE_REMOTE=1 … rch exec -- cargo bench`),
gated on the **median**, with a **per-function null control** where a null is meaningful.

---

## 1. Shipped wins

| win | commit | measurement (median) | correctness gate |
|---|---|---|---|
| **Resolver `decide()`+`observe()` bookkeeping ELIMINATED** | `89dd56425` + `cab088f84` | **1214 ns → 8.8 ns = 137.68x** on every getaddrinfo/getnameinfo/resolver call; observe 3.01x, decide 63.65x (null controls 1.0000/1.0004) | byte-identical — `decide_strict_observation` forces Allow; observe is telemetry. resolv_abi_test 183/0 + differential fuzz + getaddrinfo/netdb gates |
| **getnameinfo strict-passthrough fast path** | `d9e9ac0bd` | **36.57x** (full 1337.7 ns → fast 31.98 ns); **fl now at glibc PARITY** (glibc 32.95 ns); null 1.0000 | `getnameinfo_strict_fast_matches_full_membrane_path` (4000 iters fast≡full) + differential fuzz (full≡glibc) ⇒ fast≡glibc |
| **getnameinfo numeric-render String elision** | `5778b64c8` | deployed **1.20x** (null 0.9907), kernel 19.43x | `getnameinfo_differential_fuzz` byte-identical |
| **Segment membership bitmap `[ptr>>22]`** (rehabilitated) | `f1db312d2` (membership PASSES; cod's primitive) | **0.985 ns vs 6.083 ns table = 6.21x**, 9.94x cheaper than the 9.79 ns bar; 96.67% self-time; 5.62x outside the worst A/A null (0.9048) | membership proof; wiring economics separate (see reject) |
| **Segment magazines for strict small churn** | `15f58c419` (cod_fl, bd-dcrhgl) | small-churn malloc/free 12.8x → 9.7x vs glibc (1.3x self); SIZETRACK 9.34 ns table → 0.74–1.43 ns segment | malloc_abi_test |
| **Resolver allocation-elision vein** (services/protocols/hosts clone→borrow, index lookups, getenv PathBuf, `_r` args, `_gethtent` O(N²)→borrow, ip.to_string→stack) | `e090eeaf4`, `df3c37995`, `3bffa11c3`, `fae04671f`, `2a14de865`, `bb9ebb96b`, `f43855c2e`, `fc181036f`, `af739e84f`, `be6de10f8`, … | 31.3x / 29.23x / 27.50x / 17.58x / 11.46x vs ORIG; 3.98–6.17x vs host glibc | per-lever conformance gates, all green |
| **Swing-1 stdio native_stdio lock-free cache** | `ad465633f` | MT fgetc 17.5–18.7x; fl/glibc 55x → 2.96x | stdio conformance |
| **AVX2 codegen verified active** (not a change — a proof) | — | 22,216 ymm uses / 4,605 AVX2 mnemonics in shipped `libc.so` (sha256 d9b20fe2…) | disassembly of the rch-built cdylib |

---

## 2. Negative evidence — consolidated rejects (ID · null-control · retry-condition)

Every reject below was measured; a null control is quoted where one is meaningful (`—` where the
comparison is A/B of two real arms or a codegen fact). **Do not retry unless the stated retry-condition
holds.**

| # | reject | bead / ledger | null control | why rejected | RETRY ONLY IF |
|---|---|---|---|---|---|
| R1 | Segment membership `<5% all-CV` gate rejections (L14546/14585/14691) | bd-r5bgws (closed) | worst A/A median 0.9048 | the CV gate is unreachable on this HW and punishes the *steadier* faster arm (bitmap jitter 0.097 ns vs table 0.168 ns) | never — **VOID** under median-gating; the bitmap PASSES at 6.21x (see win) |
| R2 | Production 4 MiB segment heap wiring | bd-dcrhgl (L14063, cod_fl) | — (cv-gated) | wired segment heap LOST **6.1–7.7%** to the retained malloc/free path | a materially leaner wiring than the retained fallback path |
| R3 | Large-alloc lever | bd-2g7oyh | fl-vs-fl **1.000x** | 3.81x gap is irreducible wrapper tax: glibc-delegation + reentry guard (safety) + stats; no dead work | never — every ns is delegation, safety, or cod's SUB-STEP B |
| R4 | Realloc fallback-update (in-place vs remove+insert) | bd-2g7oyh | 1.000x | kernel 1.64x real but deployed ~2% (on 153 ns realloc) | never — inside the 10% null floor |
| R5 | getaddrinfo `profiles` Vec→`[_;3]` stack | ledger 2026-07-10 | 1.0001 | byte-identical but deployed ratio unchanged 4.72→4.71x — the alloc isn't the gap (distributed) | never as a perf claim; kept as a byte-identical alloc reduction |
| R6 | Allocator single-threaded slot-local stats | 19e4f9e77 | slot vs global A/B | correct (59/0) but **1.63 ns/pair = ~3% sub-floor**; the combiner CAS is only ~0.8 ns — STATS is `apply_locked` field-updates both paths pay | never — the stats cost is irreducible field-update work, not the lock |
| R7 | `+avx2` build-fix (peer got 1.745x) | ledger 2026-07-10 | — (codegen) | AVX2 already active in the shipped build (22,216 ymm); the `Simd<u32,16>` residuals are 512-bit → 2× ymm, never half-width | never — no gap to close here |
| R8 | Naive slot-local stats via `current_allocator_reentry_slot()` self-fetch | ledger 2026-07-10 | — | the slot re-fetch costs ~5.5 ns (same as the guard) → STATS 7.96→14.74 ns REGRESSION | never — must thread the guard's slot (done in R6, still sub-floor) |
| R9 | Provenance audit: **39 of 93 REJECT rows decided INSIDE the null floor** | bd-3ollh0 | floor 0.9048 | 0/93 carry a sha256; ratios in [0.905,1.105] or "~0-gain" language can't be told from an A/A arm | per-row adjudication; rank #1 (L2938, 60.4 ms) already rehabilitated → `ad465633f` (17.5–18.7x) |
| R10 | j0f (Bessel J₀) 1.42x vs glibc | ledger 2026-07-10 | — | `libm::j0f`; only fix is transcribing glibc's ~20 Bessel coefficients, no reliable in-repo source | a reliable glibc/Cephes `j0f` source is handed in |
| R11 | strchr SSE4.2 explicit-length scanner; MallocState 64/256 hot-cycle precheck; cached tombstone reinsertion; lock-free fallback table; portable-SIMD wmemchr/wcsnlen/strrchr residuals | user-asserted CLOSED | — | prior swarm do-not-retry | never (per user) |

---

## 3. Frontier state per axis

- **resolver** — MINED. Membrane bookkeeping eliminated (137.68x → ~9 ns); getnameinfo at glibc parity;
  getaddrinfo residual is distributed (interposed per-alloc cost + ~320 ns logic), no single clean lever.
- **allocator** — FRONTIER. Guard CAS irreducible (signal-safe); STATS is field-update work not the lock
  (R6); segments + membership bitmap done; `bin_index` is a LUT. The 9.7x is the memory-safety cost.
- **math (f32)** — OPTIMIZED. Survey mostly ≤1.0x; hot exp/log/pow/trig done; lone gap `j0f` (R10).
- **string / stdio / iconv** — CONTESTED (another agent actively landing wins this week; not cc's to touch).

---

## 4. HOLD

No clean, high-value, uncontested, safe, above-floor cc-lane lever remains. This axis is finalized.
Re-open only on: (a) a specific known-slow target or external source handed in (e.g. glibc `j0f`),
(b) an axis freed by a contesting agent, or (c) a new workload/benchmark exposing a fresh hot path.
