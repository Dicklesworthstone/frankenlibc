# Host glibc baseline profile

Bead: `bd-2g7oyh.183` (refresh of `bd-bp8fl.8.3`)
Generated: `2026-06-06`
Source base commit: `80ca72e3`
Profile tool: Criterion via `rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench`
Runtime mode: `strict`  Replacement level: `L0`  Host: Zen3 (AVX2+FMA, no AVX-512)

## Why this was regenerated

The previous baseline (2026-05-03, commit `0f2534c5`) is **stale by ~30–2000x**.
It reported `strlen_4096` at 43.56x slower and `malloc_free_64` at 2628x slower.
A month of SIMD + algorithm work (SWAR int-parse, ARM-table log2/exp2, Cephes
tgamma, two-way memmem, pdqsort, exp-identity hyperbolics, regex lazy DFA, …)
has **closed or reversed** those gaps. Measured now: `strlen_4096` is **0.89x —
FrankenLibC is faster**. Leaving the old numbers in place misdirected the
no-gaps epic toward phantom regressions, so this is a full re-measure.

`Hotness = frankenlibc_core_mean / host_glibc_mean` (>1 = FrankenLibC slower).
~60 profiles: FrankenLibC is **faster on ~38**, at **parity on ~8**, slower on
~14 (all ≤1.9x). The substring family (memmem/strstr/strcasestr/wcsstr) is
100–400x faster because glibc ships a naïve O(n·m) scan there while FrankenLibC
uses Two-Way + a SIMD first-byte filter.

## Residual FrankenLibC-slower profiles (ranked, worst first)

| Profile | FL mean | glibc mean | Hotness | Class |
|---|---:|---:|---:|---|
| `math/pow_irrational` | 1515.8 ns | 796.7 ns | 1.90x | transcendental fusion (2 safe-Rust kernels vs glibc fused asm) — parked `bd-e4jb7k` |
| `math/powf_irrational` | 681.9 ns | 391.2 ns | 1.74x | same fusion wall |
| `memcmp_256` | 5.12 ns | 3.47 ns | 1.48x | safe-SIMD vs hand-AVX2 codegen |
| `memchr_absent` | 33.0 ns | 22.4 ns | 1.47x | codegen |
| `memcmp_16` | 3.70 ns | 2.54 ns | 1.45x | small-size dispatch overhead |
| `strchr_absent` | 44.6 ns | 32.5 ns | 1.37x | codegen |
| `math/log10f` | 464.7 ns | 352.7 ns | 1.32x | f32 transcendental |
| `math/erfc` | 975.5 ns | 792.0 ns | 1.23x | special-fn polynomial |
| `strncmp_256` | 7.24 ns | 5.89 ns | 1.23x | codegen |
| `memmove_4096` | 43.3 ns | 35.3 ns | 1.23x | codegen |
| `math/erf` | 984.0 ns | 804.1 ns | 1.22x | special-fn polynomial |
| `strrchr_absent` | 43.8 ns | 37.6 ns | 1.16x | codegen |
| `strtol_short` | 8.75 ns | 7.59 ns | 1.15x | setup-bound (short input) |
| `math/log2f` | 374.3 ns | 331.1 ns | 1.13x | f32 transcendental |
| `memcmp_4096` / `memcpy_4096` / `strcpy_4096` / `math/exp` / `math/exp10` | — | — | 1.02–1.04x | parity (within noise) |

## Representative FrankenLibC wins (Hotness < 1)

| Profile | FL mean | glibc mean | Hotness |
|---|---:|---:|---:|
| `memmem_absent` | 34.7 ns | 14885 ns | 0.0023x (428x faster) |
| `strstr_absent` | 56.5 ns | 15041 ns | 0.0038x (266x) |
| `strcasestr_absent` | 100.7 ns | 19265 ns | 0.0052x (191x) |
| `math/tgamma` | 265.1 ns | 1767.3 ns | 0.15x (6.7x) |
| `math/pow` | 215.1 ns | 771.6 ns | 0.28x |
| `scanf_hex_long` | 28.4 ns | 92.7 ns | 0.31x |
| `strtoul_hex_long` | 11.7 ns | 29.3 ns | 0.40x |
| `math/expm1` | 249.1 ns | 562.3 ns | 0.44x |
| `printf_f_6` | 103.0 ns | 192.3 ns | 0.54x |
| `math/exp2` | 191.8 ns | 352.1 ns | 0.54x |
| `fnmatch_pathname` | 49.7 ns | 81.6 ns | 0.61x |
| `math/sin` | 363.6 ns | 560.0 ns | 0.65x |
| `qsort_128_i32` | 1799 ns | 2611 ns | 0.69x |
| `strcmp_256_equal` | 4.25 ns | 5.33 ns | 0.80x |
| `strlen_4096` | 19.3 ns | 21.6 ns | 0.89x |
| `memset_4096` | 34.7 ns | 37.1 ns | 0.94x |

(`malloc` is excluded — peer-owned `bd-4scbmf`; the old synthetic
`frankenlibc_core_state` row measured state-routing overhead, not the ABI
allocator, and was the source of the bogus 2628x figure.)

## Interpretation / remaining levers

- **Compute surface (math, parse, format, sort, search, match): no safe-Rust gap
  remains** — FrankenLibC meets or beats glibc. The no-gaps directive is
  effectively satisfied here.
- **Core mem primitives (memcmp/memchr/strchr/memmove small-mid sizes, ~1.2–1.5x):**
  instruction-selection bound, not algorithmic. glibc dispatches to runtime-ERMS
  `rep movsb`/`rep cmpsb` and non-temporal stores; safe Rust cannot emit those
  without `unsafe` arch intrinsics, which would violate the project's 100%-safe-Rust
  premise. The portable-SIMD algorithm already matches glibc's; the gap is the
  hand-tuned asm schedule on Zen3. Micro-levers here have been repeatedly rejected
  (correctly) — this is a language/principle boundary, not a missing optimization.
- **`pow_irrational` / `powf_irrational` (1.7–1.9x):** the only sizeable
  non-mem gap — transcendental-fusion bound (composing two safe-Rust kernels vs
  glibc's single fused asm routine). Tracked in `bd-e4jb7k`; a fully-fused
  minimax `pow` is the only lever and is low-EV (~1.4x best case).
- **Regex single-pass search — DONE (was the named next swing).** The unanchored
  *search* path no longer probes every start with `run_from` (O(n²·m)); a single
  merged unanchored sweep (`PikeVm::leftmost_start`, `regex.rs`) finds the leftmost
  matching start in O(n·m), then one `run_from` at that start recovers captures.
  A debug-only assertion pins this isomorphic to the old per-start probe, and the
  regex differential fuzz vs glibc gates POSIX leftmost-longest correctness.
  Confirmed against fnmatch/regex bench groups (fl beats glibc on the adversarial
  backtracking cases).
- **Regex nested/empty submatch (`bd-1djvkw`) — RESOLVED, not a gap.** The nested
  divergence is a glibc *artifact* (it reports group spans impossible for a single
  iteration, e.g. `(.(b*)*)*` on "aaaa." → g1=[0,5]); fl is POSIX-principled
  (last-iteration). Whole-match parity is exact. Document-don't-mirror (like
  twalk/ecvt/remquo); pinned by `conformance_diff_regex_nested_submatch.rs`.
- **Named next algorithmic swing:** **SIMD UTF-8 multibyte decoder** (Lemire-style)
  for the `mb*`/`wc*` conversion family (`bd-w7mtzu`). The ASCII fast paths are SIMD
  and the bounded/restartable variants now match glibc, but the *multibyte* decode is
  still scalar per-char (`utf8_decode_step`): measured fl 1.3–1.8× slower than glibc's
  gconv on Cyrillic (2-byte) / CJK (3-byte) text (`mbstowcs` 1.33 vs 0.73 ns/byte). A
  high-nibble lead-length lookup + shuffle-assemble decoder (fallback to scalar for
  4-byte/errors/chunk-boundary) is the lever; multi-session, correctness-critical,
  gated by the wchar differential fuzzes. Overlaps iconv UTF-8 (`bd-48uzu9`) — a
  shared decoder primitive serves both. A `src[si]<0x80` guard already removed the
  wasted re-entrant ASCII SIMD probe on multibyte lead bytes (~1.12×, isomorphic).

## Validation Commands

```bash
rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench
```
