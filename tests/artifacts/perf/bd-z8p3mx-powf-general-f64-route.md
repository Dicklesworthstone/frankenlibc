# bd-z8p3mx — general `powf` f64 exp/ln route — MEASURED PARTIAL WIN (kept)

**Lever:** the general/irrational case of fl `powf` (f32) deferred to
`libm::powf` (the bead's named ~2.5x-slower fallback). Route positive-finite
bases with finite exponents through `powf(x,y) = exp(y*ln(x))` evaluated in f64
using fl's own fast f64 `exp`/`log` kernels (both beat glibc on their fast-path
domains, libm-correct elsewhere). Accept the result only when it rounds to a
finite **normal** f32 — overflow/underflow/subnormal defer to `libm::powf` so the
errno-setting ABI layer keeps exact FE_OVERFLOW/FE_UNDERFLOW/EDOM/ERANGE
semantics.

**Verdict:** WIN vs prior fl code (1.4–1.6x faster general powf), still LOSS vs
glibc (~3.9x). Strict improvement, **no regression** → KEPT (the ledger reverts
*regressions*; this is the opposite). Accuracy ≤1 ULP. A follow-up bead carries
the remaining glibc gap (needs a fused single-pass f32 kernel, not two f64
transcendentals).

## Why it does not yet beat glibc

`exp(y*ln(x))` is **two** f64 transcendental calls (~15 ns each on fl's fast
paths) for one f32 result — inherently ~2x glibc's single fused f32 `powf`
kernel (table log + reduce + table exp, double-double precision, ~8 ns). The f64
intermediate is *required* for general-range accuracy: rounding `y*log2(x)` to
f32 before a fast f32 `exp2f` exceeds 4 ULP for large |y·log2 x| (which is
exactly why the existing `powf_medium_fast_path` is bounded to base∈[0.5,2.5),
exp∈[-3,3]). So ~30 ns is the floor for this approach; closing to glibc needs a
ported fused f32 algorithm (follow-up bead).

## Method

- Worker: rch `ovh-a` (cache warm). New self-contained bench
  `crates/frankenlibc-bench/benches/powf_glibc_bench.rs` (no `abi-bench`, so the
  host `powf` symbol resolves to glibc with no fl interposition).
- Arms per case: `fl` (`frankenlibc_core::math::powf`, new path), `fl_old`
  (`libm::powf`, the pre-lever fallback), `glibc` (host `powf`).
- Cases target the GENERAL path (base outside the medium box, non-special
  exponent): `general_big_e` (base∈[3,9.3), y=e), `general_small_1p7`
  (base∈[0.02,0.47), y=1.7), `general_big_pi` (base∈[3,9.3), y=π);
  `medium_ref_1p7` is the unchanged medium path for reference.

```
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
rch exec -- cargo bench -p frankenlibc-bench --bench powf_glibc_bench -- \
  --measurement-time 2 --warm-up-time 1 --noplot
```

## Results (p50 ns/op, batch of 64 f32 inputs)

| case | fl (new) | fl_old (libm) | glibc | fl/fl_old | fl/glibc |
|------|---------:|--------------:|------:|----------:|---------:|
| general_big_e     | 30.85 | 44.77 | 7.89 | 0.689 (WIN) | 3.91 |
| general_small_1p7 | 27.31 | 44.82 | 7.86 | 0.609 (WIN) | 3.48 |
| general_big_pi    | 32.41 | 44.61 | 7.82 | 0.726 (WIN) | 4.14 |
| medium_ref_1p7 (unchanged) | 18.64 | 43.75 | 7.82 | 0.426 | 2.38 |

`medium_ref` is the pre-existing `exp2f/log2f` medium path (not touched by this
lever) and shows the same kind of residual glibc gap — both point at the same
follow-up: a fused f32 powf kernel.

## Conformance (all GREEN, host glibc 2.42)

- **New gate** `conformance_diff_powf_general::general_powf_within_4_ulps_vs_glibc`:
  6981 general-domain inputs within 4 ULP, **worst = 1 ULP**
  (`powf(6.068393, e) fl=134.46677 glibc=134.46678`). Overflow/underflow/subnormal
  pairs asserted for exact inf/0 classification (errno-layer parity).
- Existing `diff_powf_profile_exp_1_337_within_4_ulps`: pass (1.337 hits the
  earlier overfit grid, unaffected).
- `math_abi::tests::powf_underflow_{positive,negative}_exponent_sets_range_errno`:
  pass (underflow defers to libm → ABI errno logic unchanged).
- `conformance_diff_fp_exceptions::fp_exception_and_value_parity_vs_glibc`: pass.

## Retry predicate / follow-up

To actually beat glibc on general `powf`, port a fused single-pass f32 kernel
(glibc `e_powf` / the Arm-optimized `__v_powf` 2^7-entry log+exp tables with a
double-precision reduction) instead of composing two f64 transcendentals. Filed
as a follow-up bead. The same fused kernel would also close the `medium_ref`
residual. Reuse `powf_glibc_bench` for measurement.
