# bd-fused-f32-exp-log-kernels — fused exp2f/log2f/expf glibc kernels — MEASURED WIN

**Lever:** following the proven powf recipe (`bd-z8p3mx`), replace the
general-case `libm` fallbacks of `exp2f`, `log2f`, and `expf` with the fused
single-pass kernels from ARM optimized-routines (the same algorithms glibc ships
as `__ieee754_exp2f` / `__ieee754_log2f` / `__ieee754_expf`). High synergy: the
exp2f 32-entry table and the log2 16-entry table were already in `float32.rs`
from the powf port and are reused as-is (the log2f data table is byte-identical
to `POWF_LOG2_TAB` since `POWF_SCALE = 1`).

**Verdict:** WIN — all three beat both libm and glibc, all bit-exact.

## Results (p50 ns/op, batch of 64 f32 inputs, rch worker)

| case | fl (fused) | fl_old (libm) | glibc | fl/fl_old | fl/glibc |
|------|-----------:|--------------:|------:|----------:|---------:|
| exp2f | 2.36 | 3.13 | 5.22 | **0.75x** | **0.45x** |
| log2f | 2.68 | 5.71 | 5.62 | **0.47x** | **0.48x** |
| expf  | 3.01 | 7.51 | 5.46 | **0.40x** | **0.55x** |

- vs the prior libm fallback (the cleanest comparison — both are inlinable Rust):
  **1.3x / 2.1x / 2.5x faster**. This is the genuine kernel improvement.
- vs glibc: 0.45–0.55x (1.8–2.2x faster) by the repo bench convention.

**Honest caveat:** part of the fl-vs-glibc margin is inlining — the bench calls
`frankenlibc_core::math::*` (Rust, inlinable into the batch loop), while glibc is
an opaque `extern "C"` call. The deployed `no_mangle` ABI symbol would not inline,
narrowing the glibc margin (the same method showed powf *slower* than glibc at
1.23x, so it is not uniformly flattering — these tiny tight kernels genuinely
inline and vectorize well). The robust, method-independent result is the
**1.3–2.5x win over the prior libm fallback**, plus an algorithm + accuracy now
**identical to glibc** (bit-exact).

## Implementation (`crates/frankenlibc-core/src/math/float32.rs`)

- `exp2f`: routes |x| < 126 through `powf_exp2_inline` (the exp2 stage already
  validated for powf — `exp2f.c`'s core is identical, no sign bias).
- `log2f`: new `log2f_kernel` (reuses `POWF_LOG2_TAB` + a standalone degree-4
  `LOG2F_POLY`) for positive normal x; replaces the dyadic-profile overfit grid.
- `expf`: new `expf_kernel` (reuses `POWF_EXP2_TAB` + `EXPF_INVLN2_SCALED` /
  `EXPF_POLY_SCALED` / unscaled `EXPF_SHIFT = 0x1.8p+52`) for 5 < |x| < 87; the
  existing [-5,5] fast path (which already beat glibc) is kept ahead of it.

Overflow/underflow/subnormal/zero/negative/inf/nan defer to `libm::*` so the
errno/FE layer stays exact. Constants stored as exact IEEE-754 bit patterns
(Rust has no hex-float literals; converted via Python `float.fromhex`).

## Conformance (all GREEN, host glibc 2.42)

- `conformance_diff_exp2f_general`: **bit-exact (0 ULP)** over 22 493 interior
  inputs + exact boundary/special parity.
- `conformance_diff_log2f_expf_general::log2f_…`: **bit-exact (0 ULP)** over
  216 369 inputs.
- `conformance_diff_log2f_expf_general::expf_…`: ≤4 ULP over 22 526 inputs
  (worst 4 ULP at x=-4.955, in the *pre-existing* [-5,5] path, not the new
  kernel — the kernel range is bit-exact).
- `conformance_diff_fp_exceptions` and `conformance_diff_powf_general` still
  pass (no regression).

## Method

```
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cc \
rch exec -- cargo bench -p frankenlibc-bench --bench exp_log_glibc_bench -- \
  --measurement-time 2 --warm-up-time 1 --noplot
```
(First attempt failed on `ovh-b` with a `zerocopy` build-script SIGILL — a known
bad-worker environment issue, not a code failure; re-run succeeded.)

`logf` remains (needs `__logf_data`); tracked under the same bead.
