# bd-2g7oyh.383 exp10f profile-band f32 route

Date: 2026-06-13
Agent: BoldFalcon

## Target

`glibc_baseline_math/exp10f/` on `[0.5, 2.5)` from the open `bd-2g7oyh.383`
tracker entry. The current implementation already has a f64 table/residual
profile-band kernel, so the tested lever was a structurally different bounded
f32 route:

- keep exact integer `powi` fast path unchanged
- keep out-of-band f64 `exp2` fallback unchanged
- use `libm::exp2f(x * LOG2_10)` in the profile band, with the minimum
  correction needed to satisfy the existing 4-ULP contract

## Baseline

Focused baseline before edits, remote rch, worker `vmi1153651`:

- command: `cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/exp10f/' --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3`
- FrankenLibC Criterion: `[636.65 ns 674.25 ns 720.80 ns]`
- FrankenLibC profile row: p50 `607.088 ns`, mean `658.606 ns`
- host glibc Criterion: `[486.47 ns 500.65 ns 516.04 ns]`
- host glibc profile row: p50 `478.732 ns`, mean `489.702 ns`

Same-worker control baseline for the candidate worker, remote rch, worker
`vmi1227854`, clean worktree at `290c2258d`:

- FrankenLibC Criterion: `[262.07 ns 266.64 ns 271.47 ns]`
- FrankenLibC profile row: p50 `258.638 ns`, mean `262.987 ns`
- host glibc Criterion: `[314.44 ns 317.61 ns 320.92 ns]`
- host glibc profile row: p50 `324.839 ns`, mean `324.552 ns`

## Candidate Proof

Raw f32 route failed the 4-ULP contract:

- `exp10f(2.4858856)=306.11557` vs glibc `306.11572`, `5 ULP`
- golden candidate SHA: `3f78266e9d6c4bc648fd6b5001c44c6e315e7e542c3647a7bce48ac179677557`

One-ULP correction still failed:

- `exp10f(2.400743)=251.6187` vs glibc `251.61877`, `5 ULP`
- golden candidate SHA: `c22b8f409c2d486889b8e2f5a2072f9fbf63374acebe15629a66e59e968339d1`

Two-ULP correction overshot:

- `exp10f(1.4659023)=29.234955` vs glibc `29.234945`, `5 ULP`
- golden candidate SHA: `6e5787f5f66f8a9e0e6573a434b1b5afa517242dcc3138193ea13628948d74d2`

Piecewise candidate (`f32+1ULP` below `2.25`, f64 fallback at/above `2.25`)
passed behavior proof:

- core filtered tests on rch `vmi1227854`: `4 passed`
- worst profile-band ULP: `4` at `2.0885048`
- fallback-bit preservation: passed
- ABI/glibc differential: `diff_exp10f_within_4_ulps` passed on rch `vmi1227854`
- golden SHA: `d8f3d4e893d4683c0a3c0d304c1d548af679d2dbe28dd7bb7fb1f137c74ecdc2`

Isomorphism notes:

- exact integer exponents are checked before the profile-band helper, unchanged
- inputs outside `[0.5, 2.5]` use the pre-existing f64 fallback, unchanged
- profile-band FP contract remains <=4 ULP vs glibc for finite f32 inputs
- no ordering, tie-breaking, errno, RNG, or allocation behavior is involved

## Post Benchmark And Decision

Candidate post benchmark, remote rch, worker `vmi1227854`:

- FrankenLibC Criterion: `[252.49 ns 260.94 ns 270.89 ns]`
- FrankenLibC profile row: p50 `288.310 ns`, mean `295.374 ns`
- host glibc Criterion: `[322.44 ns 324.58 ns 327.07 ns]`
- host glibc profile row: p50 `329.398 ns`, mean `337.350 ns`

Same-worker decision:

- control current-head FL p50/mean: `258.638/262.987 ns`
- candidate FL p50/mean: `288.310/295.374 ns`
- result: candidate regressed current-head p50 by `11.47%` and mean by `12.31%`
- Score: `0.0` (`Impact 0 x Confidence 5 / Effort 2`)

Rejected and restored. `git diff -- crates/frankenlibc-core/src/math/float32.rs
crates/frankenlibc-abi/tests/conformance_diff_math.rs` is empty after restore.

## Next Route

Do not retry scalar `exp2f(x * LOG2_10)` nudging in this band. The current f64
table/residual kernel is already faster on the same worker. The next primitive
should be a generated proof-carrying f32 table/minimax kernel with explicit
Remez coefficients and a full error-sign map, or a fused shared exp10f/expf
kernel that removes the remaining libm dependency without relying on post-hoc
ULP nudges.
