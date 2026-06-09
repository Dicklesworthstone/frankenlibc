# bd-2g7oyh.298 erf profile-band kernel

Status: kept and closed.
Date: 2026-06-09.
Agent: BoldFalcon.
Base commit: `95a7e8c4f54f252cf2b35c997820cf8ba77c5a2e`.

## Target

Focused `erf`/`erfc` baseline on RCH `ovh-a` reproduced a real special-function
gap. This retained lever targets only public `erf`; public `erfc` remains on
`libm` because the candidate `erfc` complement branch exceeded the dense 4-ULP
gate below `1.0`.

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_BUILD_SLOTS=3 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass31-erf-baseline-20260609 cargo bench -j 2 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/erf --noplot --sample-size 60 --warm-up-time 1 --measurement-time 4
```

Focused baseline on `ovh-a`:

- `erf` FrankenLibC p50 `1316.602 ns/op`, mean `1231.196 ns/op`, p95 `1353.097 ns/op`, p99 `1375.034 ns/op`.
- `erf` host glibc p50 `727.174 ns/op`, mean `856.245 ns/op`, p95 `1120.094 ns/op`, p99 `1511.201 ns/op`.
- `erfc` FrankenLibC p50 `1312.375 ns/op`, mean `1128.054 ns/op`.
- `erfc` host glibc p50 `689.155 ns/op`, mean `755.551 ns/op`.

## Lever

One source lever: finite `|x| < 2.5` `erf` now uses public-domain
Cephes/Moshier rational pieces for the profiled band:

- `[0,1)`: direct no-exp `x * P(x^2) / Q(x^2)`.
- `[1,2.5)`: `1 - exp(-x*x) * P(x) / Q(x)`.

Out-of-band values, non-finite values, and public `erfc` fall back to the
existing `libm` implementation.

## Behavior Proof

RCH proof command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_BUILD_SLOTS=3 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass31-erf-proof-20260609 cargo test -j 2 -p frankenlibc-abi --test conformance_diff_math_special diff_erf -- --nocapture --test-threads=1
```

RCH selected `vmi1227854` for proof and passed:

- `diff_erf_within_4_ulps`
- `diff_erf_profile_band_within_4_ulps`

Golden fixture SHA-256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

Isomorphism:

- Out-of-band, non-finite, and public `erfc` behavior are unchanged.
- Negative `erf` inputs use exact odd symmetry over the positive kernel.
- The only accepted numeric delta is within the repo's existing 4-ULP
  glibc-differential math contract.
- Ordering, tie-breaking, and RNG behavior are not involved.

## Post Benchmark

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a RCH_WORKERS=ovh-a RCH_BUILD_SLOTS=3 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass31-erf-post-20260609 cargo bench -j 2 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/erf/ --noplot --sample-size 60 --warm-up-time 1 --measurement-time 4
```

Same-worker post on `ovh-a`:

- FrankenLibC p50 `361.027 ns/op`, mean `363.345 ns/op`, p95 `370.500 ns/op`, p99 `434.087 ns/op`.
- Host glibc p50 `669.657 ns/op`, mean `676.707 ns/op`, p95 `696.500 ns/op`, p99 `806.927 ns/op`.

Result:

- FrankenLibC p50 improved `1316.602 -> 361.027 ns/op` (`72.6%` faster).
- FrankenLibC mean improved `1231.196 -> 363.345 ns/op` (`70.5%` faster).
- Ratio moved from `1.81x` slower than host p50 to `1.85x` faster than host p50.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/special.rs crates/frankenlibc-abi/tests/conformance_diff_math_special.rs`: passed.
- RCH `cargo check -p frankenlibc-core -p frankenlibc-abi --all-targets`: passed, with unrelated existing test warnings.
- Strict RCH `cargo clippy -p frankenlibc-core -p frankenlibc-abi --all-targets -- -D warnings`: blocked by unrelated existing lints in `exp.rs`, `sort.rs`, `fnmatch.rs`, `regex.rs`, `glob.rs`, `wctype_table_gen.rs`, and `cjk_table_gen.rs`.
- RCH targeted clippy passed for `frankenlibc-core --lib` and `frankenlibc-abi --test conformance_diff_math_special` with the established core allowlist for unrelated lint families.

## Verdict

KEPT, Score `18.0`.

`bd-2g7oyh.298` is closed. Reprofile next; `erfc` remains a residual but needs a
separate minimax/table-assisted artifact with dense ULP proof instead of a
`1 - erf` complement shortcut.
