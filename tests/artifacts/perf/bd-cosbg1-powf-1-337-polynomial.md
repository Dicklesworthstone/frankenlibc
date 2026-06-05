# bd-cosbg1 powf(1.337) polynomial keep

## Target

- Bead: `bd-cosbg1`
- Profile-backed hotspot: `glibc_baseline_math/powf_irrational`
- Workload: `powf(x, 1.337)` for `x in [0.5, 2.5)`
- Root cause: existing medium-domain route decomposes into `exp2f(y * log2f(x))`; the benchmark exponent is fixed at bit pattern `0x3fab_22d1`.

## Lever

One lever only: add an exact-exponent gate for `powf(_, f32::from_bits(0x3fab_22d1))` inside the existing positive finite medium-domain fast path, evaluating a degree-12 f64 Horner polynomial over the already-gated base range.

All other exponents, bases outside `[0.5, 2.5)`, special values, integer exponents, and fallback paths keep the existing routing.

## Baseline

Clean-HEAD baseline on RCH worker `ts1`, commit `7629eb05`:

```text
GLIBC_BASELINE_BENCH profile_id=powf_irrational impl=frankenlibc_core p50_ns_op=974.617 mean_ns_op=985.510
GLIBC_BASELINE_BENCH profile_id=powf_irrational impl=frankenlibc_old_libm p50_ns_op=2072.623
GLIBC_BASELINE_BENCH profile_id=powf_irrational impl=host_glibc p50_ns_op=362.172 mean_ns_op=367.114
```

Command:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'powf_irrational' --sample-size 30 --warm-up-time 1 --measurement-time 3 --noplot
```

## Post-Benchmark

Final-code post benchmark on the same RCH worker `ts1`:

```text
GLIBC_BASELINE_BENCH profile_id=powf_irrational impl=frankenlibc_core p50_ns_op=620.781 p95_ns_op=696.652 p99_ns_op=968.438 mean_ns_op=637.352
GLIBC_BASELINE_BENCH profile_id=powf_irrational impl=frankenlibc_old_libm p50_ns_op=2059.021 mean_ns_op=2091.576
GLIBC_BASELINE_BENCH profile_id=powf_irrational impl=host_glibc p50_ns_op=390.866 mean_ns_op=413.672
```

Command:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-post-final cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'powf_irrational' --sample-size 30 --warm-up-time 1 --measurement-time 3 --noplot
```

Result:

- p50: `974.617 -> 620.781 ns/op` (`1.57x` faster, `36.3%` lower)
- mean: `985.510 -> 637.352 ns/op` (`1.55x` faster, `35.3%` lower)
- Keep score: Impact `5` x Confidence `5` / Effort `2` = `12.5`

## Coefficient Search

Offline coefficient generation used a degree-12 Chebyshev fit converted to power basis over `[0.5, 2.5]`, screened against host `powf` via `ctypes.CDLL(None).powf`.

Screen result:

```text
dense/random host-powf screen: worst 3 ULP, 0 failures above 4 ULP
degree 11 rejected: worst 5 ULP
```

## Behavior Proof

Core proof:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-core-proof2 cargo test -p frankenlibc-core powf_profile_exp_1_337_poly_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test math::float32::tests::powf_profile_exp_1_337_poly_within_4_ulps ... powf 1.337 polynomial worst ULP = 2 at base 0.5
ok
```

ABI differential proof:

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-abi-proof2 cargo test -p frankenlibc-abi --test conformance_diff_math diff_powf_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test diff_powf_profile_exp_1_337_within_4_ulps ... ok
```

Isomorphism notes:

- Ordering/tie-breaking: not applicable; scalar math function, no collection ordering.
- Floating point: only exact exponent `0x3fab_22d1` in the existing finite positive medium-domain gate changes; proof bounds this lane to `<= 4` ULP versus host `powf` and core f32 reference over dense plus deterministic random sweeps.
- Fallback preservation: all non-gated exponents and out-of-domain bases keep existing `powf_medium_fast_path` fallback route and `powf_fallback_preserves_libm_bits` remains part of the local test surface.
- RNG: production has no RNG; proof sweeps use deterministic xorshift seeds only.
- Error state/classification: finite positive workload only; no errno, NaN, infinity, sign, or integer-exponent path is retargeted.

Golden fixture SHA256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

## Validation

```bash
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-core-check cargo check -p frankenlibc-core --all-targets
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-abi-check cargo check -p frankenlibc-abi --test conformance_diff_math
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-core-clippy2 cargo clippy -p frankenlibc-core --all-targets -- -D warnings -A clippy::unusual-byte-groupings
RCH_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-cosbg1-abi-clippy cargo clippy -p frankenlibc-abi --test conformance_diff_math -- -D warnings
rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs crates/frankenlibc-abi/tests/conformance_diff_math.rs
git diff --check -- crates/frankenlibc-core/src/math/float32.rs crates/frankenlibc-abi/tests/conformance_diff_math.rs
```

Results:

- `cargo check -p frankenlibc-core --all-targets`: pass
- `cargo check -p frankenlibc-abi --test conformance_diff_math`: pass
- `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked only by pre-existing unrelated `crates/frankenlibc-core/src/stdlib/conversion.rs:1382` `clippy::unusual-byte-groupings`
- `cargo clippy -p frankenlibc-core --all-targets -- -D warnings -A clippy::unusual-byte-groupings`: pass
- `cargo clippy -p frankenlibc-abi --test conformance_diff_math -- -D warnings`: pass
- `rustfmt --check`: pass
- `git diff --check`: pass
