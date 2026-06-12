# bd-2g7oyh.353 log2f f32-native route

Date: 2026-06-12
Agent: BoldFalcon
Status: kept

## Target

`glibc_baseline_math/log2f` for `log2f(x)` over `x in [0.5, 2.5)`.

The fresh pass-75 focused gate reproduced a material residual after excluding
peer-owned `strncmp` work and prior rejected math families:

- f64 widening through the in-tree f64 log kernel;
- exponent extraction plus atanh-series profile-band;
- small scalar table/Taylor/DD finalization.

## Focused Baseline

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass75-log2f-baseline-target-20260612T2202 \
CRITERION_HOME=/data/tmp/frankenlibc-pass75-log2f-baseline-criterion-20260612T2202 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/log2f --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| implementation | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC baseline | 394.106 | 367.582 | 413.146 | 417.801 |
| host glibc baseline | 323.307 | 325.578 | 355.500 | 370.291 |

## Lever

One source lever in `crates/frankenlibc-core/src/math/float32.rs`: route
`log2f` through Rust's native `f32::log2` path instead of the prior
`libm::log2f` call.

This is a distinct f32-native computation route from the rejected f64 widening
and profile-band atanh-series attempts. No other math function, fallback gate,
RNG path, ordering rule, or benchmark harness code changed.

## Isomorphism

- Ordering/tie-breaking: none involved.
- RNG/state: none involved.
- Floating point: dense deterministic core proof compares the new path against
  the prior `libm::log2f` route on 1,000,000 values in `[0.5, 2.5)` and bounds
  the delta to `<= 4 ULP`; observed worst case was `1 ULP` at `2.428807`.
- Special cases: `-0.0`, `0.0`, `1.0`, `2.0`, and `+inf` stayed bit-equal to
  the prior route; negative and NaN inputs stayed NaN.
- Golden fixtures: math conformance fixture SHA-256 values were unchanged.

## Proof

Touched-file formatting and whitespace:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs
git diff --check
```

Both passed.

Core ULP proof on RCH `vmi1227854`:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass75-log2f-proof-target-20260612T2208 \
cargo test -j 1 -p frankenlibc-core --lib \
log2f_intrinsic_matches_prior_libm_path_within_4_ulps -- \
--nocapture --test-threads=1
```

Result:

```text
test math::float32::tests::log2f_intrinsic_matches_prior_libm_path_within_4_ulps ... log2f intrinsic worst ULP = 1 at 2.428807
ok
```

Golden fixture SHA-256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

## Same-worker Post

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass75-log2f-post-target-20260612T2212 \
CRITERION_HOME=/data/tmp/frankenlibc-pass75-log2f-post-criterion-20260612T2212 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/log2f --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| implementation | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC post | 328.803 | 334.828 | 390.500 | 475.355 |
| host glibc post control | 331.471 | 341.587 | 380.043 | 471.000 |

The same-worker FrankenLibC result improved:

- p50: `394.106 -> 328.803 ns` (`16.6%` faster)
- mean: `367.582 -> 334.828 ns` (`8.9%` faster)

## Validation

- RCH `vmi1227854` `cargo check -j 1 -p frankenlibc-core --lib`: passed.
- RCH `vmi1227854` strict `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`:
  blocked by unrelated pre-existing lints in `math/exp.rs`, `stdlib/sort.rs`,
  `string/fnmatch.rs`, and `string/regex.rs`.
- RCH `vmi1227854` allowlisted `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings
  -A clippy::excessive_precision -A clippy::collapsible_if -A clippy::manual_contains
  -A clippy::type_complexity -A clippy::unnecessary_map_or`: passed.

Source and harness SHA-256:

```text
ff7b33df842777acd48e5560fd1b27fd9f497607cffaf277a267ccbd7d9cfb5b  crates/frankenlibc-core/src/math/float32.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

## Verdict

KEPT, Score `9.0` (`Impact 3.0 x Confidence 3.0 / Effort 1.0`). The focused
same-worker gate cleared Score >= 2.0 and brought FrankenLibC `log2f` p50 to
parity with the in-run host control.

Next route: close and push this bead, then reprofile. Do not repeat the old
f64 widening, atanh-series, or scalar table/Taylor/DD families. If `log2f`
reappears with a material residual, the next route should be a generated
piecewise minimax/Estrin artifact with a direct lowering proof.
