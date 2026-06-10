# bd-2g7oyh.315 tanhf profile-band f32 expf reroute

Date: 2026-06-10
Agent: BoldFalcon
Scope: `frankenlibc-core` f32 math + ABI differential proof

## Target

`bd-2g7oyh.315` was opened after the pass-40 `memmove_4096` focused gate
collapsed. Prior math routing evidence (`bd-um6xoq` log-route rejection)
identified `tanhf` and `expm1f` as remaining f32 special-function residuals
after f32 log-family reroutes were rejected. The focused target here is
`glibc_baseline_math/tanhf` over `x in [0.5,2.5)`.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd315-tanhf-baseline-target-20260610T052939Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd315-tanhf-baseline-criterion-20260610T052939Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/tanhf --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 396.122 | 389.124 | 414.231 | 464.609 |
| host glibc | 335.046 | 334.651 | 349.558 | 353.987 |

Focused same-worker gap: `1.18x` p50 and `1.16x` mean.

## Lever

Before this change, the profiled `tanhf` band used the stable identity
`tanh(x) = (e^(2x) - 1) / (e^(2x) + 1)` but widened to the f64 in-tree `exp`
kernel and rounded back to f32. The kept lever keeps the exact same profiled
domain, identity, and fallback boundary, but evaluates `e^(2x)` through the
existing f32 `expf` fast path:

```rust
let u = expf(2.0 * x);
return (u - 1.0) / (u + 1.0);
```

This avoids widening through the f64 exp kernel while preserving the
cancellation guard: the route is used only when `0.5 <= |x| <= 2.5`; near-zero,
large, and non-finite values still defer to `libm::tanhf`.

## Isomorphism

- Ordering/tie-breaking: none involved.
- RNG/state: none involved.
- Floating point: same hyperbolic identity, same signed-domain gate, same
  fallback for near-zero, large, and non-finite values.
- Rounding contract: dense core and ABI differentials prove the changed band is
  within the existing 4-ULP glibc/libm parity budget.
- Golden fixtures: math conformance fixture SHA-256 values are unchanged.

## Proof

Touched-file formatting and whitespace:

```text
rustfmt --edition 2024 --check \
  crates/frankenlibc-core/src/math/float32.rs \
  crates/frankenlibc-abi/tests/conformance_diff_math_special.rs
git diff --check -- \
  crates/frankenlibc-core/src/math/float32.rs \
  crates/frankenlibc-abi/tests/conformance_diff_math_special.rs
```

Both passed. Workspace `cargo fmt --check` is blocked by broad pre-existing
formatting drift in unrelated files and scratch tests, so the format gate was
narrowed to touched files.

Core ULP proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CARGO_BUILD_JOBS' \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd315-tanhf-proof-target-20260610T053453Z \
cargo test -j 1 -p frankenlibc-core --lib tanhf_fast_path_within_4_ulps -- \
--nocapture --test-threads=1
```

Result: `test math::float32::tests::tanhf_fast_path_within_4_ulps ... ok`.

ABI glibc differential proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CARGO_BUILD_JOBS' \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd315-tanhf-abi-proof-target-20260610T054311Z \
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math_special \
diff_tanhf_profile_band_within_4_ulps -- --nocapture --test-threads=1
```

Result: `test diff_tanhf_profile_band_within_4_ulps ... ok`.

Golden fixture SHA-256:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
```

## Same-worker Post

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd315-tanhf-post-target-20260610T053736Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd315-tanhf-post-criterion-20260610T053736Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_math/tanhf --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `vmi1227854`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 313.836 | 312.681 | 402.252 | 468.708 |
| host glibc | 342.391 | 353.584 | 414.474 | 467.807 |

FrankenLibC improved `20.8%` p50 and `19.6%` mean versus the same-worker
baseline, and the focused band moved from slower than host to faster than host
in both p50 and mean on the post control.

## Verdict

Kept, Score `6.0`.

Next route: reprofile. If f32 special functions remain hot, attack the next
profile-backed residual such as `expm1f` with a proof-carrying reduced-domain
artifact rather than widening this `tanhf` gate without new dense glibc evidence.
