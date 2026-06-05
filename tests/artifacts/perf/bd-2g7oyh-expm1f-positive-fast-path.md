# expm1f positive-medium fast path keep

Date: 2026-06-05
Agent: BlackThrush
Parent bead: bd-2g7oyh
Residual source bead: bd-um6xoq (closed concurrently before this keep landed)

## Target

`glibc_baseline_math/expm1f` profiles `expm1f(x)` for `x in [0.5, 2.5)`.
The pre-change implementation delegated every case to `libm::expm1f`.

Alien primitive: cancellation-aware gated reroute.  For positive-medium inputs,
`expf(x) - 1.0` avoids near-zero cancellation, reuses the existing optimized
`expf` path, and preserves all fallback cases bit-for-bit through `libm::expm1f`.

## Same-worker benchmark

All numbers below are Criterion rows via `rch` on worker `ts2`, with
`FRANKENLIBC_BENCH_PIN=1` and the exact patch applied in a clean detached
worktree at `HEAD=4e1193f3`.

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-um6xoq-expm1f-head-baseline-ts2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/expm1f' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Baseline:

```text
frankenlibc_core p50_ns_op=834.992 p95_ns_op=911.500 p99_ns_op=996.154 mean_ns_op=860.992
host_glibc       p50_ns_op=524.410 p95_ns_op=562.271 p99_ns_op=647.437 mean_ns_op=532.402
```

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-expm1f-clean-post-ts2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench 'glibc_baseline_math/expm1f' -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Post:

```text
frankenlibc_core p50_ns_op=324.089 p95_ns_op=337.746 p99_ns_op=343.931 mean_ns_op=325.431
host_glibc       p50_ns_op=526.309 p95_ns_op=620.547 p99_ns_op=791.000 mean_ns_op=540.272
```

Win:

```text
p50 834.992 -> 324.089 ns, 2.58x faster
mean 860.992 -> 325.431 ns, 2.65x faster
frankenlibc after/host p50 ratio = 0.62x
Score = Impact 3 x Confidence 3 / Effort 1 = 9.0
```

## Behavior proof

Isomorphism:

- Ordering and tie-breaking: no ordering-dependent behavior is introduced.
- Floating point: only finite `x in [0.5, 2.5]` uses `expf(x) - 1.0`; this
  gated interval avoids near-zero cancellation. A 1,000,000-point deterministic
  xorshift sweep stayed within 3 ULP against Rust/glibc-compatible `exp_m1`.
- Fallback: all outside-gate, zero, negative, infinity, and NaN cases continue
  through `libm::expm1f`; fallback test checks exact bits except NaN payload.
- RNG: proof uses deterministic fixed-seed xorshift only; runtime has no RNG.

Proof commands:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/float32.rs crates/frankenlibc-abi/tests/conformance_diff_math.rs
git diff --check -- crates/frankenlibc-core/src/math/float32.rs crates/frankenlibc-abi/tests/conformance_diff_math.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-expm1f-clean-core-tests cargo test -p frankenlibc-core --lib expm1f_ -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-expm1f-clean-abi-tests cargo test -p frankenlibc-abi --test conformance_diff_math diff_expm1f_positive_medium_within_4_ulps -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-expm1f-clean-core-check cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_PREFERRED_WORKER=ts2 rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-expm1f-clean-abi-check cargo check -p frankenlibc-abi --test conformance_diff_math
```

Proof results:

```text
core expm1f tests: 2 passed; worst positive fast-path ULP = 3
ABI glibc differential: 1 passed
core cargo check all-targets: passed
ABI conformance_diff_math cargo check: passed
```

Targeted clippy was attempted and failed on existing unrelated lints outside
this patch:

```text
cargo clippy -p frankenlibc-core --lib -- -D warnings
  existing regex.rs question_mark/too_many_arguments/collapsible_if lints
  existing wide.rs question_mark lints

cargo clippy -p frankenlibc-abi --test conformance_diff_math --no-deps -- -D warnings
  existing stdio_abi.rs collapsible_if lint
```

## Golden hashes

No fixture files were changed. Hashes from the exact-patch worktree:

```text
4a874f4d7301bc9de1b5a602c5d8c28ca6b92d39dddf6d347ca9a5e432fc2a35  tests/conformance/fixtures/math_ops.json
269202b7c609d7906f7c0012cecca2c341d3ab1390a5750b483dcc3a9ae8435f  tests/conformance/fixtures/math_finite_special_wave02.json
acdf0c472bbbdaad2534ac3380b3c3fcb901a5095bb7e160aab1b55b25439491  tests/conformance/fixtures/math_finite_special_wave03.json
8c8106b2e5a6a34465389266dee320315101161daeb2c86538ce01479451cc5e  crates/frankenlibc-core/src/math/float32.rs
6a5502f21d9fb870ebdb3d0960b170d5f9a72ca78c75693779e73cdc9f48480b  crates/frankenlibc-abi/tests/conformance_diff_math.rs
```
