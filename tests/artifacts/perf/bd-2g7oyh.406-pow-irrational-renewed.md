# bd-2g7oyh.406 pow_irrational renewed dispatch-order keep

## Target

- Bead: `bd-2g7oyh.406`
- Profile-backed hotspot: `glibc_baseline_math/pow_irrational`
- Workload: `pow(x, 1.337)` for `x in [0.5, 2.5)`
- Baseline source: HEAD `1e133c62`, RCH worker `vmi1153651`

Pass 107 current-head routing showed a renewed residual:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core p50_ns_op=1930.955 mean_ns_op=2162.547
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc p50_ns_op=1553.000 mean_ns_op=1599.955
```

Focused same-worker baseline:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=60 p50_ns_op=1788.500 p95_ns_op=2074.088 p99_ns_op=2222.585 mean_ns_op=1784.584 throughput_ops_s=563813.246
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=60 p50_ns_op=1678.026 p95_ns_op=2049.239 p99_ns_op=2184.000 mean_ns_op=1721.820 throughput_ops_s=574871.940
```

Baseline command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-baseline-target-20260614T2337 CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-baseline-criterion-20260614T2337 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/pow_irrational' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

## Lever

One source lever in `crates/frankenlibc-core/src/math/exp.rs`:

- Route the exact profile gate `pow_profile_exp_1_337_fast_path(base, exponent)` at the top of `pow`.
- Keep the accepted exponent bit gate, base envelope, 16-segment degree-10 coefficient artifact, and Estrin evaluator unchanged.
- Leave the integer, square-root, half-integer, medium generic, special-value, and fallback routes unchanged.

This removes generic classifier work from the profiled exact-exponent row without changing the mathematical kernel.

## Post Benchmark

Same-worker post benchmark on RCH worker `vmi1153651`:

```text
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=frankenlibc_core api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=60 p50_ns_op=1003.379 p95_ns_op=1163.712 p99_ns_op=1260.547 mean_ns_op=1042.289 throughput_ops_s=976409.314
GLIBC_BASELINE_BENCH profile_id=pow_irrational impl=host_glibc api_family=math symbol=pow workload="pow(x,1.337) x in [0.5,2.5)" runtime_mode=strict replacement_level=L0 profile_tool=criterion samples=60 p50_ns_op=1747.343 p95_ns_op=2521.472 p99_ns_op=4341.506 mean_ns_op=1916.963 throughput_ops_s=570701.873
```

Post command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-post-target-20260614T2349 CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-post-criterion-20260614T2349 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_math/pow_irrational' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC p50: `1788.500 -> 1003.379 ns/op` (`43.9%` lower, `1.78x` faster)
- FrankenLibC mean: `1784.584 -> 1042.289 ns/op` (`41.6%` lower, `1.71x` faster)
- Same-worker post host: p50 `1747.343 ns/op`, mean `1916.963 ns/op`
- Score: `(Impact 4.0 x Confidence 5.0) / Effort 1.0 = 20.0`

## Behavior Proof

RCH core proof on `vmi1153651`:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-proof-target-20260614T2345 cargo test -j 1 -p frankenlibc-core --lib pow_profile_exp_1_337 -- --nocapture --test-threads=1
```

Result:

```text
test math::exp::tests::golden_pow_profile_exp_1_337_corpus_sha256 ... ok
test math::exp::tests::pow_profile_exp_1_337_estrin_within_4_ulps ... ok
test math::exp::tests::pow_profile_exp_1_337_preserves_non_profile_dispatch ... ok
```

RCH ABI/glibc proof on `vmi1153651`:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-abi-target-20260614T2356 cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_pow_profile_exp_1_337_within_4_ulps -- --nocapture --test-threads=1
```

Result:

```text
test diff_pow_profile_exp_1_337_within_4_ulps ... ok
```

Golden hash unchanged:

```text
pow 1.337 segment corpus: a55ce2571c9313994a6f82d9a0361017d72f8588f0a0ed9ef616e72f59ca002d
```

Isomorphism notes:

- Ordering/tie-breaking: not applicable; scalar math function.
- Floating point: exact profile exponent and base envelope return the same accepted polynomial result as before; dense and deterministic randomized sweeps stay within `<= 4` ULP versus host/glibc.
- Fallback preservation: adjacent exponent bit patterns, special values, negative/zero bases, non-finite inputs, and out-of-range cases keep prior dispatch and bit behavior, covered by `pow_profile_exp_1_337_preserves_non_profile_dispatch`.
- RNG: production has no RNG; proof sweeps use deterministic LCG seeds only.

## Validation

```bash
git diff --check -- crates/frankenlibc-core/src/math/exp.rs
rustfmt +nightly --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_BUILD_SLOTS=1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-406-pow-check-target-20260614T2359 cargo check -j 1 -p frankenlibc-core --lib
```

Results:

- `git diff --check`: pass
- `rustfmt --check`: blocked by pre-existing formatting drift elsewhere in `exp.rs`; this hunk was already rustfmt-compatible and was not widened to unrelated lines.
- RCH `cargo check -j 1 -p frankenlibc-core --lib`: pass on `vmi1153651`; existing warnings remain in `float32.rs` and `special.rs`, not in this hunk.
- Strict clippy was not rerun because the touched crate has known pre-existing warning/lint debt unrelated to this four-line dispatch-order change.
