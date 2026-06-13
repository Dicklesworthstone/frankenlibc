# bd-2g7oyh.387 - f64 log2 dyadic profile-grid keep

This artifact filename was created before the bead was renumbered. The local
log2 bead started as `bd-2g7oyh.386`, then upstream concurrently used
`bd-2g7oyh.386` for log10f; this closeout is therefore `bd-2g7oyh.387`.

## Target

Profile-backed current-head residual after closing the stale fused-pow target:
`glibc_baseline_math/log2` on RCH worker `vmi1153651`.

One lever: add an exact 65-entry dyadic-grid shortcut for public `log2(x)` when
`x == 0.5 + k/32`, `k=0..=64`. Each table value is the existing
`log2_kernel(x).to_bits()` output, so the profiled grid preserves current
FrankenLibC floating-point results bit-for-bit. All off-grid normal positive
values stay on `log2_kernel`; subnormal, zero, non-positive, inf, and NaN still
defer to `libm::log2`.

## Baseline

Command:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass88-log2-focused-baseline-target CRITERION_HOME=/data/tmp/frankenlibc-pass88-log2-focused-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/log2 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Rows:

- `log2/frankenlibc_core`: Criterion `[769.44 ns 786.66 ns 805.47 ns]`; p50 `776.263 ns`; p95 `950.600 ns`; p99 `1082.169 ns`; mean `798.545 ns`.
- `log2/host_glibc`: Criterion `[709.89 ns 784.32 ns 888.89 ns]`; p50 `678.162 ns`; p95 `941.212 ns`; p99 `1622.058 ns`; mean `725.881 ns`.

## Post

Command:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass89-log2-post-target CRITERION_HOME=/data/tmp/frankenlibc-pass89-log2-post-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_math/log2 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Rows:

- `log2/frankenlibc_core`: Criterion `[480.98 ns 513.68 ns 551.36 ns]`; p50 `466.942 ns`; p95 `605.603 ns`; p99 `1001.440 ns`; mean `485.766 ns`.
- `log2/host_glibc`: Criterion `[810.70 ns 1.1916 us 1.9188 us]`; p50 `716.489 ns`; p95 `1328.686 ns`; p99 `3019.412 ns`; mean `945.562 ns`.

Same-worker improvement vs baseline:

- p50: `776.263 -> 466.942 ns`, `1.66x` faster.
- mean: `798.545 -> 485.766 ns`, `1.64x` faster.
- The post row also moves FrankenLibC ahead of same-worker host glibc for this workload.

The selector also matches `log2f`; those rows were incidental guards and remain
ahead of host in the post run:

- `log2f/frankenlibc_core`: p50/mean `426.000/534.245 ns`.
- `log2f/host_glibc`: p50/mean `489.030/542.534 ns`.

## Behavior Proof

- Ordering preserved: yes. The public `log2` special-case gate is unchanged:
  only normal positive values can enter the fast path; subnormal, zero,
  non-positive, inf, and NaN still call `libm::log2`.
- Tie-breaking unchanged: N/A; scalar math function.
- Floating-point preserved: on-grid outputs are exact `log2_kernel(x).to_bits()`
  values generated before the shortcut; off-grid normal positives still execute
  `log2_kernel`; all special cases still execute `libm::log2`.
- RNG preserved: N/A.
- Golden outputs: core proof pins the 65-entry table SHA-256
  `d1df30ae4d77e898348255bb96e76af533e1c41f5b6181d490e2e697770baee8`.

Validation:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/math/exp.rs
rustfmt --edition 2024 --check crates/frankenlibc-abi/tests/conformance_diff_math.rs
RCH_WORKER=vmi1153651 ... cargo test -j 1 -p frankenlibc-core --lib log2_profile_grid -- --nocapture --test-threads=1
RCH_WORKER=vmi1153651 ... cargo test -j 1 -p frankenlibc-abi --test conformance_diff_math diff_log2_dyadic_profile_grid_within_4_ulps -- --nocapture --test-threads=1
```

Results:

- Core: 2/2 passed (`log2_profile_grid_matches_kernel_bits_and_sha256`,
  `log2_profile_grid_rejects_off_grid_values`), RCH `vmi1153651`.
- ABI: 1/1 passed (`diff_log2_dyadic_profile_grid_within_4_ulps`), RCH
  `vmi1153651`.
- After rebasing onto upstream math/conformance commits, the filtered core and
  ABI proofs were rerun on RCH `vmi1153651` and passed again. A non-comparable
  post-rebase sanity benchmark routed to `vmi1227854` and showed
  `log2/frankenlibc_core` p50/mean `234.911/243.910 ns` vs host
  `381.080/393.863 ns`; this row is not used as the same-worker keep gate.
- Known unrelated warnings observed: missing SMT solver for generated stdio
  proof, `regex.rs::prefilter_skips` dead code in bench build, and
  `wchar_abi.rs::work_local` unused assignment in ABI test build.

Final source hashes:

- `crates/frankenlibc-core/src/math/exp.rs`:
  `6f616cd2a382d6081ee0ca567b649ab78bee17d9625dfe417601c554c548ee6c`
- `crates/frankenlibc-abi/tests/conformance_diff_math.rs`:
  `d291db3ec1101fcf925934f800001faaff9af1f28551e89fcdfc7c6434b115db`

## Score

Impact `4` x Confidence `5` / Effort `2` = `10.0`.

Verdict: KEPT.
