# bd-2g7oyh.417 - memchr_absent folded-block widening rejection

## Target

- Profile row: `glibc_baseline_memchr_absent`
- Worker: `ovh-a`
- Source commit before candidate: `b77c59a12aa9a69ca3a575b1bf98da9463f9f613`
- Broad routing evidence after `bd-2g7oyh.416`: FrankenLibC p50/mean `27.279/28.951 ns` vs host glibc `18.389/24.399 ns`.
- Alien primitive screen: SIMD metadata/group-probe style negative certificate, widening the absent-heavy control reduction from 256-byte groups to 512-byte groups while preserving ordered low-to-high resolver semantics.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=ovh-a RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-417-baseline-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-417-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion `[28.988 ns 31.180 ns 33.255 ns]`, p50/mean `26.771/28.886 ns`
- Host glibc Criterion `[18.413 ns 18.531 ns 18.684 ns]`, p50/mean `18.647/20.036 ns`

## Candidate

One source lever in `crates/frankenlibc-core/src/string/mem.rs`:

- `MEMCHR_FOLD_BYTES` changed from `SIMD_LANES * MEMCHR_FOLD_PANELS` (`256`) to `MEMCHR_WIDE_LANES * MEMCHR_FOLD_PANELS` (`512`).
- `has_byte_memchr_folded` widened from four 64-byte SIMD equality panels to eight 64-byte panels before the horizontal `any()`.
- Positive blocks still resolved through the existing low-to-high 32-byte `first_byte_simd_32` loop, preserving first-match ordering and exact index semantics.

## Behavior Proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=ovh-a RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-417-proof-target cargo test -j 1 -p frankenlibc-core --lib memchr -- --nocapture --test-threads=1
```

Result: passed 10/10 filtered memchr/wmemchr tests, including:

- `string::mem::tests::memchr_golden_output_sha256`
- `string::mem::tests::prop_memchr_matches_scalar_position`
- folded-block first-match tests

Golden SHA remained `04930b6afad5d9eb3047ad0fd21c4db13061e93ee506bcf740787790f8ae3500`.

Isomorphism: first-match ordering, absent result, clamped `n`, no-read-past-slice behavior, pointer-index semantics, FP/RNG/allocation/errno behavior are unchanged.

## Post Benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_WORKER=ovh-a RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-417-post-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-417-post-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memchr_absent --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Result:

- Candidate FrankenLibC Criterion `[28.921 ns 29.032 ns 29.153 ns]`, p50/mean `28.947/29.830 ns`
- Host glibc Criterion `[17.834 ns 17.883 ns 17.940 ns]`, p50/mean `17.906/20.197 ns`

## Verdict

Rejected and restored.

- FrankenLibC p50 regressed `26.771 -> 28.947 ns`.
- FrankenLibC mean regressed `28.886 -> 29.830 ns`.
- Score: `0.0`
- Restored `crates/frankenlibc-core/src/string/mem.rs` to SHA256 `da6e98c17b996e9d3fc546f88c5a5216a6727833679061b668a3fd555551fb6c`; `git diff -- crates/frankenlibc-core/src/string/mem.rs` is empty.

Do not retry wider folded `memchr` block sizes on this row. A future `memchr_absent` pass needs a different generated-code or backend-dispatch primitive, not another 256/512/1024-byte reduction-width change.
