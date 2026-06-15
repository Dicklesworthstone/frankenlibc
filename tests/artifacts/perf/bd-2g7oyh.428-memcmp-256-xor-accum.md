# bd-2g7oyh.428 memcmp_256 XOR accumulator keep

Date: 2026-06-15

## Target

Profile target ID: `bd-2g7oyh.428`

The pass 128 broad RCH profile left `glibc_baseline_memcmp_256` as a small but
less-stale string residual after excluding recent `strcpy_4096`, `memmove_4096`,
`memcpy_4096`, `printf_g_6`, and `strpbrk_absent` no-code or rejected lanes.

Broad route row on `ovh-a`:

- FrankenLibC: p50 `6.566 ns/op`, mean `7.722 ns/op`
- host glibc: p50 `4.766 ns/op`, mean `6.011 ns/op`

Prior no-retry families for this lane:

- exact-256 foldback to two 128-byte certificates
- 64-lane rank/select and broadword equality probes
- large-loop folded equality certificate reuse
- cross-crate inline and generic loop unrolling

## Focused RCH Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ovh-a \
RCH_WORKERS=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_BUILD_SLOTS=1 \
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass129-memcmp256-target-20260615T2125 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass129-memcmp256-criterion-20260615T2125 \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 \
  --noplot --sample-size 90 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`, so this became the comparison worker for the pass.

Focused baseline:

- FrankenLibC Criterion: `[4.7291 ns 4.7525 ns 4.7766 ns]`
- FrankenLibC row: p50 `4.729 ns/op`, mean `6.963 ns/op`, p95 `5.625 ns/op`, p99 `25.000 ns/op`
- host glibc Criterion: `[3.3499 ns 3.4312 ns 3.5178 ns]`
- host glibc row: p50 `3.795 ns/op`, mean `5.102 ns/op`, p95 `4.375 ns/op`, p99 `30.000 ns/op`

## One Lever

In `crates/frankenlibc-core/src/string/mem.rs`, change only the exact-256 equal
buffer certificate from four ORed `simd_ne` masks to the XOR/OR accumulator
shape used by the exact-4096 equality certificate:

```rust
let diff = (a0 ^ b0) | (a1 ^ b1) | (a2 ^ b2) | (a3 ^ b3);
diff.simd_ne(Simd::splat(0)).any()
```

The helper still returns only "any byte differs." It never decides ordering.
When any byte differs, `memcmp` falls through to the existing first-difference
resolver.

## Behavior Proof

RCH focused tests:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=512 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass129-memcmp256-proof-target-20260615T2130 \
  cargo test -j 1 -p frankenlibc-core --lib memcmp \
  -- --nocapture --test-threads=1
```

Result: passed on RCH `ovh-a`, 32/32 filtered tests:

- `test_memcmp_exact_256_equal_certificate_guard`
- `memcmp_golden_output_sha256`
- antisymmetry and std-lexicographic property guards
- timingsafe memcmp and wide memcmp guards

RCH property golden:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 \
rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  RUST_TEST_THREADS=1 FRANKENLIBC_PROPTEST_CASES=512 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass129-memcmp256-golden-target-20260615T2130 \
  cargo test -j 1 -p frankenlibc-core --test property_tests \
  golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
```

Result: passed on RCH `vmi1227854`.

Golden hashes:

- `string::mem::tests::memcmp_golden_output_sha256`: `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`
- `string_properties::golden_memcmp_corpus_sha256`: `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`
- `tests/conformance/fixtures/string_ops.json`: `27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89`
- `tests/conformance/fixtures/string_memory_full.json`: `94e8dc73391d2f0d29fa07dc15366150bc015b59ce2d7c2e18ead6373f35b9e4`
- `tests/conformance/fixtures/string_memory_hotpaths.json`: `3dfa8b35df1dcc43244a1c1a9105d6ca44ea418c7b8c4c8db40919867cade170`
- `tests/conformance/fixtures/string_memory_hotpaths_wave10.json`: `65311119dd6d169d9584ed825329f856739cf66b76a1c431eb7417dd56ece845`

Isomorphism:

- Equal exact-256 buffers still return `Ordering::Equal` after the certificate proves all bytes match.
- Non-equal exact-256 buffers still fall through to the existing ordered resolver.
- First-difference tie-breaking, unsigned-byte ordering, `n` clamping, zero-length behavior, FP, RNG, allocation, errno, and locale behavior are unchanged.

## Post Benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 \
RCH_BUILD_SLOTS=1 RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass129-memcmp256-post-target-20260615T2138 \
  CRITERION_HOME=/data/tmp/frankenlibc-pass129-memcmp256-post-criterion-20260615T2138 \
  cargo bench -j 1 -p frankenlibc-bench \
  --bench glibc_baseline_bench -- glibc_baseline_memcmp_256 \
  --noplot --sample-size 90 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854`.

Post result:

- FrankenLibC Criterion: `[4.3757 ns 4.4723 ns 4.5806 ns]`
- FrankenLibC row: p50 `4.573 ns/op`, mean `5.673 ns/op`, p95 `5.764 ns/op`, p99 `30.000 ns/op`
- host glibc Criterion: `[3.2128 ns 3.2561 ns 3.3020 ns]`
- host glibc row: p50 `3.288 ns/op`, mean `4.314 ns/op`, p95 `4.703 ns/op`, p99 `30.000 ns/op`

FrankenLibC self delta:

- p50: `4.729 -> 4.573 ns/op` (`1.03x`, `3.3%` lower)
- mean: `6.963 -> 5.673 ns/op` (`1.23x`, `18.5%` lower)
- Criterion center: `4.7525 -> 4.4723 ns/op` (`1.06x`, `5.9%` lower)

The post row still trails host, so this is not a parity closeout. Reprofile and
route deeper after this commit.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`: passed locally.
- `git diff --check -- crates/frankenlibc-core/src/string/mem.rs`: passed locally.
- RCH `cargo check -j 1 -p frankenlibc-core --all-targets`: passed on `vmi1227854`.
- RCH strict `cargo clippy -j 1 -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated `crates/frankenlibc-core/src/resolv/mod.rs:316` `clippy::explicit_counter_loop`.
- RCH allowlisted `cargo clippy -j 1 -p frankenlibc-core --all-targets -- -D warnings -A clippy::explicit_counter_loop`: passed on `vmi1227854`.

## Verdict

KEPT. Score `(Impact 2.2 x Confidence 4.0) / Effort 1.0 = 8.8`.

Next route: reprofile current head. Do not report `memcmp_256` as closed to
parity; if it remains material, the next primitive must be generated-code or
backend-dispatch work that changes the emitted load/test sequence more deeply.
