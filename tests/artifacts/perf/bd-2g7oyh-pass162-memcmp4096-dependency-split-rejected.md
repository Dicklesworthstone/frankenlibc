# bd-2g7oyh.444 - pass162 memcmp_4096 dependency-split rejection

Date: 2026-06-17
Agent: BoldFalcon
Mode: local fallback, because ts1/RCH remote is offline by directive
Head: 780c53296

## Target

Pass 161 routed to `glibc_baseline_memcmp_4096` from the pass 159 broad profile.
The focused local gate reproduced a material gap on the current source, so a
single source candidate was allowed:

| Implementation | Criterion interval | p50 | p95 | p99 | Mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| frankenlibc_core | [55.296, 56.194, 57.232] ns | 56.801 ns | 80.656 ns | 146.039 ns | 61.046 ns |
| host_glibc | [37.800, 38.468, 39.149] ns | 37.879 ns | 45.173 ns | 55.000 ns | 39.147 ns |

Baseline command:

```bash
env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass162-memcmp4096-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass162-memcmp4096-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_4096 --noplot --sample-size 80 --warm-up-time 1 \
  --measurement-time 3
```

Baseline log SHA-256:

```text
18008f15416c49933424edda78ae8c2a1a856d915561ea7dba96185b5f257d3f  /data/tmp/frankenlibc-pass162-memcmp4096-baseline-local.log
```

## Candidate

Rejected source lever: split the exact-4096 equality accumulator into four
independent `Simd<u8, 64>` accumulators per 256-byte stride, then OR the four
accumulators once at the end.

Intent: reduce the long dependency chain in the existing equal-buffer
certificate without changing the public comparison contract. This was a
load/reduction-shape experiment, not a first-difference resolver change.

## Behavior Proof

Commands:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs

env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  FRANKENLIBC_PROPTEST_CASES=512 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass162-proof-target \
  cargo test -j 1 -p frankenlibc-core --lib memcmp -- \
  --nocapture --test-threads=1

env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 RUST_TEST_THREADS=1 \
  FRANKENLIBC_PROPTEST_CASES=512 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass162-proof-target \
  cargo test -j 1 -p frankenlibc-core --test property_tests \
  golden_memcmp_corpus_sha256 -- --nocapture --test-threads=1
```

Results:

- touched-file rustfmt passed.
- focused memcmp unit/property proof passed 32/32 filtered tests, including
  `memcmp_golden_output_sha256`, exact-256 guard, exact-4096 ordering guard,
  timingsafe memcmp, and wide memcmp coverage.
- `string_properties::golden_memcmp_corpus_sha256` passed 1/1.
- existing unrelated warnings remained in `iconv`; no warning came from
  `string/mem.rs`.

Golden hashes covered by those tests:

- `memcmp_golden_output_sha256`:
  `458c0ae019afaffccbfc5a6aacfeb4713dab611eac4b6257398016a7eae45ef9`
- `golden_memcmp_corpus_sha256`:
  `23ff1bb367d74ce77644397fa6f7f2160759f5991d6fb383e89ad5bb6d0b4e5e`

## Candidate Benchmark

Post command matched the baseline sample, warmup, and measurement settings:

```bash
env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass162-memcmp4096-candidate-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass162-memcmp4096-candidate-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcmp_4096 --noplot --sample-size 80 --warm-up-time 1 \
  --measurement-time 3
```

| Implementation | Criterion interval | p50 | p95 | p99 | Mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| candidate frankenlibc_core | [59.390, 61.051, 62.763] ns | 59.518 ns | 75.727 ns | 84.782 ns | 61.515 ns |
| host_glibc | [36.802, 37.454, 38.132] ns | 36.589 ns | 45.934 ns | 55.000 ns | 38.747 ns |

Candidate log SHA-256:

```text
7879c7adcfe8fae091879b92f85e9045045e1835446c0b52bf291db1fa2476e5  /data/tmp/frankenlibc-pass162-memcmp4096-candidate-local.log
```

Candidate delta versus focused baseline:

- p50 regressed `56.801 -> 59.518 ns`.
- mean regressed `61.046 -> 61.515 ns`.
- host also improved slightly in the post run, so host-normalized ratio worsened.

## Isomorphism

- Ordering preserved during the candidate: yes. The changed code only decided
  whether an exact 4096-byte prefix was fully equal; every non-equal case fell
  through to the existing ordered resolver.
- Tie-breaking preserved: yes. First-difference byte order stayed in the
  existing 128-byte, 32-byte, then byte resolver.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: both memcmp golden hashes passed before the post benchmark.

## Verdict

REJECTED-RESTORED. Score: `0.0`.

The candidate preserved behavior but regressed the profiled row. Source was
restored to:

```text
78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d  crates/frankenlibc-core/src/string/mem.rs
```

`git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs` passed
after restore.

## Reroute

Do not retry exact-4096 dependency-split accumulators, superfolds, folded-panel
widening, rank/select, broadword extraction, slice/array equality lowering,
cross-crate inline, chunk cursor, or XOR/test-zero retunes without a new
codegen/assembly artifact that proves a materially different hot loop first.

Next pass should be codegen-first: emit and inspect IR/assembly for the current
exact-4096 path, then only attempt a source lever if the artifact identifies a
new safe-Rust load/test shape that avoids `memcmp`/`bcmp` calls and changes the
current reduction bottleneck.
