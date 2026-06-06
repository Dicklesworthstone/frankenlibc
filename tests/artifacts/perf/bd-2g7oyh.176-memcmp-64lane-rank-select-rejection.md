# bd-2g7oyh.176 - memcmp 64-lane rank/select rejection

## Target

- Function: `frankenlibc_core::string::mem::memcmp`
- Workload: `glibc_baseline_memcmp_4096`, equal 4096-byte buffers
- Candidate primitive: safe portable-SIMD 64-byte mismatch bitmask with `to_bitmask()`
  and `trailing_zeros()` first-difference selection.

## Baseline

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-176-baseline \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(memcmp_16|memcmp_256|memcmp_4096|memchr_absent|memmove_4096)' \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

- Worker: `vmi1227854`
- `memcmp_4096` FrankenLibC: p50 `47.750 ns`, mean `49.907 ns`
- `memcmp_4096` host glibc: p50 `41.896 ns`, mean `43.167 ns`

## Proof

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-176-proof \
  FRANKENLIBC_PROPTEST_CASES=4096 \
  cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

Result: passed on `vmi1227854`.

- 29 focused lib tests passed.
- Existing `golden_memcmp_corpus_sha256` passed.
- Candidate-only 4096-byte first-difference SHA corpus passed with scalar-reference
  digest `c40f0d4007aacff23828349af0ddda09658c6ebb6c1ac25c0ec85f09caf2a283`.

Isomorphism:

- Ordering preserved: yes; panels were scanned in increasing address order.
- Tie-breaking/first-difference preserved: yes; `trailing_zeros()` selected the
  lowest differing lane in the first nonzero mismatch mask.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: passed before rejection.

## Post Benchmark

Command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-176-post \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_(memcmp_16|memcmp_256|memcmp_4096|memchr_absent|memmove_4096)' \
  --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

- Worker: `vmi1227854`
- `memcmp_4096` FrankenLibC: p50 `56.910 ns`, mean `59.643 ns`
- `memcmp_4096` host glibc: p50 `43.079 ns`, mean `45.501 ns`

## Verdict

Rejected and source restored.

Score: `(Impact 0 * Confidence 4) / Effort 2 = 0.0`.

Do not retry 64-lane portable-SIMD `to_bitmask()` extraction for the equal
`memcmp_4096` path. The proof was clean, but the mask extraction cost regressed
the primary row. The next `memcmp` attempt needs a different primitive than
loop unrolling, equality certificates, folded-panel widening, or 64-lane
rank/select masks.

## Additional Confirmation

Current-turn same-worker confirmation on `vmi1149989` used a clean detached
worktree at `HEAD=04d92c1c` for baseline and the dirty candidate workspace for
post.

Clean baseline:

- `memcmp_4096` FrankenLibC: p50 `51.281 ns`, mean `52.747 ns`
- `memcmp_4096` host glibc: p50 `37.875 ns`, mean `42.027 ns`

Candidate:

- `memcmp_4096` FrankenLibC: p50 `50.078 ns`, mean `52.537 ns`
- `memcmp_4096` host glibc: p50 `39.364 ns`, mean `40.881 ns`

This confirmation shows only a marginal `2.3%` p50 move and `0.4%` mean move,
also below the keep threshold.
