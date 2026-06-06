# bd-2g7oyh.173 - memcmp 512-byte folded block rejection

## Target

- Bead: `bd-2g7oyh.173`
- Function family: `memcmp_4096`
- Source scope tested: `crates/frankenlibc-core/src/string/mem.rs`
- Comparable benchmark worker: `ts1`

## Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass2-profile cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcpy_4096|memmove_4096|memset_4096|memchr_absent|memcmp_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

RCH selected `ts1`. Fresh pre-edit rows:

- `memcmp_4096`: Franken p50 `62.019 ns`, mean `63.336 ns`; host p50 `43.634 ns`, mean `48.224 ns`
- `memchr_absent`: Franken p50 `33.416 ns`, mean `35.472 ns`; host p50 `24.449 ns`, mean `26.982 ns`
- `memmove_4096`: Franken p50 `43.978 ns`, mean `46.450 ns`; host p50 `38.672 ns`, mean `44.559 ns`

The top unowned target was `memcmp_4096`, a `1.42x` p50 / `1.31x` mean residual against host glibc.

## Candidate Lever

The candidate unrolled the existing `memcmp` folded equality scan:

- Process 512 bytes at a time as four 128-byte folded blocks.
- Reuse the existing 128-byte SIMD folded probe for each block.
- Resolve any non-equal block in increasing 128-byte block order, then 32-byte panel order, then byte order.

This intentionally avoided the prior exact-16 and exact-256 top-level equality branches. It targeted loop/control overhead in the equal-buffer path without changing first-difference semantics.

## Behavior Proof

Local checks:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs .beads/issues.jsonl .skill-loop-progress.md
```

Remote focused test:

```text
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_PROPTEST_CASES=512 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd173-proof cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1
```

RCH routed the proof to `vmi1264463`. The run passed 29 focused `memcmp`-filtered unit tests plus property tests, including:

- `small_memcmp_matches_scalar`
- `test_memcmp_preserves_first_difference_inside_bulk_chunk`
- `test_memcmp_preserves_ordering_after_equal_prefix`
- `golden_memcmp_corpus_sha256`
- `prop_memcpy_then_memcmp_is_zero`

Isomorphism notes:

- Ordering and tie-breaking: preserved. The candidate walked blocks in increasing address order and delegated every non-equal block to the existing first-difference byte resolver.
- Floating point: not applicable.
- RNG: not applicable.
- Golden-output SHA: unchanged by focused proof run.

## Post Benchmarks

Primary post command:

```text
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd173-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcmp_4096|memchr_absent|memmove_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Primary post rows on `ts1`:

- `memcmp_4096`: Franken p50 `59.498 ns`, mean `62.380 ns`; host p50 `37.925 ns`, mean `40.033 ns`
- `memmove_4096`: Franken p50 `40.713 ns`, mean `45.593 ns`; host p50 `37.000 ns`, mean `50.807 ns`
- `memchr_absent`: Franken p50 `24.112 ns`, mean `25.551 ns`; host p50 `21.137 ns`, mean `22.917 ns`

Confirmation post command:

```text
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd173-post-confirm cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcmp_4096|memchr_absent|memmove_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Confirmation rows on `ts1`:

- `memcmp_4096`: Franken p50 `61.192 ns`, mean `62.969 ns`; host p50 `38.428 ns`, mean `40.434 ns`
- `memmove_4096`: Franken p50 `43.691 ns`, mean `45.963 ns`; host p50 `38.402 ns`, mean `42.431 ns`
- `memchr_absent`: Franken p50 `25.606 ns`, mean `30.945 ns`; host p50 `21.385 ns`, mean `22.891 ns`

## Verdict

Rejected and source restored.

The primary post was positive but weak, and the confirmation mostly collapsed:

- Baseline `memcmp_4096`: p50 `62.019 ns`, mean `63.336 ns`
- Best post: p50 `59.498 ns` (`4.1%` faster), mean `62.380 ns` (`1.5%` faster)
- Confirmation post: p50 `61.192 ns` (`1.3%` faster), mean `62.969 ns` (`0.6%` faster)

Score: `(Impact 1 * Confidence 2) / Effort 2 = 1.0`, below the keep threshold of `2.0`.

Next `memcmp_4096` work should not retry loop unrolling or broader equality-certificate branches. The next primitive should be a true mask-producing first-difference/rank-select extractor or a different memory-layout/scan strategy that reduces both equality and mismatch resolution cost.
