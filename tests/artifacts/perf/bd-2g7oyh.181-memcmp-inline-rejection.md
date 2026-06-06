# bd-2g7oyh.181: memcmp_4096 cross-crate inline visibility rejected

## Target

- Bead: `bd-2g7oyh.181`
- Profile-backed hotspot: `glibc_baseline_memcmp_4096`
- Shifted profile worker: `ts1`
- Shifted profile row after `54126e7c`: FrankenLibC p50 `72.698 ns`, mean `74.438 ns`; host glibc p50 `52.831 ns`, mean `58.444 ns`.
- Single lever tested: add `#[inline(always)]` to `frankenlibc_core::string::mem::memcmp`, exposing the existing vectorized kernel across crate boundaries without changing the algorithm.

## Behavior proof

- Formatting:
  `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs`
- Whitespace:
  `git diff --check`
- RCH proof command:
  `RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-181-proof FRANKENLIBC_PROPTEST_CASES=4096 cargo test -p frankenlibc-core memcmp -- --nocapture --test-threads=1`
- Proof result: passed 29 focused `memcmp`/`wmemcmp`/timingsafe lib tests plus property tests.
- Golden-output verification: `string_properties::golden_memcmp_corpus_sha256` passed.

## Isomorphism

- Inlining is a codegen visibility hint only. It does not change `count = n.min(a.len()).min(b.len())`.
- Equal-buffer certificates, folded SIMD probes, SWAR tail, and scalar first-difference resolver are unchanged.
- First differing byte ordering, Less/Equal/Greater tie-breaking, and zero-length behavior are unchanged.
- No floating-point, RNG, locale, errno, allocation, or side-effect ordering behavior exists in this core comparison path.

## Same-worker benchmark

Initial post on `ts1` with the candidate:

- Candidate FrankenLibC: p50 `66.336 ns`, mean `76.001 ns`
- The p50 moved better than the broader shifted profile, but mean regressed from the shifted-profile baseline, so a focused confirmation was required.

Focused clean baseline worktree:
`/data/projects/.scratch/frankenlibc-bd181-baseline-54126e7c` at `54126e7c`

Focused baseline command:
`RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-181-focused-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memcmp_4096' --noplot --sample-size 35 --warm-up-time 1 --measurement-time 3`

Focused comparison on `ts1`:

- Clean baseline FrankenLibC: p50 `50.598 ns`, mean `52.751 ns`
- Candidate FrankenLibC: p50 `66.336 ns`, mean `76.001 ns`

The candidate regressed the directly comparable focused row by `31.10%` p50 and `44.07%` mean.

## Decision

Rejected and restored source.

Score: `(Impact 0 * Confidence 5) / Effort 1 = 0.0`

Do not retry memcmp cross-crate `#[inline(always)]`, broadword equality probes, exact/certificate widening, folded-panel widening, 64-lane rank-select, or loop-unroll variants. Next memcmp work needs a genuinely different primitive such as a new packed-layout/equality certificate design with proven codegen, or route to a different profiled hotspot.
