# bd-2g7oyh.294 strlen_4096 page-certificate rejection

Date: 2026-06-09
Agent: BoldFalcon

## Target

`strlen_4096` focused residual after pass-27 broad profiling:

- Broad profile basis: FrankenLibC p50 `24.041 ns`, mean `24.070 ns`; host glibc p50 `17.508 ns`, mean `17.630 ns`.
- Required gate: fresh focused same-worker RCH baseline before source edits, one lever only, keep only Score >= 2.0.

## Focused Baseline

Recovered from RCH `ovh-a` build `29879662679164299` at `2026-06-09T19:17:51Z`.

Command:

```text
cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Criterion JSON from the worker target directory:

- FrankenLibC mean `24.400734522 ns`, median `24.372963734 ns`, slope `24.408780126 ns`, stddev `0.149418111 ns`.
- Host glibc mean `17.688670766 ns`, median `17.654768723 ns`, slope `17.659974286 ns`, stddev `0.178615289 ns`.
- Sample p50/p95/p99: FrankenLibC `24.388 / 24.670 / 24.841 ns`; host `17.656 / 18.234 / 18.324 ns`.

The focused gap reproduced at roughly `1.38x`, so a single source lever was admissible.

## Candidate Lever

Rejected candidate: page-scale NUL-free certificate for `strlen`.

Shape:

- Add `STRLEN_PAGE_BLOCK = STRLEN_NUL_BLOCK * 8`.
- Add `block_has_nul_4096` using a folded 64-lane `simd_min` reduction across a 4096-byte chunk.
- Add an early `strlen` loop that skips NUL-free 4096-byte spans, falling back to the existing 512/256/64/word/byte sequence when any NUL is detected.

Isomorphism audit while candidate was present:

- Ordering: candidate only advanced `i` after certifying an entire 4096-byte span had no NUL. If any NUL was present, it broke into existing left-to-right resolution.
- Tie-breaking: not applicable beyond first-NUL order; exact first NUL stayed delegated to existing narrower loops.
- Floating point and RNG: not applicable.
- Candidate proof-only golden transcript was `067a023af3cf7a4901dba88be5964e68345452333c7eb04fe42a0923dde57ab8`, covering no-NUL, page-terminal, early-NUL-in-page, and second-page cases.

## Post Benchmark

RCH post run:

```text
RCH_BUILD_SLOTS=3 RCH_WORKER=ovh-a RCH_WORKERS=ovh-a rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

RCH selected `ovh-a`, target `.rch-target-ovh-a-job-29879662679164379-1781034199511847970-0`, exit 0.

Criterion output:

- FrankenLibC time interval `[31.398 ns 31.982 ns 32.701 ns]`.
- FrankenLibC benchmark line p50 `30.888 ns`, p95 `38.252 ns`, p99 `69.563 ns`, mean `32.440 ns`.
- Host glibc time interval `[19.322 ns 20.391 ns 21.780 ns]`.
- Host benchmark line p50 `29.020 ns`, p95 `45.000 ns`, p99 `50.641 ns`, mean `32.932 ns`.

The run used shared `ovh-a` load because an 8-slot request starved and timed out with `selection error: queue_timeout`. Even with that caveat, the candidate did not improve the FrankenLibC row: p50 regressed from `24.373 ns` to `30.888 ns`, and Criterion mean regressed from `24.401 ns` to `31.982 ns`.

## Verdict

REJECTED-RESTORED, Score `0.0`.

No source change is kept. `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs` passed after restoring the source.

Next route: do not retry larger folded-NUL-block certificates for `strlen_4096`. The next admissible `strlen` primitive must be structurally different, such as alignment-aware dual-stream probes, a rank/select first-NUL resolver that reduces branch pressure without page-scale folding, or a safe-Rust byte-classifier layout that changes the memory access model.
