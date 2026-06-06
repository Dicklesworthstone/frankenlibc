# bd-2g7oyh.174 - memchr 64-lane mask/rank-select rejection

## Target

- Bead: `bd-2g7oyh.174`
- Function family: `memchr_absent`
- Source scope tested: `crates/frankenlibc-core/src/string/mem.rs`
- Comparable benchmark worker: `ts1`

## Baseline

Command:

```text
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass3-profile cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcpy_4096|memmove_4096|memset_4096|memchr_absent|memcmp_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Fresh pre-edit rows on `ts1`:

- `memchr_absent`: Franken p50 `32.920 ns`, mean `38.758 ns`; host p50 `21.471 ns`, mean `23.131 ns`
- `memmove_4096`: Franken p50 `42.291 ns`, mean `43.702 ns`; host p50 `36.703 ns`, mean `38.789 ns`
- `memcmp_4096`: Franken p50 `43.871 ns`, mean `50.605 ns`; host p50 `37.482 ns`, mean `40.694 ns`
- `memcpy_4096`: parity/ahead on p50
- `memset_4096`: small p50 gap, Franken ahead on mean

The top unowned target was `memchr_absent`, a `1.53x` p50 / `1.68x` mean residual.

## Candidate Lever

The candidate kept the existing 256-byte folded scan shape but replaced eight 32-byte SIMD panels with four 64-byte panels:

- `has_byte_memchr_folded` used `Simd<u8, 64>` masks.
- First-hit resolution within a matching folded block used a 64-bit mask and `trailing_zeros`.
- Block order and panel order remained increasing, preserving leftmost-match semantics.

This was not a wider 512-byte folded block and not scalar SWAR; it tested whether lower panel/reduction count improved the absent-heavy path.

## Behavior Proof

Local checks:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs .beads/issues.jsonl
```

Remote focused test:

```text
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_PROPTEST_CASES=512 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd174-proof cargo test -p frankenlibc-core memchr -- --nocapture --test-threads=1
```

RCH routed the proof to `vmi1149989`. The run passed:

- 10 focused `memchr`/`wmemchr` unit and property tests
- `memchr_golden_output_sha256`
- `prop_memchr_matches_scalar_position`
- `golden_memchr_corpus_sha256`
- `prop_memchr_finds_first_occurrence`

Isomorphism notes:

- Ordering and tie-breaking: preserved. Blocks and 64-byte panels were visited left-to-right; `trailing_zeros` returns the first set lane inside the first matching panel.
- Floating point: not applicable.
- RNG: not applicable.
- Golden-output SHA: unchanged by focused proof run.

## Post Benchmark

Command:

```text
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd174-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memchr_absent|memmove_4096|memcmp_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Same-worker post rows on `ts1`:

- `memchr_absent`: Franken p50 `34.535 ns`, mean `36.996 ns`; host p50 `26.004 ns`, mean `28.864 ns`
- `memmove_4096`: Franken p50 `42.795 ns`, mean `47.718 ns`; host p50 `37.431 ns`, mean `39.793 ns`
- `memcmp_4096`: Franken p50 `60.650 ns`, mean `62.974 ns`; host p50 `39.360 ns`, mean `41.609 ns`

## Verdict

Rejected and source restored.

The target mean improved, but the primary p50 regressed:

- p50: `32.920 ns` -> `34.535 ns`
- mean: `38.758 ns` -> `36.996 ns`

Score: `(Impact 0 * Confidence 3) / Effort 2 = 0.0`, below the keep threshold of `2.0`.

Next `memchr_absent` work should not retry wider folded blocks, split-fold resolvers, scalar SWAR chunks, or 64-lane panel replacement. The next primitive should change the scan strategy rather than only changing panel width.
