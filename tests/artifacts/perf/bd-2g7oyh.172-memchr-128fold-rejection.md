# bd-2g7oyh.172 - memchr 128-fold resolver rejection

## Target

- Bead: `bd-2g7oyh.172`
- Function family: `memchr_absent`
- Source scope tested: `crates/frankenlibc-core/src/string/mem.rs`
- Worker for comparable benchmark evidence: `vmi1227854`

## Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=CodexPerf FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-perf-mem-baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memcpy_4096|memmove_4096|memset_4096|memchr_absent|memcmp_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Fresh pre-edit `memchr_absent` row:

- FrankenLibC: p50 `27.562 ns`, mean `29.063 ns`
- Host glibc: p50 `19.285 ns`, mean `21.514 ns`
- Residual: `1.43x` p50, `1.35x` mean

Guard rows on the same worker:

- `memcpy_4096`: Franken p50 `31.441 ns`, mean `32.970 ns`; host p50 `30.544 ns`, mean `32.398 ns`
- `memset_4096`: Franken p50 `22.562 ns`, mean `23.805 ns`; host p50 `22.609 ns`, mean `25.579 ns`
- `memcmp_4096`: Franken p50 `51.797 ns`, mean `54.534 ns`; host p50 `36.766 ns`, mean `39.790 ns`
- `memmove_4096`: Franken p50 `31.629 ns`, mean `32.942 ns`; host p50 `28.269 ns`, mean `31.330 ns`

## Candidate Lever

The candidate replaced the existing 256-byte folded absent certificate with a lower-register-pressure split resolver:

- Fold the first 128 bytes into four 32-byte SIMD equality masks.
- Fold the second 128 bytes only if the first half had no hit.
- Resolve the first nonzero 32-byte panel with the existing first-byte SIMD resolver.

This was a materially different attempt from the prior rejected wider 512-byte folded panel. It targeted mask/rank-select style first-set extraction while preserving the current leftmost result contract.

## Behavior Proof

Local checks:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/mem.rs
git diff --check -- crates/frankenlibc-core/src/string/mem.rs .skill-loop-progress.md .beads/issues.jsonl
```

Remote focused test:

```text
RCH_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_PROPTEST_CASES=512 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd172-proof cargo test -p frankenlibc-core memchr -- --nocapture --test-threads=1
```

The proof run routed to `vmi1149989` and passed focused `memchr` unit/property/integration tests, including:

- `prop_memchr_matches_scalar_position`
- `memchr_golden_output_sha256`
- `golden_memchr_corpus_sha256`
- boundary tests for zero-length, exact-end, and folded-panel cases

Isomorphism notes:

- Ordering and tie-breaking: preserved. The candidate checked halves and 32-byte panels in increasing address order and delegated the selected panel to the existing first-match resolver.
- Floating point: not applicable.
- RNG: not applicable.
- Golden-output SHA: unchanged by focused proof run.

## Post Benchmark

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd172-post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_(memchr_absent|memcmp_4096|memmove_4096)' --noplot --sample-size 40 --warm-up-time 1 --measurement-time 3
```

Same-worker post rows on `vmi1227854`:

- `memchr_absent`: Franken p50 `28.690 ns`, mean `30.325 ns`; host p50 `19.875 ns`, mean `21.608 ns`
- `memcmp_4096`: Franken p50 `46.749 ns`, mean `49.904 ns`; host p50 `42.094 ns`, mean `45.539 ns`
- `memmove_4096`: Franken p50 `31.519 ns`, mean `32.316 ns`; host p50 `27.836 ns`, mean `30.446 ns`

## Verdict

Rejected and source restored.

The primary row regressed against the same-worker pre-edit baseline:

- p50: `27.562 ns` -> `28.690 ns`
- mean: `29.063 ns` -> `30.325 ns`

Score: `(Impact 0 * Confidence 4) / Effort 2 = 0.0`, below the keep threshold of `2.0`.

Next `memchr_absent` work should not retry a wider folded panel or this split-fold resolver. Re-profile first, then either attack a true vector-mask first-set/rank-select extractor with less panel overhead or route to the next unowned profiler-evident gap.
