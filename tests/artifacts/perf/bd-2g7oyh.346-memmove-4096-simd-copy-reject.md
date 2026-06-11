# bd-2g7oyh.346 - memmove_4096 safe-SIMD copy rejection

## Target

- Pass: 74
- Worker: `vmi1227854`
- Benchmark: `glibc_baseline_memmove_4096`
- Workload: 4096-byte non-overlapping move
- Broad routing row: FrankenLibC p50 `32.669 ns`, mean `36.110 ns` vs host p50 `27.406 ns`, mean `29.427 ns`.

## Focused Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-346-memmove4096-baseline-target cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Focused baseline:

- FrankenLibC Criterion interval: `[34.057 ns 34.470 ns 34.865 ns]`
- FrankenLibC emitted row: p50 `33.845 ns`, mean `34.771 ns`, p95 `37.673 ns`, p99 `60.000 ns`
- Host Criterion interval: `[29.122 ns 29.549 ns 30.031 ns]`
- Host emitted row: p50 `29.914 ns`, mean `32.356 ns`, p95 `33.820 ns`, p99 `70.000 ns`

## Candidate

One lever in `crates/frankenlibc-core/src/string/mem.rs`:

- Added an exact `count == 4096` path for `memmove`.
- Copied eight 512-byte blocks with safe portable SIMD (`Simd<u8, 64>` loads and `copy_to_slice` stores).
- Left all non-4096 counts on the existing `copy_from_slice` path.

This was intended as a safe-Rust cache-line/block copy primitive. It did not change FP, RNG, comparator ordering, or tie-breaking behavior. The copy contract remained prefix copy with untouched suffix bytes after the returned count.

## Behavior Proof

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -v -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-346-memmove-proof-target cargo test -j 1 -p frankenlibc-core --lib memmove -- --nocapture --test-threads=1
```

Result: passed 4/4 filtered tests:

- `memmove_golden_output_sha256`
- `prop_memmove_matches_prefix_copy`
- `test_memmove_exact_4096_copies_prefix_and_preserves_tail`
- `test_wmemmove_basic`

Candidate-only golden SHA-256: `d0e53db0f0521b5edb753185f0ce3cb135610cd2b6847511e330175a4166a2d1`.

## Post Benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-346-memmove4096-post-target cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_memmove_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Post result:

- FrankenLibC Criterion interval: `[37.362 ns 37.887 ns 38.424 ns]`
- FrankenLibC emitted row: p50 `36.736 ns`, mean `37.299 ns`, p95 `42.737 ns`, p99 `50.000 ns`
- Host Criterion interval: `[26.319 ns 26.714 ns 27.172 ns]`
- Host emitted row: p50 `27.797 ns`, mean `29.738 ns`, p95 `32.102 ns`, p99 `65.000 ns`

The candidate regressed FrankenLibC p50 by `8.5%` and mean by `7.3%` versus the focused baseline.

## Verdict

Rejected and restored. Score `0.0`.

Restored source hashes:

- `crates/frankenlibc-core/src/string/mem.rs`: `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- `crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

No source change is retained. Do not retry exact-size safe-SIMD copy-panel paths for `memmove_4096`; this matches the earlier rejected exact-size `memcpy_4096` family. The next route should be either a generated/disassembly-backed copy lowering artifact or a different unowned profile-backed residual such as `memchr_absent`.
