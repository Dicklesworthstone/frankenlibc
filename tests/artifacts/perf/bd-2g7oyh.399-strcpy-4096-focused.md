# bd-2g7oyh.399 strcpy_4096 focused gate

## Target

- Bead: `bd-2g7oyh.399`
- Profile row: `glibc_baseline_strcpy_4096`
- Worker: `vmi1227854`
- Source baseline: `0655fbda9`
- Source surface: `crates/frankenlibc-core/src/string/str.rs`

The bead was opened from broad routing evidence. Prior no-retry families
included final-block rank-select, per-certified-block `copy_from_slice`
lowering, whole-string scan-then-bulk-copy, generic fused scan/store retunes,
and the already-kept exact-size unrolled path.

## Focused Baseline

Command:

```bash
RCH_WORKERS=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd399-strcpy-baseline-target-20260614T0338 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd399-strcpy-baseline-criterion-20260614T0338 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 60 --warm-up-time 1 \
  --measurement-time 3
```

Focused result:

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
|---|---:|---:|---:|---:|---:|
| FrankenLibC | `[49.886 ns 51.077 ns 52.207 ns]` | 52.608 | 70.364 | 67.413 | 95.000 |
| host glibc | `[44.710 ns 45.781 ns 46.960 ns]` | 45.830 | 47.842 | 55.169 | 70.500 |

The focused gate reproduced a material mean gap and a smaller p50 gap.

## Candidate

One source lever tested a uniform-source certificate for the exact profiled
`4096 + NUL` shape:

- if the first payload byte was nonzero,
- and all 4096 payload bytes matched that byte under a 512-byte SIMD equality
  certificate,
- then fill the destination payload with that byte and write the final NUL.

All nonuniform, early-NUL, empty, short, and fallback cases stayed on the
existing exact-size `strcpy_4096_terminated` path. This was a distinct
run-length certificate/store-shape probe, not a retry of the prior rank-select,
bulk-copy, or per-certified-block copy lowering families.

## Behavior Proof

Command:

```bash
RCH_WORKERS=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  RUST_TEST_THREADS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd399-strcpy-proof-target-20260614T0344 \
  cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1
```

Result: passed 8/8 filtered tests on `vmi1227854`, including:

- `test_strcpy_exact_4096_uniform_certificate`
- `test_strcpy_exact_4096_path_preserves_tail_after_early_nul`
- `test_strcpy_fused_path_preserves_tail_after_early_nul`
- `test_strcpy_golden_transcript_sha256`
- `test_strcpy_no_nul_still_panics_without_synthetic_nul_room`
- `test_stpcpy_returns_terminator_index`

The golden transcript SHA remained
`fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.

Local touched-file validation:

```bash
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
```

Both passed.

## Post Benchmark

Command:

```bash
RCH_WORKERS=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd399-strcpy-post-target-20260614T0348 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd399-strcpy-post-criterion-20260614T0348 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 60 --warm-up-time 1 \
  --measurement-time 3
```

Post result:

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
|---|---:|---:|---:|---:|---:|
| FrankenLibC candidate | `[52.914 ns 54.584 ns 56.327 ns]` | 55.539 | 64.931 | 83.564 | 171.613 |
| host glibc | `[37.575 ns 38.350 ns 39.150 ns]` | 38.726 | 39.995 | 46.340 | 60.000 |

Same-worker FrankenLibC delta:

- p50 regressed `52.608 -> 55.539 ns`.
- mean improved `70.364 -> 64.931 ns`, but not enough to offset the p50
  regression and wider vs-host gap.
- p95/p99 regressed.

## Verdict

REJECTED-RESTORED, Score `0.0`.

The candidate passed behavior proof but failed the performance keep gate. Source
was restored; `str.rs` SHA-256 after restore is
`0305360b0772daceb7c7920e2e025204be11d92f4737a2d9d15fc1933f4929e8`.

Next route: do not retry uniform-run certificates for this exact row. Continue
from a fresh profile and choose a different residual or a genuinely generated
code/disassembly-backed string primitive.
