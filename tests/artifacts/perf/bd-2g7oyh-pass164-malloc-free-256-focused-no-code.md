# bd-2g7oyh.446 malloc_free_256 pass 164 focused no-code closeout

## Target

- Parent: `bd-2g7oyh`
- Child: `bd-2g7oyh.446`
- Workload: `glibc_baseline_malloc_free_256`
- Guard rows: `malloc_free_64`, `malloc_cache_pressure_256`,
  `malloc_free_large`
- Source target if reproduced: `crates/frankenlibc-core/src/malloc/`

Pass 164 used the pass 159 routing row as the profile-backed target while
`ts1`/remote RCH was offline by directive. No allocator source was edited before
the local focused gate.

## Local Baseline Command

```bash
env AGENT_NAME=BoldFalcon \
  FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass164-malloc-baseline-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass164-malloc-baseline-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_malloc_(free_64|free_256|cache_pressure_256|free_large)' \
  --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log SHA-256:

```text
1e79b3b38b19b556d8de61bba64b5803399b235f1c6b9b6e4938c02a8d41b4f7  /data/tmp/frankenlibc-pass164-malloc-baseline-local.log
```

## Results

| row | implementation | Criterion low | Criterion center | Criterion high | p50 | mean |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `malloc_free_64` | FrankenLibC | 4.9422 ns | 5.0352 ns | 5.1375 ns | 5.177 ns | 6.468 ns |
| `malloc_free_64` | host glibc | 4.8549 ns | 4.9664 ns | 5.1402 ns | 4.782 ns | 5.743 ns |
| `malloc_free_256` | FrankenLibC | 5.0025 ns | 5.0681 ns | 5.1462 ns | 5.011 ns | 6.772 ns |
| `malloc_free_256` | host glibc | 5.4265 ns | 5.5125 ns | 5.6068 ns | 5.418 ns | 6.105 ns |
| `malloc_cache_pressure_256` | FrankenLibC | 852.83 ns | 875.82 ns | 905.16 ns | 834.054 ns | 853.655 ns |
| `malloc_cache_pressure_256` | host glibc | 2.8924 us | 2.9461 us | 3.0039 us | 2865.500 ns | 2985.425 ns |
| `malloc_free_large` | FrankenLibC | 5.8354 ns | 5.9328 ns | 6.0376 ns | 5.834 ns | 6.472 ns |
| `malloc_free_large` | host glibc | 19.191 ns | 19.562 ns | 19.982 ns | 19.083 ns | 22.964 ns |

Primary row conclusion:

- `malloc_free_256` no longer reproduces as a material source-edit target.
- FrankenLibC is faster than host on Criterion center (`5.0681 ns` vs
  `5.5125 ns`) and p50 (`5.011 ns` vs `5.418 ns`).
- The mean tail is slower (`6.772 ns` vs `6.105 ns`), but this is an
  outlier-sensitive 10.9% tail delta on a row that is faster on the main timing
  estimators. It does not justify touching allocator semantics.

Guard conclusions:

- `malloc_cache_pressure_256` is already much faster than host on p50 and mean,
  so the deeper magazine/central-bin path is not a vs-host gap in this local
  gate.
- `malloc_free_large` remains much faster than host.
- `malloc_free_64` has a small residual, but this exact one-live hot-slot family
  is explicitly no-repeat from prior passes unless a deeper primitive and
  material focused gap appear.

## Isomorphism Proof

No source changed in pass 164.

```text
2ca1fd83bf633e1397dde64d6425701a21fee79b7d7a953b3ca8104c0833229d  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
```

`git diff --exit-code -- crates/frankenlibc-core/src/malloc/allocator.rs
crates/frankenlibc-core/src/malloc/thread_cache.rs
crates/frankenlibc-core/src/malloc/size_class.rs` passed.

Allocation/free ordering, hot-slot LIFO behavior, magazine displacement,
central-bin spill/refill, elimination ordering, active/total accounting,
lifecycle log records, floating-point state, RNG state, and golden outputs are
unchanged by identity.

## Verdict

NO-CODE ROUTED OUT, Score `0.0`.

Do not edit allocator internals for `malloc_free_256` from this gate. If a
future profile selects allocator again, require a fresh material residual and a
non-repeated deeper primitive; do not retry one-live hot-slot metadata tweaks,
lazy-accounting retunes, bitmap-only hot-slot packing, or front-cache metadata
experiments.
