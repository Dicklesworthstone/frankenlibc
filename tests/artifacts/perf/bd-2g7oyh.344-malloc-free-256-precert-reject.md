# bd-2g7oyh.345 - malloc_free_256 exact-class pre-certificate rejection

Note: this artifact keeps its pre-rebase filename. The bead was originally
opened as `bd-2g7oyh.344`, then renumbered to `bd-2g7oyh.345` after upstream
landed `bd-2g7oyh.344` for the log2f pass.

## Target

Pass 73 selected `glibc_baseline_malloc_free_256` from the post-pass-71 broad
RCH profile on `vmi1227854` at `aeae1e69`. The broad routing row showed
FrankenLibC p50 `5.811 ns`, mean `7.593 ns` versus host p50 `3.482 ns`, mean
`5.242 ns` (`1.45x` mean). Peer-owned `pow`/`strncmp` lanes were excluded.

Focused baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -v -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-344-malloc256-baseline-target \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_malloc_free_256 --noplot --sample-size 50 --warm-up-time 1 \
  --measurement-time 3
```

Focused baseline on `vmi1227854`:

| row | Criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC | `[5.8544 ns 5.9196 ns 5.9825 ns]` | 6.023 | 7.233 | 6.594 | 30.000 |
| host glibc | `[3.5256 ns 3.6074 ns 3.6988 ns]` | 3.739 | 6.076 | 9.438 | 40.000 |

## Candidate

Rejected lever: an exact size-class hot-slot fast branch in `MallocState::malloc`
for non-Trace logging. For exact class sizes such as 256 bytes, the size-class
certificate is provably non-violating and its Trace row is dropped at the default
Warn log level. The candidate consumed `thread_cache_hot_slots[bin]` before the
diagnostic certificate path, while Trace mode fell back to the existing code to
keep byte-identical certificate and lifecycle rows.

This was intentionally one lever. It did not change free-side elimination order,
hot-slot LIFO behavior, active/total accounting, or backend release semantics.

## Behavior Proof

RCH proof command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -v -- \
  env AGENT_NAME=BoldFalcon RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=2 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-344-malloc256-proof-target \
  cargo test -j 1 -p frankenlibc-core --lib malloc -- --nocapture --test-threads=1
```

Result: 66/66 malloc-family tests passed on `vmi1227854`, including:

- `hot_cycle_lifecycle_record_sha256_is_stable`
- `hot_slot_lifecycle_record_sha256_is_stable`
- `free_matches_waiting_consumer_through_elimination`
- candidate-only `exact_class_hot_slot_fast_path_preserves_default_warn_observability`

Isomorphism notes:

- Ordering/tie-breaking: Trace mode used the original path; default Warn mode
  dropped the same Trace rows as before and preserved hot-slot LIFO.
- Floating-point/RNG: N/A.
- Golden SHA: allocator lifecycle SHA tests above stayed stable.
- Shared elimination: unchanged, because the candidate only touched malloc-side
  hot-slot consumption after an object was already cached locally.

## Post Benchmark

Post command matched the baseline except for target dir:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 rch exec -v -- \
  env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-BoldFalcon-bd-2g7oyh-344-malloc256-post-target \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_malloc_free_256 --noplot --sample-size 50 --warm-up-time 1 \
  --measurement-time 3
```

Post on `vmi1227854`:

| row | Criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | `[7.6027 ns 7.6695 ns 7.7392 ns]` | 7.633 | 8.748 | 8.766 | 40.000 |
| host glibc same run | `[3.2376 ns 3.3747 ns 3.5191 ns]` | 3.214 | 4.572 | 4.227 | 30.000 |

The candidate regressed FrankenLibC by p50 `26.7%` and mean `20.9%` versus the
focused baseline. It was restored immediately.

## Restored Source

Restored source fingerprints:

```text
c126320efbc34e01a1ae36a9d4fdf2b3dbde9b796a3dbbb82f821e3dedb900fd  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

`git diff --check` passed after restore.

## Verdict

Rejected. Score `(Impact 0.0 x Confidence 4.0) / Effort 2.0 = 0.0`.

Do not retry exact-class pre-certificate hot-slot reordering, exact-size
allocator shortcuts, Trace lifecycle gates, fixed magazine/plain storage swaps,
certificate/log micro-specialization, or hot-slot metadata tweaks.

Next allocator attempt must be materially different: a structural safe-Rust
small-object allocator primitive such as lazy-materialized observability with
batched exact counters, or a real intrusive slab/LIFO replacement that changes
the measured steady-state path rather than retuning the existing hot slot.
