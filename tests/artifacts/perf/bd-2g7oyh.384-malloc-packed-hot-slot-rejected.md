# bd-2g7oyh.385 malloc packed hot-slot bitmap gate

Status: REJECTED, no source retained.

Note: this artifact filename was created while the local bead was
`bd-2g7oyh.384`. During rebase, upstream had already used `.384` for a
different exp10f closeout, so the malloc Beads row was renumbered to
`bd-2g7oyh.385` without changing this evidence file path.

## Target

Fresh broad RCH profiling after `8d70544c` reproduced an allocator residual on
`vmi1153651`:

- `malloc_free_64`: FrankenLibC p50/mean `13.326/17.123 ns` vs host
  `8.597/11.302 ns`
- `malloc_free_256`: FrankenLibC p50/mean `13.703/22.129 ns` vs host
  `8.864/14.956 ns`

The focused same-worker baseline kept the target profile-backed:

- `malloc_free_64`: FrankenLibC Criterion `[16.021 ns 17.523 ns 19.153 ns]`,
  p50 `14.088 ns`, p95 `37.312 ns`, p99 `120.000 ns`, mean `19.609 ns`;
  host Criterion `[9.3657 ns 11.264 ns 13.702 ns]`, p50 `8.864 ns`,
  mean `14.288 ns`
- `malloc_free_256`: FrankenLibC Criterion `[13.809 ns 15.423 ns 17.715 ns]`,
  p50 `13.781 ns`, p95 `58.539 ns`, p99 `99.750 ns`, mean `28.661 ns`;
  host Criterion `[8.7564 ns 9.4376 ns 10.406 ns]`, p50 `8.462 ns`,
  mean `10.994 ns`
- `malloc_free_large` guard stayed faster than host: FrankenLibC p50/mean
  `13.465/26.019 ns` vs host `44.024/62.103 ns`

## Lever Tested

One safe-Rust allocator lever was tested in
`crates/frankenlibc-core/src/malloc/allocator.rs`: replace the
`[Option<usize>; NUM_SIZE_CLASSES]` one-entry hot-slot table with a
bitmap-backed packed table storing pointer payloads and occupancy bits
separately.

The intended primitive came from the allocator no-gaps route: a more compact
hot-cache state machine that removes `Option<usize>` discriminants while
preserving one-object-per-bin LIFO behavior. This did not win.

## Behavior Proof

Candidate-source RCH proof on `vmi1153651`:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass84-malloc-proof-final-target cargo test -j 1 -p frankenlibc-core --lib malloc -- --nocapture --test-threads=1
```

Result: `67 passed; 0 failed`.

The candidate added `hot_slots_preserve_empty_and_zero_pointer_states` and
kept the existing allocator proof set passing:

- `hot_cycle_lifecycle_record_sha256_is_stable`:
  `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`
- `hot_slot_lifecycle_record_sha256_is_stable`:
  `eca20f7a00fb7f2dc41fcafde6f1d9f7184f585b492b87616dd9ef07e16e2729`
- `hot_slot_lazy_accounting_is_exact_and_materializes_before_next_shape`
  remained valid.
- `thread_cache_hot_slot_preserves_lifo_order_and_capacity` and elimination
  tests preserved allocation/free ordering and central-bin spill behavior.

Isomorphism notes for the tested lever:

- Ordering and tie-breaking: unchanged. The hot-slot pop remained one per bin;
  occupied-slot free still displaced the previous slot into the thread-cache
  magazine before installing the new pointer; full-magazine rejection still left
  the old hot slot unchanged.
- Pointer semantics: the candidate made zero-pointer payloads distinguishable
  from empty slots, but normal allocator paths still never synthesize null
  object pointers.
- Public accounting and lifecycle rows: unchanged by the existing golden tests.
- Floating point and RNG: not applicable.

After the benchmark rejection, the allocator source was manually restored.
`git diff -- crates/frankenlibc-core/src/malloc/allocator.rs` is empty, so the
retained tree preserves behavior by construction.

Final retained source SHAs:

- `allocator.rs`: `4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e`
- `thread_cache.rs`: `4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174`
- `size_class.rs`: `e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef`
- `glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

## Post Benchmark

Same-worker RCH Criterion worker: `vmi1153651`.

Command:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass84-malloc-post-target CRITERION_HOME=/data/tmp/frankenlibc-pass84-malloc-post-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Rows:

- `malloc_free_64/frankenlibc_core_state`: Criterion
  `[17.922 ns 18.302 ns 18.695 ns]`, p50 `18.392 ns`, p95 `22.777 ns`,
  p99 `50.000 ns`, mean `19.613 ns`
- `malloc_free_64/host_glibc`: Criterion `[8.5452 ns 8.7850 ns 9.1012 ns]`,
  p50 `8.536 ns`, mean `10.066 ns`
- `malloc_free_256/frankenlibc_core_state`: Criterion
  `[18.065 ns 18.888 ns 20.408 ns]`, p50 `18.081 ns`, p95 `24.975 ns`,
  p99 `55.468 ns`, mean `19.854 ns`
- `malloc_free_256/host_glibc`: Criterion `[8.2514 ns 8.4890 ns 8.7798 ns]`,
  p50 `8.321 ns`, mean `10.407 ns`
- `malloc_free_large/frankenlibc_core_state` guard: Criterion
  `[11.640 ns 12.127 ns 12.655 ns]`, p50 `12.157 ns`, mean `13.500 ns`
- `malloc_free_large/host_glibc` guard: Criterion
  `[40.732 ns 41.703 ns 42.843 ns]`, p50 `41.588 ns`, mean `48.761 ns`

## Verdict

REJECTED-RESTORED. Score `0.0`.

- `malloc_free_64` p50 regressed `14.088 ns -> 18.392 ns`; mean was flat
  `19.609 ns -> 19.613 ns`.
- `malloc_free_256` p50 regressed `13.781 ns -> 18.081 ns`. The mean improved
  `28.661 ns -> 19.854 ns`, but the Criterion interval and p50 regressed, so
  this fails the keep gate.
- Large-allocation guard remained faster than host but is not the target row.

Do not retry bitmap-only hot-slot representation changes. Next allocator route,
if a fresh profile still selects malloc, should be a deeper slab/arena primitive:
segregated per-size-class slab heads, refill batching, or an intrusive hot-list
layout with a proof of alignment, non-overlap, LIFO, central-bin, and lifecycle
golden preservation.
