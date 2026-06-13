# bd-2g7oyh.380 malloc hot-slot lazy accounting keep

Date: 2026-06-13
Agent: BoldFalcon
Worker: RCH `vmi1227854`
Source: `b3a22638` clean baseline vs final working tree

## Target

`malloc_free_64` and `malloc_free_256` remained the top admissible allocator
residual after pass 83. The accepted lever is one structural accounting change:
when a pointer is checked out from the allocator-level hot slot, defer only the
eager `active_count` / `total_allocated` counter mutation until either the
matching free arrives or any non-exact allocation/free shape needs the counters.

The pointer selection, hot-slot LIFO order, thread-cache displacement order,
central-bin fallback, and elimination-first order are unchanged.

## Baseline

Command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free --noplot --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Clean detached worktree: `/data/projects/.scratch/frankenlibc-bd-2g7oyh-380-baseline`

Rows:

- `malloc_free_64/frankenlibc_core_state`: Criterion `[6.0670 ns 6.1042 ns 6.1400 ns]`, p50 `6.114 ns`, p95 `7.500 ns`, p99 `30.500 ns`, mean `9.809 ns`
- `malloc_free_64/host_glibc`: Criterion `[4.7378 ns 4.9098 ns 5.0658 ns]`, p50 `4.926 ns`, mean `6.691 ns`
- `malloc_free_256/frankenlibc_core_state`: Criterion `[6.2756 ns 6.3215 ns 6.3698 ns]`, p50 `6.328 ns`, p95 `9.037 ns`, p99 `35.000 ns`, mean `7.579 ns`
- `malloc_free_256/host_glibc`: Criterion `[3.4730 ns 3.5558 ns 3.6434 ns]`, p50 `3.560 ns`, mean `4.874 ns`
- `malloc_free_large/frankenlibc_core_state` guard: Criterion `[7.9121 ns 7.9464 ns 7.9851 ns]`, p50 `7.998 ns`, mean `9.177 ns`

## Final Post

Command matched the baseline command from the live final-source tree.

Rows:

- `malloc_free_64/frankenlibc_core_state`: Criterion `[5.5814 ns 5.8677 ns 6.1456 ns]`, p50 `6.001 ns`, p95 `8.156 ns`, p99 `55.000 ns`, mean `8.192 ns`
- `malloc_free_64/host_glibc`: Criterion `[4.1467 ns 4.4019 ns 4.6287 ns]`, p50 `4.058 ns`, mean `5.461 ns`
- `malloc_free_256/frankenlibc_core_state`: Criterion `[5.0859 ns 5.2626 ns 5.4441 ns]`, p50 `5.431 ns`, p95 `12.500 ns`, p99 `35.500 ns`, mean `7.251 ns`
- `malloc_free_256/host_glibc`: Criterion `[3.8235 ns 3.9205 ns 4.0146 ns]`, p50 `3.807 ns`, mean `5.035 ns`
- `malloc_free_large/frankenlibc_core_state` guard: Criterion `[6.0143 ns 6.0449 ns 6.0741 ns]`, p50 `6.031 ns`, mean `7.197 ns`

Improvement:

- 64B Criterion middle: `6.1042 -> 5.8677 ns` (`1.04x`); p50 `6.114 -> 6.001 ns`; mean `9.809 -> 8.192 ns` (`1.20x`)
- 256B Criterion middle: `6.3215 -> 5.2626 ns` (`1.20x`); p50 `6.328 -> 5.431 ns` (`1.17x`); mean `7.579 -> 7.251 ns`
- Large guard: Criterion middle `7.9464 -> 6.0449 ns` (`1.31x`); p50 `7.998 -> 6.031 ns`

## Behavior Proof

Final-source proof commands:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 cargo test -j 1 -p frankenlibc-core --lib malloc -- --nocapture --test-threads=1
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 cargo check -j 1 -p frankenlibc-core --lib
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings -A clippy::excessive_precision -A clippy::collapsible_if -A clippy::manual_contains -A clippy::type_complexity -A clippy::unnecessary_map_or
rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs crates/frankenlibc-core/src/malloc/thread_cache.rs
```

Results:

- RCH `cargo test -p frankenlibc-core --lib malloc`: `66 passed; 0 failed`
- RCH `cargo check -p frankenlibc-core --lib`: passed
- RCH allowlisted clippy: passed. Strict clippy was blocked by pre-existing non-malloc lint families in `math/exp.rs`, `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`.
- Touched-file rustfmt: passed

Golden and isomorphism notes:

- Existing lifecycle SHA goldens passed unchanged:
  - `hot_cycle_lifecycle_record_sha256_is_stable`: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`
  - `hot_slot_lifecycle_record_sha256_is_stable`: `eca20f7a00fb7f2dc41fcafde6f1d9f7184f585b492b87616dd9ef07e16e2729`
- New `hot_slot_lazy_accounting_is_exact_and_materializes_before_next_shape` proves public `active_count()` / `total_allocated()` remain exact while raw eager counters are deferred only inside the exact one-live hot-slot cycle.
- `thread_cache_hot_slot_preserves_lifo_order_and_capacity` preserves LIFO and central-bin spill behavior.
- `free_matches_waiting_consumer_through_elimination` preserves elimination-first tie-breaking when a consumer exists.
- Floating point and RNG are not involved.

Final source SHAs:

- `allocator.rs`: `4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e`
- `thread_cache.rs`: `4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174`
- `size_class.rs`: `e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef`
- `glibc_baseline_bench.rs`: `b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c`

## Verdict

KEPT. Score `2.7 = Impact 3.0 x Confidence 0.9 / Effort 1.0`.

Next route: reprofile after commit because allocator row weights shifted; if
allocator remains a top residual, attack a deeper packed hot-cache/slab
state-machine primitive rather than repeating lazy-accounting or hot-slot
metadata micro-families.
