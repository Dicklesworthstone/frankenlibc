# bd-2g7oyh.380 malloc_free_64/256 lazy-accounting rejection

Date: 2026-06-13
Agent: BoldFalcon
Worker: vmi1153651
Status: REJECTED-RESTORED

## Target

After the pass-83 iconv closeout and broad reprofile, the largest admissible
allocator residual was `malloc_free_64`, with `malloc_free_256` as the guard
row. Prior allocator artifacts already reject exact-size hot-slot bypasses,
Trace lifecycle gates, fixed magazine/plain storage swaps, production-only
elimination compile-out, certificate/log micro-specialization, and hot-slot
metadata tweaks.

The only admissible allocator family for this bead was a structural
safe-Rust small-object primitive from the no-gaps allocator directive and the
graveyard Modern Allocator / region-slab guidance: either a real small-object
LIFO/slab replacement or a lazy-materialized observability representation that
changes the measured steady-state path while preserving exact public counters.

## Focused Baseline

Command shape:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
'glibc_baseline_(malloc_free_64|malloc_free_256)' --noplot --sample-size 60
--warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1153651`; all post data below used the same worker.

| row | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FL `malloc_free_64` | `[11.127 ns 11.830 ns 12.842 ns]` | 11.186 | 15.405 | 21.815 | 40.500 |
| host `malloc_free_64` | `[8.4538 ns 8.6682 ns 8.9024 ns]` | 9.069 | 11.440 | 16.375 | 45.500 |
| FL `malloc_free_256` | `[10.584 ns 11.028 ns 11.558 ns]` | 10.542 | 13.116 | 16.002 | 50.000 |
| host `malloc_free_256` | `[9.5366 ns 10.693 ns 12.154 ns]` | 9.391 | 11.900 | 27.013 | 32.930 |

## Candidate

Rejected source lever: lazy materialized accounting for the one-live hot-slot
allocation/free cycle.

The candidate kept the hot-slot pointer reuse order unchanged but represented a
single checked-out hot-slot allocation as a pending accounting slot. Public
`active_count()` / `total_allocated()` and lifecycle rows observed the pending
slot as exact state; any non-exact or multi-live shape materialized the pending
slot back into the eager counters before continuing through the original path.

This was one source lever in `crates/frankenlibc-core/src/malloc/allocator.rs`.
It did not change size-class selection, hot-slot LIFO order, magazine order,
central-bin order, shared-elimination ordering, backend release behavior,
floating-point state, or RNG state.

## Behavior Proof

Proof command:

```text
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 rch exec -- env
AGENT_NAME=BoldFalcon RUST_TEST_THREADS=1 CARGO_BUILD_JOBS=1
cargo test -j 1 -p frankenlibc-core --lib malloc -- --nocapture --test-threads=1
```

Result on `vmi1153651`: 66/66 malloc-family tests passed, including:

- `hot_cycle_lifecycle_record_sha256_is_stable`
- `hot_slot_lifecycle_record_sha256_is_stable`
- `thread_cache_hot_slot_preserves_lifo_order_and_capacity`
- `free_matches_waiting_consumer_through_elimination`
- candidate-only `hot_slot_lazy_accounting_is_exact_and_materializes_before_next_shape`

Isomorphism:

- Ordering/tie-breaking: unchanged. The candidate only delayed accounting for a
  hot-slot checkout; free still offered elimination first when shared, then
  cached/spilled/released through the original order.
- LIFO reuse: unchanged. `thread_cache_hot_slots[bin]` remained the stack top.
- Public accounting: exact by construction; the candidate-only proof checked
  observed active/total values and forced materialization before a second
  allocation shape.
- Lifecycle golden output: unchanged; both existing SHA tests passed.
- Floating point / RNG: not involved.

Local pre/post source hygiene:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`
  passed after candidate formatting.
- `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs` passed.

## Post Benchmark

Post command matched the focused baseline and pinned `RCH_WORKER=vmi1153651`.

| row | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| FL candidate `malloc_free_64` | `[13.418 ns 16.196 ns 19.963 ns]` | 13.734 | 19.621 | 37.500 | 63.353 |
| host `malloc_free_64` | `[8.7226 ns 9.5000 ns 10.560 ns]` | 8.571 | 11.770 | 22.500 | 40.000 |
| FL candidate `malloc_free_256` | `[15.588 ns 18.416 ns 22.100 ns]` | 14.462 | 24.068 | 69.744 | 120.848 |
| host `malloc_free_256` | `[9.3676 ns 10.254 ns 11.394 ns]` | 9.513 | 12.023 | 21.259 | 45.000 |

Against the same-worker baseline, the candidate regressed:

- `malloc_free_64`: p50 `11.186 -> 13.734 ns` (+22.8%), mean `15.405 -> 19.621 ns` (+27.4%).
- `malloc_free_256`: p50 `10.542 -> 14.462 ns` (+37.2%), mean `13.116 -> 24.068 ns` (+83.5%).

## Restored Source

The candidate was restored manually. Final source fingerprints:

```text
c126320efbc34e01a1ae36a9d4fdf2b3dbde9b796a3dbbb82f821e3dedb900fd  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

`git diff --exit-code -- crates/frankenlibc-core/src/malloc/allocator.rs`
passed after restore.

## Verdict

Rejected. Score `(Impact 0.0 * Confidence 4.0) / Effort 3.0 = 0.0`.

Do not retry lazy hot-slot accounting, hot-slot metadata splits, exact-class
pre-certificate reordering, exact-size allocator shortcuts, Trace lifecycle
gates, fixed magazine/plain storage swaps, or certificate/log micro-specializing
for this allocator row.

Next route: reprofile and either attack a different top residual or return to
allocator only with a deeper primitive that replaces the hot cache state machine
itself, such as a packed per-size-class small-object stack/slab with exact
counter integration and a codegen-backed lowering proof. A general magazine
rewrite alone is insufficient because the measured one-live cycle already
resolves through the front hot slot.
