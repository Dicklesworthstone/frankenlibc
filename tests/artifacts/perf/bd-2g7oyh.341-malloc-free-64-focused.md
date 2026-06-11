# bd-2g7oyh.342 malloc_free_64 focused allocator gate

## Target

Pass 70 screened `malloc_free_64` after the remote-only broad profile on
worker `vmi1153651` at `abbda514`. This artifact was created before rebase
under the temporary bead id `bd-2g7oyh.341`; the tracker bead is
`bd-2g7oyh.342` because peer commit `9a5cbbe1` used `.341` for memcmp.

Broad route basis:

| row | impl | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| `malloc_free_64` | FrankenLibC | 12.470 | 19.370 |
| `malloc_free_64` | host glibc | 9.048 | 10.960 |

Peer-owned and recent-exhausted lanes were excluded: `pow` / `powf` / `exp.rs`
under MossyFern (`bd-2g7oyh.125`), `strncmp` / `str.rs` under SilverCedar
(`bd-2g7oyh.65`), plus recent string, copy, math, and allocator focused gates.

## Focused gate

Command:

```bash
RCH_WORKER=vmi1153651 RCH_PREFERRED_WORKER=vmi1153651 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd341-malloc64-focused-baseline \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_malloc_free_64 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected worker `vmi1227854`; the paired target and host rows below are
therefore compared only within that focused worker run.

Focused result:

| row | impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: |
| `malloc_free_64` | FrankenLibC | 6.343 | 8.105 | 8.125 | 35.000 |
| `malloc_free_64` | host glibc | 4.978 | 6.508 | 10.062 | 40.000 |

The focused gate reproduced a median and mean residual, while FrankenLibC had
better p95/p99 tails in this run.

## Candidate screen

No source lever was applied. The available small allocator edits repeat rejected
families:

- hot-slot metadata / exact-cycle lease (`bd-2g7oyh.281`);
- exact-size and size-class shortcuts (`bd-2g7oyh.36`, `.49`);
- default-Warn Trace call gates (`bd-2g7oyh.182`);
- lifecycle row representation tweaks (`bd-2g7oyh.50`);
- fixed magazine / plain storage layout swaps (`bd-2g7oyh.48`, `.175`);
- certificate/log micro-specialization (`bd-2g7oyh.148` and successors).

The current 64-byte one-live-object cycle already uses the front hot slot and
does not touch the general `ThreadCache` `Vec<Magazine>` path after warmup.
The remaining admissible allocator primitive is the deeper Modern Allocator
route from `bd-4scbmf`: a safe-Rust intrusive index-linked slab/LIFO plus
lazy-materialized observability/accounting. That needs its own dedicated
profile and proof harness because naive counter deferral would change
immediately observable `active_count` / `total_allocated` and Trace snapshot
semantics.

## Behavior proof

No allocator or benchmark source changed.

Source SHA256:

```text
c126320efbc34e01a1ae36a9d4fdf2b3dbde9b796a3dbbb82f821e3dedb900fd  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
b092626db679409efebad5c33b7ee552cd4f3d1401c907130d18a65c9d005f4c  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Isomorphism: allocation/free order, thread-cache hot-slot LIFO behavior,
general magazine order, central-bin LIFO order, shared-elimination ordering,
backend callback behavior, active/total accounting, lifecycle Trace row order,
golden lifecycle output, tie-breaking, floating-point state, and RNG state are
unchanged by construction.

## Verdict

NO-CODE REJECTED. Score `0.0`.

Do not retry this allocator gate with another micro-lever. The next allocator
attack must be the larger safe-Rust slab/LIFO plus lazy-observability artifact,
with target ratio `malloc_free_64` p50 `6.343 ns -> <=5.0 ns` on the same
focused worker class and preserved allocator accounting/golden Trace semantics.
Until that artifact is ready, re-profile and select the next unowned
profile-backed residual.
