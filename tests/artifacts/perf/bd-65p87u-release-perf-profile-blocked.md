# bd-65p87u release-perf profile attempt

Date: 2026-08-04

## Scope

This is the required prerequisite capture for the `segment_free` structural
bead.  The intended workload is the deployed allocator's
`segment_allocator_3way` member in `malloc_bench`, built with `abi-bench` so it
exercises exported `malloc`/`free` rather than Rust's process allocator.

## Ledger preflight

`python3 scripts/check_perf_ledger_integrity.py preflight --lever bd-65p87u
--surface segment_free --comparison legacy-incumbent --incumbent host-glibc`
returned **PREFLIGHT BLOCKED**.  It cites three earlier `segment_free` rows:
the VOID-CV rows at `docs/NEGATIVE_EVIDENCE.md:18918` and `:18967`, plus the
worker-stability row at `:19002`.  Two do not contain a concrete retry
predicate, so this attempt cannot be admitted as a new competitive result.

## Remote build provenance

| Build | Worker | Command | Result |
| --- | --- | --- | --- |
| Base profiler build | `vmi1293453` | `cargo bench -j 1 -p frankenlibc-bench --profile release-perf --bench malloc_bench --no-run` | RCH build `29961269708587128` completed with exit 0. |
| Production allocator build | `vmi1227854` | `cargo bench -j 1 -p frankenlibc-bench --features abi-bench --profile release-perf --bench malloc_bench --no-run` | RCH build `29961269708587142` failed with exit 101. |

Both builds requested `RUSTFLAGS=-C force-frame-pointers=yes`; `release-perf`
has line tables and is unstripped.  The worker's `perf stat true` succeeds as
the RCH worker user, so the blocker is not perf permissions.

## Attribution table

| Frame | Self time | Evidence |
| --- | ---: | --- |
| `malloc_abi::segment_free` | unavailable | The `abi-bench` ELF failed to link before `perf record` could start. |
| `malloc_abi::enter_allocator_reentry_guard` | unavailable | Same failed build; no samples exist. |
| exported `malloc` / `free` | unavailable | Same failed build; no samples exist. |

No value in this table is a zero measurement.  There is no `perf.data`, no
executing-ELF SHA-256, and no competitive conclusion from this attempt.

## Blocking compiler diagnostic

The remote `release-perf` ABI build reports:

```text
error: symbol `fedisableexcept` is already defined
  --> crates/frankenlibc-abi/src/fenv_abi.rs:401:1
```

The duplicate exported definition is also present in
`crates/frankenlibc-abi/src/math_abi.rs:5530`.  This is outside the allocator
edit surface and was not changed here.

## Retry predicate

After the duplicate `fedisableexcept` export is resolved, rerun the exact
`abi-bench` release-perf build on one RCH worker, then record
`segment_allocator_3way` with no call-graph collection.  Only proceed to a
liveness-map lever if the fixed-path eight-thread churn gate completes 20/20
and the resulting profile still places at least 15% self time in
`segment_free`, with at least 80% of that frame on the liveness RMW.
