# bd-2g7oyh.182 malloc default-Warn trace lifecycle call gate rejected

## Target

- Bead: `bd-2g7oyh.182`
- Profile-backed hotspot: `malloc_free_256` and guard row `malloc_free_64`
- Broad pass-5 profile source: RCH worker `vmi1264463`
  - `malloc_free_256`: FrankenLibC p50 `14.036 ns`, mean `28.861 ns`; host p50 `9.032 ns`, mean `15.733 ns`
  - `malloc_free_64`: FrankenLibC p50 `12.732 ns`, mean `29.142 ns`; host p50 `10.386 ns`, mean `24.420 ns`

Prior fixed-capacity magazine storage was rejected in `bd-2g7oyh.175`, so this
lever attacked a different allocator primitive: skip default-dropped Trace
lifecycle recorder calls before entering `record_lifecycle`.

## Baseline

Focused baseline command:

```bash
RCH_WORKER=ts1 RCH_PREFERRED_WORKER=ts1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-182-baseline \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_malloc_free_(64|256)' --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

Worker: `vmi1227854`

- `malloc_free_64` FrankenLibC: p50 `6.161 ns`, mean `7.567 ns`; Criterion center `6.1454 ns`
- `malloc_free_64` host glibc: p50 `3.877 ns`, mean `5.518 ns`
- `malloc_free_256` FrankenLibC: p50 `6.250 ns`, mean `8.108 ns`; Criterion center `6.4224 ns`
- `malloc_free_256` host glibc: p50 `4.332 ns`, mean `6.024 ns`

## Lever

One lever only: add a Trace-enabled predicate and guard Trace-level allocator
success lifecycle calls before invoking `record_lifecycle` in the default
`Warn` mode. Warn/error diagnostics, size-class violation diagnostics, pointer
choice, allocation/free order, thread-cache LIFO behavior, central-bin order,
elimination order, and accounting were not changed.

## Behavior proof

RCH proof command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-182-proof \
  FRANKENLIBC_PROPTEST_CASES=4096 \
  cargo test -p frankenlibc-core malloc -- --nocapture --test-threads=1
```

Result on `vmi1227854`: passed.

- 63 focused malloc unit tests passed.
- `allocator_properties::prop_malloc_state_tracks_large_allocation_metadata` passed.
- Golden lifecycle SHA test passed:
  `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`

## Isomorphism

- Ordering preserved: yes. Allocation path order stayed thread cache,
  elimination, central bin, backend refill; free path stayed elimination,
  thread cache, central bin, backend release.
- Tie-breaking preserved: yes. Thread-cache LIFO reuse, central-bin LIFO reuse,
  and elimination matching order were unchanged.
- Trace-mode lifecycle bytes preserved: yes. Trace mode still entered
  `record_lifecycle` at the same program points, and the golden lifecycle SHA
  stayed pinned.
- Warn/error diagnostics preserved: yes. Non-Trace calls were left unchanged.
- Floating point: N/A.
- RNG: N/A.

## Same-worker benchmark

Post command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-182-post \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_malloc_free_(64|256)' --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

Post on `vmi1227854`:

- `malloc_free_64` FrankenLibC: p50 `6.023 ns`, mean `8.042 ns`; Criterion center `6.0123 ns`
- `malloc_free_256` FrankenLibC: p50 `6.194 ns`, mean `7.759 ns`; Criterion center `6.0350 ns`

Confirmation command:

```bash
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-182-confirm \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  'glibc_baseline_malloc_free_(64|256)' --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

Confirmation on `vmi1227854`:

- `malloc_free_64` FrankenLibC: p50 `6.214 ns`, mean `7.934 ns`; Criterion center `6.2520 ns`
- `malloc_free_256` FrankenLibC: p50 `6.186 ns`, mean `7.587 ns`; Criterion center `5.9993 ns`

## Decision

Rejected and source restored. The candidate gave only a small `malloc_free_256`
mean improvement while `malloc_free_64` regressed on the confirmation row
(`6.161 -> 6.214 ns` p50, `7.567 -> 7.934 ns` mean). Score:
`(Impact 1 * Confidence 1) / Effort 1 = 1.0`, below the keep gate.

Do not retry dropped Trace call gating as a standalone allocator lever. The next
allocator route should be a deeper primitive: central-bin/thread-cache layout
fusion or a true per-size-class hot path that reduces the two `small_bin_index`
lookups and cache magazine indirections together, with a fresh profile first.
