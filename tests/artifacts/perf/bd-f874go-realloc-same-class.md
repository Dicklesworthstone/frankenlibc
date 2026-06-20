# bd-f874go strict fallback realloc same-class fast path

Date: 2026-06-20
Agent: BlackThrush / cod-b
Bead: `bd-f874go`
Verdict: keep as measured FrankenLibC gap narrowing; still loss vs glibc

## Lever

Strict fallback-tracked `realloc` previously routed every non-null pointer
through host `realloc`, even when the request could legally stay in place:

- same-size `realloc(ptr, old_size)`
- shrink requests that remain inside the same small malloc size class

The kept change returns the pointer unchanged for those two shapes. For
same-class shrink, it tightens the fallback metadata to the requested size so
`known_remaining` and future membrane bounds reflect the C-visible object size.
Growth and cross-class shrink continue to call the host allocator.

## Commands

Baseline benchmark, current `HEAD` before source edit:

```bash
RCH_WORKER=vmi1149989 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -- env AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
cargo bench -p frankenlibc-bench --features=abi-bench \
--bench calloc_glibc_bench realloc_cycle -- \
--sample-size 30 --measurement-time 2 --warm-up-time 1 --noplot
```

Candidate benchmark used the same command and rch selected the same worker
`vmi1149989`. The benchmark marker was renamed from the temporary
`ALLOC_BENCH` label to `REALLOC_BENCH` after the run to preserve the existing
`CALLOC_BENCH` marker for calloc rows; this is output-only and does not change
the measured workload.

Focused conformance:

```bash
RCH_WORKER=vmi1149989 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -- env AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
cargo test -p frankenlibc-abi --test malloc_abi_test realloc -- \
--nocapture --test-threads=1
```

Release build:

```bash
RCH_WORKER=vmi1149989 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -- env AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
cargo build -p frankenlibc-abi --release
```

## Results

All p50/mean values are ns per realloc operation. Ratio is lower-is-better.

| Workload | Baseline FL p50 | Baseline FL mean | Baseline glibc p50 | Candidate FL p50 | Candidate FL mean | Candidate glibc p50 | Candidate FL/glibc p50 | Candidate/base FL p50 | Candidate/base FL mean | Verdict |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| `same_256` | 69.188 | 73.984 | 3.170 | 13.333 | 21.904 | 3.288 | 4.06x | 0.193x | 0.296x | LOSS vs glibc / WIN vs FL |
| `same_class_shrink_256_to_240` | 226.960 | 306.948 | 8.904 | 170.314 | 171.806 | 7.480 | 22.77x | 0.750x | 0.560x | LOSS vs glibc / WIN vs FL |
| `cross_class_shrink_256_to_128` | 324.102 | 334.670 | 26.082 | 239.357 | 317.183 | 17.063 | 14.03x | 0.739x | 0.948x | LOSS vs glibc / guard-only FL improvement |
| `same_class_shrink_4096_to_3584` | 283.024 | 310.388 | 20.953 | 171.915 | 201.019 | 24.170 | 7.11x | 0.607x | 0.648x | LOSS vs glibc / WIN vs FL |

Candidate mean ratios vs same-run glibc:

| Workload | Candidate FL mean | Candidate glibc mean | Candidate FL/glibc mean |
|---|---:|---:|---:|
| `same_256` | 21.904 | 8.285 | 2.64x |
| `same_class_shrink_256_to_240` | 171.806 | 10.187 | 16.87x |
| `cross_class_shrink_256_to_128` | 317.183 | 27.380 | 11.58x |
| `same_class_shrink_4096_to_3584` | 201.019 | 29.064 | 6.92x |

## Validation

- `malloc_abi_test realloc`: passed 7 tests, 0 failed, 48 filtered on rch.
- New guard: `test_realloc_same_small_size_class_shrink_updates_bounds_in_place`
  verifies pointer stability, data preservation, and tightened fallback bounds.
- `cargo build -p frankenlibc-abi --release`: passed after rebase on rch
  worker `vmi1167313` with pre-existing warnings.
- `rustfmt --edition 2024 --check` on touched Rust files: passed.
- `git diff --check`: passed.

## Negative Evidence And Retry Predicate

This is not a glibc domination closeout. It removes the most wasteful host
`realloc` call shapes and narrows FL p50 by 25-81%, but every row remains slower
than glibc. The residual is not solved by another fallback-table cache variant:
the prior exact hot-slot cache was rejected, and this keep proves only that
avoiding host `realloc` helps when C semantics allow in-place return.

Next allocator attempt should target one of:

- a slim strict `realloc` metadata path that bypasses diffuse allocator
  entrypoint bookkeeping after the pointer is known fallback-owned;
- a same-worker split of fallback lookup, stats update, and native host
  `realloc` cost for shrink/grow pairs;
- a cross-thread-safe proof-carrying object-size table that avoids the global
  fallback table for common strict realloc cycles.

Do not retry per-thread exact fallback-slot caching as a standalone lever.
