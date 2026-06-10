# bd-2g7oyh.326 malloc_free_64 focused allocator gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

`bd-2g7oyh.326` screened `malloc_free_64` after a fresh broad RCH profile at
`cf6ff4df` showed it as the strongest unowned slower row in the parsed Criterion
artifacts.

Broad route basis:

- RCH build: `29879662679165252`
- Worker: `ovh-a`
- Criterion artifacts:
  `/data/tmp/frankenlibc-pass51-broad-profile-target-20260610T1821`

| profile | impl | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| `malloc_free_64` | FrankenLibC | 8.325 | 7.920 |
| `malloc_free_64` | host glibc | 4.679 | 5.196 |

That broad route was `1.779x` by p50 and `1.524x` by mean. Active peer-owned
lanes (`pow*`, `strncmp`) were excluded. Recent copy/string routes were either
focused-no-code or rejected/restored, and prior allocator artifacts already
rejected hot-slot metadata, exact-size cache bypass, Trace lifecycle gates,
fixed magazine storage, plain storage-layout swaps, and
lease/certificate/log micro-specialization.

The only admissible source route, if the focused gap reproduced materially, was
a genuinely structural safe-Rust allocator primitive: intrusive index-linked
small-object LIFO/slab and/or deferred hot-path observability.

## Focused Baseline

The focused benchmark ran from a clean detached worktree at `cf6ff4df`:

`/data/projects/frankenlibc_b326_baseline_20260610T1832`

The shared checkout contained unrelated in-flight tracker/artifact changes, so
it was not used as the benchmark source tree.

Command:

```text
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd326-malloc64-baseline-target-20260610T1832 \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_malloc_free_64 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `ovh-a`, matching the broad worker. Remote build:
`29879662679165295`.

| impl | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 5.336 | 6.395 | 7.562 | 20.000 |
| host glibc | 4.607 | 6.093 | 8.125 | 20.000 |

The focused gate collapsed to `1.158x` by p50 and `1.050x` by mean, with only a
`0.729 ns` absolute p50 gap.

## Isomorphism

No source code changed.

- Allocation/free ordering: unchanged by construction.
- LIFO reuse and central-bin/backend tie-breaking: unchanged by construction.
- Active/total accounting and lifecycle Trace rows: unchanged by construction.
- Floating point and RNG: not involved.
- Golden source SHA-256:
  - `crates/frankenlibc-core/src/malloc/allocator.rs`
    `c126320efbc34e01a1ae36a9d4fdf2b3dbde9b796a3dbbb82f821e3dedb900fd`
  - `crates/frankenlibc-core/src/malloc/thread_cache.rs`
    `4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174`

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused same-worker gate did not reproduce a material allocator gap, so
attempting another allocator source change would violate the profile-backed
target rule.

Next route: reprofile and attack a different reproduced unowned residual. Only
return to allocator work after a focused same-worker baseline shows a material
gap; the next admissible allocator primitive remains a true structural
small-object LIFO/slab or hot/cold observability replacement, not another
metadata, layout-swap, lifecycle, or certificate/log micro-lever.
