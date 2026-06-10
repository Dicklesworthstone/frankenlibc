# bd-2g7oyh.323 malloc_free_256 focused allocator gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Pass 50 selected `malloc_free_256` from the pass-48 broad RCH profile after
excluding peer-owned `pow*` and `strncmp` lanes and after `strcpy_4096` rejected
its focused source lever.

Broad route basis on `vmi1227854`:

| impl | p50 ns | mean ns |
| --- | ---: | ---: |
| FrankenLibC | 6.072 | 8.532 |
| host glibc | 3.601 | 5.067 |

Prior allocator artifacts reject hot-slot metadata, exact-size cache bypass,
Trace lifecycle gates, fixed magazine storage, plain Vec-to-fixed storage swaps,
and lease/certificate/log micro-specialization. The only admissible source route
was the deeper alien-graveyard Modern Allocator Design primitive: a safe-Rust
intrusive index-linked small-object LIFO/slab and/or deferred hot-path
observability, with unchanged lifecycle and reuse semantics.

## Focused Baseline

The first RCH attempt selected `vmi1227854` but was blocked before execution by
remote dependency preflight `RCH-E324`; no local fallback ran because
`RCH_REQUIRE_REMOTE=1`.

Counted command:

```text
RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=600 rch exec -- env \
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd323-malloc256-baseline-target \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_malloc_free_256 --noplot --sample-size 50 --warm-up-time 1 \
--measurement-time 3
```

RCH selected `ovh-a`. Because no source edit was made, no post-run was needed.

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[5.1614 ns 5.1808 ns 5.1996 ns]` | 5.192 | 6.239 | 7.500 | 20.000 |
| host glibc | `[5.7526 ns 6.1117 ns 6.4946 ns]` | 4.959 | 6.111 | 7.872 | 15.000 |

The focused gate collapsed to `1.047x` by p50 and `1.021x` by mean. The
absolute p50 gap was `0.233 ns`.

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

The focused same-worker edit gate did not reproduce a material allocator gap, so
attempting the intrusive LIFO/slab source change would violate the profile-backed
target rule.

Next route: reprofile and attack a different reproduced unowned residual. Only
return to allocator work after a focused remote baseline shows a material gap;
the next admissible allocator primitive remains a true safe-Rust structural
small-object LIFO/slab or hot/cold observability replacement, not another
metadata or lifecycle micro-lever.
