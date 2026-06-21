# bd-5iae3q pthread_self global fast-cache guard

Date: 2026-06-21
Agent: BlackThrush / cod-a

## Target

Current-head `strtol_glibc_bench` on `hz1` reproduced the deployed timing/thread
residuals:

| Workload | FL | glibc | fl/glibc | Verdict |
|---|---:|---:|---:|---|
| `clock_gettime` | 34.85 ns | 32.85 ns | 1.06x | NEUTRAL/weak loss |
| `time` | 8.03 ns | 3.57 ns | 2.25x | LOSS |
| `pthread_self` | 5.49 ns | 3.02 ns | 1.82x | LOSS |

`time()` already has two fresh rejected vDSO-cache/split families, so this bead
targets `pthread_self`.

## Lever

The prior `pthread_self` `Cell` cache still called
`force_native_threading_enabled()` before reading the small cache. In the default
non-`owned-tls-cache` build that function borrows the larger pthread TLS
`RefCell` on every hot cache hit, so the fast lane was not actually a pure
single-cell read.

This patch adds `global_force_native_threading_enabled()` and uses it as a
front guard:

- if the global forced-native flag is set, keep the old conservative behavior
  and bypass the cache;
- if it is clear, read `PTHREAD_SELF_FAST` directly before touching the larger
  pthread TLS state;
- on a cache miss, fall back to the full `force_native_threading_enabled()`
  check before consulting the larger TLS cache.

Correctness invariant: all force-native entrypoints in this crate update the
global `FORCE_NATIVE_THREADING` flag before installing the TLS override, so the
fast guard cannot miss the mode that invalidates cached `pthread_self` identity.
This is the seqlock/RCU-style graveyard move: make the common read side pay only
the monotone version/flag check, pushing the heavier state inspection off the
hot hit path.

## Measurement

All bench commands were crate-scoped, through `rch`, with:

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_VISIBILITY=summary \
  rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
    --bench strtol_glibc_bench -- --noplot --sample-size 10 \
    --warm-up-time 1 --measurement-time 2
```

The first post-change run was a screen on `ovh-a`. To avoid cross-worker proof,
the source was temporarily restored to the old hunk with `apply_patch`, the same
bench was run again on `ovh-a`, and the candidate hunk was then reapplied.

| Run | Worker | `pthread_self` FL | `pthread_self` glibc | fl/glibc | Verdict |
|---|---|---:|---:|---:|---|
| old source | `ovh-a` | 1.91 ns | 1.70 ns | 1.13x | LOSS |
| candidate | `ovh-a` | 1.31 ns | 1.73 ns | 0.75x | WIN |

Self ratio: `1.31 / 1.91 = 0.686x`, a 31.4% cut in the deployed
`pthread_self` hot path.

Candidate full scorecard on `ovh-a`:

| Class | Count |
|---|---:|
| WIN | 16 |
| NEUTRAL | 1 (`clock_gettime`, 1.02x) |
| LOSS | 1 (`time`, 1.89x) |

The remaining `time()` loss is unrelated and remains routed to the deeper vDSO
timing track. Do not retry the rejected direct-vDSO-pointer cache, `time()`-only
cache, or timing split families for this bead.

## Validation

```bash
git diff --check -- crates/frankenlibc-abi/src/pthread_abi.rs
rustfmt --edition 2024 --check crates/frankenlibc-abi/src/pthread_abi.rs
```

Result: pass.

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_VISIBILITY=summary \
  rch exec -- cargo test -j 1 -p frankenlibc-abi \
    --test pthread_thread_lifecycle_test -- --nocapture --test-threads=1
```

Result on `hz1`: 17 passed, 0 failed, 5 ignored.

```bash
env AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-a \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
  RCH_REQUIRE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_BUILD_SLOTS=1 \
  RCH_VISIBILITY=summary \
  rch exec -- cargo test -j 1 -p frankenlibc-abi \
    --test conformance_diff_pthread -- --nocapture --test-threads=1
```

Result on `vmi1227854`: 7 passed, 0 failed; coverage report `pthread.h
primitives`, 18 functions, 0 divergences.

The candidate bench itself compiled the release `frankenlibc-abi` path through
`frankenlibc-bench`. Warnings emitted during remote builds were pre-existing
core/ABI lint warnings outside this touched hunk.

## Decision

Keep. This turns the reproduced `pthread_self` row from loss to win on the same
worker, preserves forced-native correctness, and leaves the broader timing loss
explicitly routed elsewhere.
