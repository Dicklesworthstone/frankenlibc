# bd-2g7oyh.498 pthread_self Cell fast-cache BOLD-VERIFY

## Bead

- ID: `bd-2g7oyh.498`
- Title: `perf: pthread_self Cell fast-cache pending bench`
- Assignee: `cod-a`
- Status after this batch: `closed`

## Disk-Low Constraint

The root filesystem was at critical pressure during this pass:

```text
sbh status: overall critical
df -h /data/projects/frankenlibc: 47G available, 98% used
du -sh /data/projects/frankenlibc: 37G
```

Per the turn directive, no new `cargo bench`, `cargo build`, `cargo check`, or
`cargo test` command was started.

## Code-Only Lever

`native_pthread_self` already caches the per-thread value, but in the default
non-`owned-tls-cache` build the hot hit still borrowed the larger
`PthreadTlsState` through `RefCell::try_borrow_mut()`. This pass adds a
thread-local `Cell<libc::pthread_t>` fast lane for that one immutable value.

Behavior preservation:

- `pthread_self()` remains constant for a thread after the first resolved value.
- The existing `PthreadTlsState.current_pthread_self_cache` stays synchronized,
  so fallback paths and feature builds keep the same state contract.
- Host-thread trampoline publication writes through the same helper, preserving
  host-backed `pthread_t` identity instead of falling back to the kernel TID.
- A zero cached value remains the miss sentinel; Linux `pthread_self()` values
  are nonzero for supported targets.

The BOLD-VERIFY follow-up reused the existing warm target dir per the disk-low
directive:

```text
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a
```

## 2026-06-21 incidental bench row

The single allowed partial-resume bench targeted the timing bead, but the mixed
`strtol_glibc_bench` executable also emitted the `pthread_self` row:

```text
AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot --sample-size 10 \
  --warm-up-time 1 --measurement-time 2
```

RCH selected `hz1`.

| Row | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `pthread_self` | 2.14 ns | 2.99 ns | 0.72x | WIN (bench only) |

Do not close this bead from the bench row alone. The focused pthread
lifecycle/identity conformance gate still needs to pass before this code-only
lever can be accepted as complete.

## 2026-06-21 BOLD-VERIFY closeout

The focused verification bench used the warm target dir and a small per-crate
bench command:

```text
AGENT_NAME=cod-a BR_AGENT_NAME=cod-a RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot --sample-size 10 \
  --warm-up-time 1 --measurement-time 2
```

RCH selected `vmi1149989`.

| Row | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `pthread_self` | 1.47 ns | 1.71 ns | 0.86x | WIN |

Keep. The deployed default `pthread_self` path still beats host glibc with the
thread-local `Cell` hot hit.

The verification pass did find a correctness hazard in forced-native managed
tests: inherited/stale pthread-self caches could make distinct managed threads
compare equal. The fix keeps the deployed default fast path, but makes
`cached_pthread_self_fast()` return `None` whenever
`force_native_threading_enabled()` is active and avoids publishing to the `Cell`
cache in that mode. Forced-native tests recompute identity rather than trusting
cached state.

Validation:

```text
rustfmt --edition 2024 --check crates/frankenlibc-abi/src/pthread_abi.rs
PASS

cargo fmt -p frankenlibc-abi --check
FAIL: pre-existing broad rustfmt drift outside pthread_abi.rs

rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test pthread_thread_lifecycle_test \
  pthread_equal_reflexive_and_distinct_threads_not_equal -- --nocapture \
  --test-threads=1
PASS: 1 passed

rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test pthread_thread_lifecycle_test -- --nocapture --test-threads=1
PASS: 17 passed, 0 failed, 5 ignored

rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test conformance_diff_pthread -- --nocapture --test-threads=1
PASS: 7 passed, 0 failed; pthread.h primitives: 18 functions, 0 divergences
```

The rch test commands emitted broad pre-existing warnings in core/abi support
code, but no pthread-specific compile error. Full workspace check/clippy were
not run in this disk-low pass because the user explicitly prohibited cold full
workspace builds.
