# bd-6j8kg9 getenv miss focused gate

Date: 2026-06-14
Worker: `vmi1227854`
Base commit: `7424ffe0b` (`perf(membrane): fast-path strict nominal decisions`)
Verdict: no-code rejected; do not ship the seqlock/RCU source edit for this target.

## Target

`bd-6j8kg9` claimed a `getenv` miss gap caused by `ENVIRON_LOCK` on every read-side environment-table walk. The proposed primitive was a seqlock: writers version the environment table while readers walk optimistically and retry if the version changes.

## Alien primitive screen

- Seqlock alone is unsafe over the current writer implementation because `native_setenv` and `native_putenv_impl` can grow `HOST_ENVIRON` through `host_passthrough_realloc`.
- A reader that observes the old array pointer before the writer reallocates can dereference freed array storage before the final sequence check.
- The safe source lever would have to be a combined RCU/seqlock copy-publish scheme: allocate a new array, publish it under a version counter, and retain or epoch-retire old arrays.
- That source lever was not attempted because the focused current-head gate did not reproduce a positive gap.

## Baseline

Command:

```bash
env RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_MODE=hardened CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-6j8kg9-baseline2-target-20260614T0550 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-6j8kg9-baseline2-criterion-20260614T0550 \
  cargo bench -j 1 -p frankenlibc-bench --features abi-bench --bench glibc_baseline_bench -- \
  glibc_baseline_getenv_miss --sample-size 60 --warm-up-time 1 --measurement-time 3 --noplot
```

Result:

- FrankenLibC `getenv_miss`: Criterion `[31.750 us 32.629 us 33.510 us]`; custom p50/mean `31982.381/32999.803 ns`.
- Host glibc `getenv_miss`: Criterion `[35.608 us 36.170 us 36.756 us]`; custom p50/mean `36856.164/37458.291 ns`.

The current FrankenLibC read path is faster than host on this focused row, so the proposed synchronization rewrite has Score `0.0` for this target.

## Behavior proof

No `stdlib_abi.rs` source change was made.

Command:

```bash
env RCH_REQUIRE_REMOTE=1 RCH_FORCE_REMOTE=1 RCH_QUEUE_WHEN_BUSY=1 RCH_VISIBILITY=summary \
  RCH_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 \
  rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-6j8kg9-proof-target-20260614T0545 \
  cargo test -j 1 -p frankenlibc-abi --test metamorphic_getenv -- --nocapture --test-threads=1
```

Result: 9/9 tests passed.

Golden SHA:

```text
903400ec5bd5d80a648c5d1883f60a5ab36947af57bae04cc5aafbe8581df3c8  crates/frankenlibc-abi/tests/metamorphic_getenv.rs
```

Isomorphism:

- Ordering/tie-breaking: unchanged; no environment lookup implementation change.
- Floating point: N/A.
- RNG: unchanged.
- Error/null behavior: unchanged; metamorphic getenv/setenv/unsetenv/secure_getenv suite passed.

## Next route

Do not return to `getenv` without a fresh focused same-worker gap on current source. If a future profile reproduces the gap, the admissible primitive is RCU/seqlock copy-publish with retained or epoch-retired arrays plus a concurrent reader/writer stress proof; a bare seqlock over `realloc` remains rejected as memory-unsafe.
