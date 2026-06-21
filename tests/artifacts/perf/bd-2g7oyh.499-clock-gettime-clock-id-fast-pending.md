# bd-2g7oyh.499 - clock_gettime stack-output/common-clock fast path (pending)

Date: 2026-06-21
Agent: BlackThrush / cod-b
Mode: code-only disk-low pass

## Disk state

The user reported `DISK-LOW (40G in frankenlibc)` and explicitly instructed not
to start a new Cargo bench/build this turn. No Cargo bench, build, check, or
test was started for this lever.

## Code lever

Target residual from the latest timing rows:

- `strtol_glibc_bench` `clock_gettime`: still slower than host glibc.
- `pthread_self` already has a separate pending code-only bead, so this pass
  does not stack another pthread change before measurement.

Implementation in `crates/frankenlibc-abi/src/time_abi.rs`:

- `clock_gettime` now treats an output `timespec` pointer within an 8 MiB window
  of the current stack frame as a likely stack object and skips the
  `known_remaining` fallback-allocation-table lookup for that case.
- Non-stack-looking pointers still use the previous tracked-allocation size
  check before the syscall/vDSO path.
- Common clock ids that were already accepted by the existing validators
  (`CLOCK_REALTIME`, `CLOCK_MONOTONIC`, coarse variants, `CLOCK_BOOTTIME`) get a
  local validity fast path before falling back to the existing
  `time_core::valid_clock_id` and `valid_clock_id_extended` checks.

This is intentionally not the rejected vDSO timing cache family:

- No cached resolved vDSO function pointer was added.
- No vDSO hit counter buffering was added.
- No `time(NULL)`-only runtime-ready or pipeline gate reduction was added.

## Behavior argument before bench

The prior `tracked_required_object_fits` check only rejects null or known
tracked allocations whose remaining size is smaller than `timespec`; untracked
stack pointers already pass because `known_remaining` returns `None`.

For likely current-stack outputs, the new path preserves that acceptance but
avoids probing the fallback allocation table. If the pointer is not actually
writable, the existing raw syscall/vDSO call remains the final writer and still
returns the kernel error path.

The clock-id fast path deliberately excludes `CLOCK_TAI`: it is vDSO-supported
but not currently accepted by `valid_clock_id_extended`, so including it here
would widen behavior. Less common accepted clocks still reach the same core
validators as before.

## Pending verification

Run after disk pressure clears, using the project target dir:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- clock_gettime --noplot
```

Focused conformance/guard suggestions:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- cargo test -p frankenlibc-abi --test time_abi_test -- --nocapture
```

Keep only if the same-worker `clock_gettime` ratio versus host glibc improves
without a focused time/vDSO conformance regression. Revert if the focused row is
neutral-with-cost or slower.
