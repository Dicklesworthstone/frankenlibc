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

## 2026-06-21 partial-resume measurement

The first requested spelling included `cargo bench --release`, but this Cargo
rejects `--release` for `bench`; that failed before any build or benchmark ran.
The corrected single actual bench used Cargo's standard optimized bench profile:

```text
AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- --noplot --sample-size 10 \
  --warm-up-time 1 --measurement-time 2
```

RCH selected `hz1` and rewrote the target dir to a worker-scoped path, so this
was a cold-ish remote bench rather than a warmed same-worker A/B.

Relevant rows:

| Row | FrankenLibC | glibc | Ratio | Verdict |
|---|---:|---:|---:|---|
| `clock_gettime` | 38.23 ns | 33.33 ns | 1.15x | LOSS vs glibc, partial gap-cut vs prior residual rows |
| `time` | 7.10 ns | 3.57 ns | 1.99x | LOSS, not touched by this lever |
| `pthread_self` | 2.14 ns | 2.99 ns | 0.72x | WIN, belongs to `bd-2g7oyh.498` |

Full mixed bench rows from the same run:

```text
strtol_dec_short: fl=8.71ns glibc=18.19ns fl/glibc=0.48
strtol_dec_long: fl=17.61ns glibc=38.01ns fl/glibc=0.46
strtol_hex: fl=28.66ns glibc=35.25ns fl/glibc=0.81
atoi_short: fl=7.50ns glibc=20.36ns fl/glibc=0.37
atoi_long: fl=20.55ns glibc=39.69ns fl/glibc=0.52
atol_short: fl=7.64ns glibc=18.36ns fl/glibc=0.42
atol_long: fl=21.37ns glibc=37.97ns fl/glibc=0.56
atoll_short: fl=6.75ns glibc=18.89ns fl/glibc=0.36
atoll_long: fl=19.43ns glibc=37.84ns fl/glibc=0.51
strtod_int: fl=26.54ns glibc=72.43ns fl/glibc=0.37
strtod_simple: fl=133.43ns glibc=137.42ns fl/glibc=0.97
strtod_sci: fl=40.91ns glibc=93.77ns fl/glibc=0.44
rand: fl=5.36ns glibc=9.58ns fl/glibc=0.56
getenv_hit: fl=26.25ns glibc=38.27ns fl/glibc=0.69
getenv_miss: fl=49.35ns glibc=55.81ns fl/glibc=0.88
clock_gettime: fl=38.23ns glibc=33.33ns fl/glibc=1.15
time: fl=7.10ns glibc=3.57ns fl/glibc=1.99
pthread_self: fl=2.14ns glibc=2.99ns fl/glibc=0.72
```

Focused behavior gate:

```text
AGENT_NAME=BlackThrush BR_AGENT_NAME=cod-b RCH_REQUIRE_REMOTE=1 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- cargo test -j 1 -p frankenlibc-abi \
  --test conformance_diff_clock -- --nocapture
```

RCH selected `vmi1152480`; result: 6 passed, 0 failed, zero divergences.

Action: keep as a measured partial gap-cut, not a glibc domination claim. The
remaining `clock_gettime` and `time(NULL)` losses stay routed deeper; do not
retry the rejected resolved-vDSO-pointer cache or buffered-hit-counter family.
