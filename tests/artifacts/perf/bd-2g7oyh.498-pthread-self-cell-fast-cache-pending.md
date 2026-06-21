# bd-2g7oyh.498 pthread_self Cell fast-cache pending bench

## Bead

- ID: `bd-2g7oyh.498`
- Title: `perf: pthread_self Cell fast-cache pending bench`
- Assignee: `cod-b`
- Status after this batch: `in_progress`

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

## Pending Bench

Required next-turn gate, once disk pressure is handled:

```text
AGENT_NAME=BlackThrush CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench strtol_glibc_bench -- pthread_self --noplot --sample-size 80 \
  --warm-up-time 1 --measurement-time 3
```

Also run focused pthread lifecycle/conformance coverage before scoring the
lever as a keep.

Keep only if the same-worker `pthread_self` row improves without lifecycle
regression. Revert if the result is neutral/loss or if the pthread identity
contract diverges from host behavior.

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
