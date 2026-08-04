# bd-65p87u allocator prerequisite attempt

Date: 2026-08-04

## Required gate

Before a liveness-map replacement for `segment_free` can be considered, the
bead requires a fixed-path eight-thread churn run to complete 20/20 and a
matched no-call-graph multi-threaded attribution profile showing that at least
15% of samples remain in `segment_free`, with at least 80% of that frame on
the liveness RMW.

## Attempted remote churn gate

Two strict-remote invocations were submitted with the exact command below:

```text
RCH_REQUIRE_REMOTE=1 env -u CARGO_TARGET_DIR rch exec -- cargo test -j 1 -p frankenlibc-abi --test malloc_abi_test reentry_slots_stay_single_owner_under_thread_churn -- --exact --nocapture
```

RCH selected `vmi1293453` for the first run and `vmi1264463` for the second.
Both runs completed the remote workspace transfer, but neither returned a Cargo
test completion record, pass/fail status, or profiler output. Consequently the
result is **0/20 completed**, not a partial pass.

## Decision

No no-call-graph attribution profile was run and no allocator code was changed.
The prerequisites for a liveness-map lever remain unsatisfied. Retry only after
the strict-remote executor returns completed Cargo results for the churn gate.
