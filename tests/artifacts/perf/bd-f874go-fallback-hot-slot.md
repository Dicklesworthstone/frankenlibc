# bd-f874go fallback-table exact hot-slot reject

Date: 2026-06-20

Agent: `BlackThrush` / `cod-b`

## Target

The deployed strict `calloc/free` gap remains largest at small sizes after the
native reentry-slot keep. The tested lever was a per-thread exact fallback-table
slot cache:

- `fallback_insert_sized` returned the open-addressed table index for strict
  `malloc` and `calloc`;
- the current allocator reentry slot cached `(ptr, index)`;
- strict `free` tried an atomic exact-slot remove before the existing locked
  fallback-table remove;
- the old locked table stayed as the correctness path for misses and all other
  callers.

This was deliberately different from the rejected whole-table CAS route and the
rejected tombstone compaction route: it only optimized same-thread exact
`calloc/free` cycles.

## Current-head baseline

Command:

```bash
AGENT_NAME=cod-b \
RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- env AGENT_NAME=cod-b FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

`rch` selected `vmi1153651`; `HEAD=72ebe242c`.

| Size | FL p50 ns | glibc p50 ns | p50 ratio | FL mean ns | glibc mean ns | mean ratio | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 114.960 | 10.819 | 10.63x | 140.949 | 25.417 | 5.55x | LOSS |
| 256 | 435.260 | 37.111 | 11.73x | 562.837 | 56.385 | 9.98x | LOSS |
| 4096 | 498.224 | 104.550 | 4.77x | 538.890 | 156.296 | 3.45x | LOSS |
| 65536 | 1536.001 | 1042.184 | 1.47x | 1865.195 | 1358.150 | 1.37x | LOSS |
| 262144 | 4372.561 | 4142.734 | 1.06x | 5460.396 | 4884.627 | 1.12x | LOSS |
| 1048576 | 20454.473 | 20917.348 | 0.98x | 23103.947 | 29813.969 | 0.77x | WIN |
| 4194304 | 102830.806 | 96288.569 | 1.07x | 158753.434 | 117990.544 | 1.35x | LOSS |

Baseline score: 2 wins, 0 neutral, 12 losses across p50+mean cells.

## Candidate screen

Command:

```bash
AGENT_NAME=cod-b \
RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=900 \
RCH_WORKER=vmi1153651 \
RCH_PREFERRED_WORKER=vmi1153651 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
rch exec -- env AGENT_NAME=cod-b FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
  cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

`rch` selected `vmi1167313` despite the preference, so the candidate cannot be
kept using baseline-vs-candidate deltas. It is still a valid in-run deployed
FrankenLibC-vs-glibc screen, and that screen was not promising enough to justify
another paired run.

| Size | Candidate FL p50 ns | glibc p50 ns | p50 ratio | Candidate FL mean ns | glibc mean ns | mean ratio | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 114.149 | 10.126 | 11.27x | 151.006 | 25.867 | 5.84x | LOSS |
| 256 | 413.707 | 34.482 | 12.00x | 542.141 | 46.782 | 11.59x | LOSS |
| 4096 | 497.501 | 144.469 | 3.44x | 13213.080 | 193.641 | 68.24x | LOSS/tail outlier |
| 65536 | 1474.389 | 1016.307 | 1.45x | 1781.323 | 1227.567 | 1.45x | LOSS |
| 262144 | 4895.259 | 3977.730 | 1.23x | 5544.162 | 4793.244 | 1.16x | LOSS |
| 1048576 | 20201.254 | 19162.883 | 1.05x | 26756.896 | 22411.227 | 1.19x | LOSS |
| 4194304 | 95059.017 | 94918.658 | 1.00x | 128244.779 | 120525.788 | 1.06x | NEUTRAL p50 / LOSS mean |

Candidate screen score: 0 wins, 1 neutral, 13 losses across p50+mean cells.

## Decision

**REJECTED and reverted.** The exact hot-slot cache does not dominate glibc and
does not materially change the small-size loss ratios. It also introduces a bad
4 KiB mean/tail outlier and loses the 1 MiB row that baseline won.

Do not retry this per-thread exact fallback-slot cache as a standalone lever.
The next allocator attempt should either:

- measure a substage split that separates host allocator cost, fallback-table
  metadata, stats accounting, and native reentry guard cost in one run; or
- move to a materially different deployed path, such as a proof-carrying
  allocation certificate that removes fallback-table participation entirely for
  the common strict `calloc/free` pair.

## Validation

The source patch compiled inside the candidate `cargo bench` run and was then
reverted.

Post-revert gates:

- `rustfmt --edition 2024 crates/frankenlibc-abi/src/malloc_abi.rs`: passed
  and left no source diff.
- `git diff --check -- docs/NEGATIVE_EVIDENCE.md docs/RELEASE_READINESS_SCORECARD.md tests/artifacts/perf/bd-f874go-fallback-hot-slot.md .beads/issues.jsonl`: passed.
- `RCH_REQUIRE_REMOTE=1 rch exec -- cargo test -p frankenlibc-abi --test malloc_abi_test`:
  blocked by remote pressure (`critical_pressure=1`, `insufficient_slots=10`).
- `rch exec -- cargo test -p frankenlibc-abi --test malloc_abi_test -- --nocapture --test-threads=1`:
  local fallback under rch pressure, passed 53/0/1 ignored with pre-existing
  warnings.
- `RCH_REQUIRE_REMOTE=1 rch exec -- cargo build -p frankenlibc-abi --release`:
  remote `hz2`, passed with pre-existing warnings.
