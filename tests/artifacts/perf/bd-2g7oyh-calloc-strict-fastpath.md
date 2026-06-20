# bd-2g7oyh calloc strict fast-path tombstone compaction reject

Date: 2026-06-20
Agent: `BlackThrush` / `cod-a`
Decision: **REVERTED**

## Candidate

The candidate changed `crates/frankenlibc-abi/src/malloc_abi.rs`
`fallback_remove_sized` to clear a removed open-addressing slot to `EMPTY` when
the next slot was empty, then coalesce adjacent preceding tombstones. Intended
effect: reduce fallback allocation table probe/tombstone drag under strict
`calloc/free` churn.

## Commands

Focused bench:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

Focused allocator guard after reverting the candidate source:

```bash
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
cargo test -p frankenlibc-abi --test malloc_abi_test -- --nocapture --test-threads=1
```

Result: 53 passed, 0 failed, 1 ignored. The run emitted only pre-existing
core/ABI warnings.

Per-crate release build after reverting the candidate source:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_QUEUE_WHEN_BUSY=1 \
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800 \
rch exec -- cargo build -p frankenlibc-abi --release
```

Result: passed on `hz1` in 121.7 s. The run emitted only pre-existing
core/ABI warnings and the usual missing SMT solver notice.

## Same-worker baseline

Same-worker historical baseline from
`tests/artifacts/perf/bd-deployed-malloc-membrane-50x-vmuu73.md`:
worker `vmi1293453`, target dir `/data/projects/.rch-targets/frankenlibc-cod-a`.

| size | baseline fl p50 | baseline fl mean | baseline glibc p50 | baseline glibc mean |
|---|---:|---:|---:|---:|
| 16 B | 123.295 ns | 146.359 ns | 11.352 ns | 26.956 ns |
| 256 B | 780.699 ns | 810.707 ns | 35.223 ns | 81.970 ns |
| 4096 B | 890.361 ns | 974.452 ns | 107.465 ns | 153.707 ns |
| 65536 B | 2062.725 ns | 2353.382 ns | 1112.104 ns | 1377.383 ns |
| 262144 B | 5567.124 ns | 6490.414 ns | 4146.188 ns | 4995.765 ns |
| 1048576 B | 19433.662 ns | 31152.120 ns | 20694.380 ns | 25799.618 ns |
| 4194304 B | 86130.730 ns | 110318.416 ns | 89953.772 ns | 104400.972 ns |

## Candidate run

Worker: `vmi1293453`
RCH completion: exit 0, remote elapsed 427.4 s

| size | fl p50 | fl mean | glibc p50 | glibc mean | p50 fl/glibc | mean fl/glibc |
|---|---:|---:|---:|---:|---:|---:|
| 16 B | 126.620 ns | 160.301 ns | 11.529 ns | 22.275 ns | 10.98x | 7.20x |
| 256 B | 747.608 ns | 802.223 ns | 37.921 ns | 61.376 ns | 19.72x | 13.07x |
| 4096 B | 823.597 ns | 957.779 ns | 153.098 ns | 206.916 ns | 5.38x | 4.63x |
| 65536 B | 1890.445 ns | 2231.015 ns | 1094.101 ns | 1362.809 ns | 1.73x | 1.64x |
| 262144 B | 5016.522 ns | 11097.125 ns | 4126.736 ns | 5064.784 ns | 1.22x | 2.19x |
| 1048576 B | 21035.057 ns | 31683.682 ns | 19578.059 ns | 23575.829 ns | 1.07x | 1.34x |
| 4194304 B | 108814.652 ns | 138659.193 ns | 118209.750 ns | 155904.977 ns | 0.92x | 0.89x |

## Baseline-to-candidate comparison

| size | p50 candidate / baseline | mean candidate / baseline | decision |
|---|---:|---:|---|
| 16 B | 1.027x | 1.095x | regression |
| 256 B | 0.958x | 0.990x | small win |
| 4096 B | 0.925x | 0.983x | win |
| 65536 B | 0.916x | 0.948x | win |
| 262144 B | 0.901x | 1.710x | p50 win, mean/tail regression |
| 1048576 B | 1.082x | 1.017x | regression |
| 4194304 B | 1.263x | 1.257x | regression |

## Verdict

This is not a shippable lever. It leaves every target size through 1 MiB slower
than same-run glibc, only wins the 4 MiB p50/mean row, and regresses absolute
same-worker baseline p50 at 16 B, 1 MiB, and 4 MiB. The 262 KiB row also shows a
bad mean/tail regression despite a p50 improvement.

Action taken: source reverted to the prior tombstone-on-remove behavior. The
only retained output is this evidence artifact plus the central negative ledger
and scorecard updates.

Retry predicate: do not retry deletion-time tombstone clearing/coalescing. The
next allocator attempt should be a materially different shape, preferably a slim
strict `calloc/free` fast path or a same-run paired profile that identifies the
diffuse allocator overhead before changing metadata policy.
