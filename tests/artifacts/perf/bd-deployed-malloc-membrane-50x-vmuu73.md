# `bd-deployed-malloc-membrane-50x-vmuu73` deployed calloc gauntlet

Date: 2026-06-19

Agent: `BlackThrush` / `cod-a`

Worker: `vmi1293453`

Target dir: `/data/projects/.rch-targets/frankenlibc-cod-a`

Bench command:

```bash
AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
RCH_VERBOSE=1 \
RCH_WORKER=vmi1293453 \
RCH_WORKERS=vmi1293453 \
RCH_PREFERRED_WORKER=vmi1293453 \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

`fl` is the deployed FrankenLibC ABI `calloc` + `free` cycle. `glibc` is the
isolated host glibc comparator in the same benchmark. All keep/reject decisions
below use same-worker evidence.

## Current-head deployed baseline

| Size | FL p50 ns | glibc p50 ns | p50 ratio | FL mean ns | glibc mean ns | mean ratio | Verdict vs glibc |
|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 123.295 | 11.352 | 10.86x | 146.359 | 26.956 | 5.43x | LOSS |
| 256 | 780.699 | 35.223 | 22.16x | 810.707 | 81.970 | 9.89x | LOSS |
| 4096 | 890.361 | 107.465 | 8.29x | 974.452 | 153.707 | 6.34x | LOSS |
| 65536 | 2062.725 | 1112.104 | 1.855x | 2353.382 | 1377.383 | 1.708x | LOSS |
| 262144 | 5567.124 | 4146.188 | 1.343x | 6490.414 | 4995.765 | 1.299x | LOSS |
| 1048576 | 19433.662 | 20694.380 | 0.939x | 31152.120 | 25799.618 | 1.207x | WIN p50 / LOSS mean |
| 4194304 | 86130.730 | 89953.772 | 0.958x | 110318.416 | 104400.972 | 1.057x | WIN p50 / LOSS mean |

Baseline p50+mean score: 2 wins, 0 neutral, 12 losses.

## Attempt A: lock-free fallback ownership table

Lever: replace the fallback allocation table's global spinlock insert/remove
path with a per-slot reserved sentinel and compare-exchange reservation. This
was the lock-free/custom-allocator route: remove one global serialization point
before revisiting deeper allocator layout work.

Partial same-worker after-run:

| Size | Candidate FL p50 ns | Candidate FL mean ns | Current-head FL p50 delta | Current-head FL mean delta | Same-run glibc p50 ns | Same-run glibc mean ns | Same-run ratio p50 / mean | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 153.918 | 195.183 | +24.8% | +33.4% | 12.577 | 27.135 | 12.24x / 7.19x | LOSS |
| 256 | 854.457 | 943.974 | +9.45% | +16.4% | not collected | not collected | not collected | LOSS |

Criterion reported regressions for both early `fl` rows, so the run was stopped
and the source was reverted before any commit.

Verdict: **REJECTED**. Retry condition: do not retry the single-table CAS route
as a standalone lever. If allocator metadata stays hot, use a materially
different shape such as per-thread metadata magazines with bounded drain,
non-overlapping hot/cold metadata, or direct deployment of the faster core
allocator path.

## Attempt B: strict-mode free skips ownership probe

Lever: in strict host-allocator mode, route `free` straight to the host allocator
instead of probing `check_ownership` first. This was the branchless/elide-known
certificate route: strict public allocations are host/fallback allocations, so
the membrane ownership query looked like pure overhead on paper.

Same-worker after-run:

| Size | Candidate FL p50 ns | Candidate glibc p50 ns | p50 ratio | Candidate FL mean ns | Candidate glibc mean ns | mean ratio | Current-head FL p50 delta | Current-head FL mean delta | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 119.678 | 11.797 | 10.14x | 151.346 | 24.820 | 6.10x | -2.9% | +3.4% | LOSS |
| 256 | 759.772 | 37.482 | 20.27x | 868.428 | 66.010 | 13.16x | -2.7% | +7.1% | LOSS |
| 4096 | 831.496 | 117.071 | 7.10x | 2111.643 | 192.229 | 10.99x | -6.6% | +116.7% | LOSS |
| 65536 | 1889.139 | 1091.278 | 1.731x | 2212.229 | 1372.542 | 1.612x | -8.4% | -6.0% | LOSS |
| 262144 | 5070.014 | 4050.781 | 1.252x | 6046.730 | 6800.711 | 0.889x | -8.9% | -6.8% | LOSS p50 / WIN mean |
| 1048576 | 21117.486 | 20783.943 | 1.016x | 25908.435 | 24963.808 | 1.038x | +8.7% | -16.8% | NEUTRAL p50 / LOSS mean |
| 4194304 | 101202.424 | 96460.805 | 1.049x | 147881.717 | 117259.922 | 1.261x | +17.5% | +34.1% | LOSS |

Candidate p50+mean score vs glibc: 1 win, 1 neutral, 12 losses.

Criterion reported statistically significant regressions for `fl/1048576` and
`fl/4194304`, and the 4 MiB row regressed both p50 and mean versus current head.
The source was reverted before commit.

Verdict: **REJECTED**. Retry condition: do not retry free-path ownership elision
as a standalone lever. The residual gap is dominated by deployed allocation
surface/metadata cost at small sizes and large-size tail behavior, not this one
branch.

## Validation

Pre-revert focused checks during the experiments:

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/malloc_abi.rs`
- `cargo test -p frankenlibc-abi --test malloc_abi_test -- --nocapture`
- `cargo check -p frankenlibc-bench --features abi-bench --bench calloc_glibc_bench`
- `cargo check -p frankenlibc-abi --lib`

Post-revert confirmation on the final tree:

- `cargo test -p frankenlibc-abi --test malloc_abi_test -- --nocapture`: 53
  passed, 1 ignored.
- `cargo check -p frankenlibc-bench --features abi-bench --bench
  calloc_glibc_bench`: passed.

All focused checks passed with only pre-existing warnings. Full workspace gates
remain blocked by unrelated repo-wide issues: broad `cargo fmt --check` reports
pre-existing generated/math/iconv formatting drift, and `cargo check
--workspace --all-targets` is blocked by the pre-existing scratch
`zz_scratch_divmin.rs` test compile errors.

## Route-out

The next measured attempt should not be another small branch shave. Candidate
lanes worth benchmarking:

- Deploy the fastest core allocator route more directly through ABI strict mode.
- Split fallback metadata into per-thread hot slots plus a cold global index.
- Eliminate fallback-table participation for common strict `calloc/free` pairs
  via a proof-carrying size certificate.
- Add a benchmark variant that separates `calloc` zero-fill from `free` metadata
  so future attempts target the actual losing substage.
