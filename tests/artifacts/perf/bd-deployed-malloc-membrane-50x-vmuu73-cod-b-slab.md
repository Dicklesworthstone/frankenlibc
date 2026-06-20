# bd-deployed-malloc-membrane-50x-vmuu73 cod-b slab reject

Date: 2026-06-20
Agent: BlackThrush / cod-b
Target: deployed strict `calloc/free` small-size residual in `calloc_glibc_bench`

## Candidate

Bounded exact hot-class slab for strict `calloc/free`:

- classes: 16 B, 256 B, 4096 B
- per reentry slot: 8 cached freed host blocks per class
- global exact live table so cross-thread `free`/`realloc` could identify cached blocks
- cache hit path: pop host block, zero class bytes, skip fallback table while live
- `free`: return cached-live block to current slot's slab or native `free` on overflow
- `realloc`: same/smaller cached block returns in place; growth exits through native `realloc`

The source compiled and measured, then was reverted because the target rows regressed.

## Commands

Current-head baseline:

```bash
AGENT_NAME=BlackThrush \
BR_AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_REQUIRE_REMOTE=1 \
RCH_VISIBILITY=summary \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR,AGENT_NAME,BR_AGENT_NAME \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --features abi-bench \
  --bench calloc_glibc_bench -- --measurement-time 2 --warm-up-time 1 --noplot
```

Candidate used the same command pinned to `vmi1227854`:

```bash
RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 ...
```

Worker for both accepted comparisons: `vmi1227854`.

## `calloc_cycle` p50 evidence

| Size | Baseline FL | Baseline glibc | Baseline FL/glibc | Candidate FL | Candidate glibc | Candidate FL/glibc | Candidate/Base FL | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 79.578 ns | 4.754 ns | 16.74x | 120.002 ns | 4.584 ns | 26.18x | 1.508x | REGRESSION |
| 256 | 211.482 ns | 19.300 ns | 10.96x | 251.255 ns | 19.587 ns | 12.83x | 1.188x | REGRESSION |
| 4096 | 247.232 ns | 64.609 ns | 3.83x | 295.500 ns | 48.217 ns | 6.13x | 1.195x | REGRESSION |
| 65536 | 612.980 ns | 421.758 ns | 1.45x | 611.348 ns | 406.034 ns | 1.51x | 0.997x | neutral |
| 262144 | 1815.999 ns | 1570.867 ns | 1.16x | 1863.658 ns | 1491.685 ns | 1.25x | 1.026x | loss |
| 1048576 | 8515.143 ns | 8334.562 ns | 1.02x | 8560.236 ns | 8265.335 ns | 1.04x | 1.005x | neutral |
| 4194304 | 43437.303 ns | 41499.453 ns | 1.05x | 41947.353 ns | 42680.307 ns | 0.98x | 0.966x | noisy win |

## `calloc_cycle` mean evidence

| Size | Baseline FL | Baseline glibc | Baseline FL/glibc | Candidate FL | Candidate glibc | Candidate FL/glibc | Candidate/Base FL | Verdict |
|---:|---:|---:|---:|---:|---:|---:|---:|---|
| 16 | 81.494 ns | 4.349 ns | 18.74x | 117.391 ns | 4.463 ns | 26.30x | 1.441x | REGRESSION |
| 256 | 214.920 ns | 18.294 ns | 11.75x | 259.806 ns | 18.570 ns | 13.99x | 1.209x | REGRESSION |
| 4096 | 248.776 ns | 66.327 ns | 3.75x | 300.923 ns | 47.168 ns | 6.38x | 1.210x | REGRESSION |
| 65536 | 620.925 ns | 431.737 ns | 1.44x | 613.246 ns | 408.567 ns | 1.50x | 0.988x | neutral |
| 262144 | 1808.497 ns | 1546.551 ns | 1.17x | 1782.273 ns | 1493.866 ns | 1.19x | 0.985x | neutral |
| 1048576 | 8603.094 ns | 8287.700 ns | 1.04x | 8490.660 ns | 8312.175 ns | 1.02x | 0.987x | neutral |
| 4194304 | 43133.942 ns | 42279.725 ns | 1.02x | 42321.431 ns | 42563.953 ns | 0.99x | 0.981x | noisy neutral |

## `realloc_cycle` screen

The slab touched `realloc` only to preserve ownership if a cached-live pointer
escaped through growth. It did not produce a useful realloc win.

| Workload | Baseline FL p50 | Candidate FL p50 | Candidate/Base FL | Candidate FL/glibc p50 | Verdict |
|---|---:|---:|---:|---:|---|
| same_256 | 86.951 ns | 76.442 ns | 0.879x | 27.18x | still loss |
| same_class_shrink_256_to_240 | 162.293 ns | 161.652 ns | 0.996x | 23.50x | neutral |
| cross_class_shrink_256_to_128 | 227.781 ns | 239.695 ns | 1.052x | 10.15x | regression vs FL |
| same_class_shrink_4096_to_3584 | 162.977 ns | 157.119 ns | 0.964x | 7.75x | neutral |

## Decision

REJECTED and source reverted.

The candidate attacks exactly the rows it was supposed to improve, but those
rows regressed on the same worker while glibc stayed stable:

- 16 B p50 +50.8%, mean +44.1%
- 256 B p50 +18.8%, mean +20.9%
- 4096 B p50 +19.5%, mean +21.0%

Likely root cause: for this benchmark shape, the current strict path is already
near the busy main-namespace native `calloc` cost, while the slab adds live-table
hash probes and a mandatory zero pass on every hit. Avoiding fallback-table
insert/remove does not repay that added work for 16/256/4096 B.

Retry predicate: do not retry bounded exact hot-class slab caching for deployed
strict `calloc/free` as a standalone lever. A future allocator attempt needs a
different shape: either remove enough code from the existing strict path without
an extra live table, or change the benchmarked ownership model with proof and a
same-worker win against current FL and glibc.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-abi/src/malloc_abi.rs`: passed before benchmark and after revert.
- `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b cargo check -p frankenlibc-abi --lib`: passed before benchmark and after revert, with known pre-existing warnings.
- Candidate `calloc_glibc_bench`: passed/ran to completion via `rch` on `vmi1227854`.
- Source action: candidate source reverted; only evidence/docs remain.
