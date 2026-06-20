# bd-zexi06 — pure-literal `snprintf` fast path

Agent: BlackThrush / cod-b
Date: 2026-06-20
Crates: `frankenlibc-abi`, `frankenlibc-bench`
Worker target root: `CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b`

## Lever

Specialize strict-mode `snprintf`, `sprintf`, and `vsnprintf` formats that contain
no `%` before the NUL terminator. The final kept path:

- Detects no-conversion formats before runtime policy and printf parsing.
- Caches literal format lengths only when the full format string lives in a
  non-writable `/proc/self/maps` range, preserving mutable stack/heap format
  behavior through the uncached scan path.
- Copies literal output with exact unaligned word chunks instead of routing a
  tiny variable copy through generic `memcpy` setup.

## Head-to-head measurements

Command shape:

```bash
AGENT_NAME=BlackThrush BR_AGENT_NAME=BlackThrush \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-b \
RCH_ENV_ALLOWLIST=CARGO_TARGET_DIR \
rch exec -- cargo bench -j 1 -p frankenlibc-bench \
  --bench stdio_glibc_baseline_bench --features abi-bench -- \
  stdio_glibc_baseline_snprintf_literal --noplot --sample-size 50
```

| Stage | Worker | FrankenLibC mean | glibc mean | fl/glibc | Verdict |
|---|---|---:|---:|---:|---|
| Baseline with benchmark only | `hz1` | 1.9118 us | 26.287 ns | 72.73x | LOSS |
| No-render literal shortcut | `vmi1227854` | 55.287 ns | 14.563 ns | 3.80x | LOSS |
| Read-only length cache | `vmi1149989` | 27.941 ns | 17.671 ns | 1.58x | LOSS |
| Read-only cache + word copy | `hz1` | 10.960 ns | 22.036 ns | 0.497x | WIN |

Same-worker `hz1` self-speedup: 1.9118 us -> 10.960 ns = 174.4x faster.

## Regression guards

Adjacent exact string groups, same-worker `hz1`:

| Workload | FrankenLibC mean | glibc mean | fl/glibc | Verdict |
|---|---:|---:|---:|---|
| `snprintf("%s\n")` | 24.130 ns | 35.897 ns | 0.672x | WIN |
| `snprintf("%s")` | 23.474 ns | 28.263 ns | 0.831x | WIN |

## Validation

- `rch exec -- cargo test -j 1 -p frankenlibc-abi --test conformance_diff_stdio_printf diff_snprintf -- --nocapture`
  - 7 passed, 0 failed.
- `rch exec -- cargo build -j 1 -p frankenlibc-abi --release`
  - passed on `hz1`.
- `cargo fmt --check` and file-scoped `rustfmt --check` are blocked by broad
  pre-existing formatting drift in generated tables and older ABI/bench code;
  no formatting churn was applied in this perf commit.

## Result

Kept. The simple no-render and cache-only variants were not shippable by the
ledger threshold; the final cache + exact word-copy path is a same-worker
deployed ABI win over host glibc.
