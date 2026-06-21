# bd-baifnq fgetc strict single-lock probe

Date: 2026-06-21
Agent: cod-a / BlackThrush
Verdict: no source change; current focused dlmopen rows are already FrankenLibC wins.

## Commands

```bash
AGENT_NAME=cod-a RCH_WORKER=hz1 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench stdio_glibc_baseline_bench --profile release -- \
  stdio_glibc_baseline_fgetc_4096 --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

```bash
AGENT_NAME=cod-a RCH_WORKER=hz1 \
CARGO_TARGET_DIR=/data/projects/.rch-targets/frankenlibc-cod-a \
rch exec -- cargo bench -p frankenlibc-bench --features abi-bench \
  --bench stdio_glibc_baseline_bench --profile release -- \
  stdio_glibc_baseline_fgetc_unlocked_4096 --noplot --sample-size 50 \
  --warm-up-time 1 --measurement-time 3
```

## Results

| Workload | FrankenLibC median | host glibc median | ratio |
| --- | ---: | ---: | ---: |
| `stdio_glibc_baseline_fgetc_4096` | 300.66 us | 1.1433 ms | 0.263x |
| `stdio_glibc_baseline_fgetc_unlocked_4096` | 301.34 us | 1.4411 ms | 0.209x |

Scorecard: 2 WIN / 0 NEUTRAL / 0 LOSS for this focused bench.

## Decision

Do not ship a strict single-lock rewrite from this evidence. The current
single-thread dlmopen rows do not reproduce a loss, and the issue warns that a
naive collapse can change host-delegation ordering or hold the registry lock
across policy code. Keep the architectural registry-lock target open for a
deployed/LD_PRELOAD or multi-thread contention gate where FrankenLibC actually
loses.
