# bd-2g7oyh.398 exp10f focused gate no-code closeout

## Target

- Bead: `bd-2g7oyh.398`
- Profile row: `glibc_baseline_math/exp10f`
- Workload: `exp10f(x)` for `x in [0.5, 2.5)`
- Worker: `vmi1227854`
- Source baseline: `0655fbda9`

The bead was opened from a broad routing table where `exp10f` appeared slower than
host glibc. Per campaign discipline, the broad row was routing evidence only and
required a focused same-worker gate before any source change could be kept.

## Focused Baseline

Command:

```bash
RCH_WORKERS=vmi1227854 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd398-exp10f-baseline-target-20260614T0333 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd398-exp10f-baseline-criterion-20260614T0333 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/exp10f --noplot --sample-size 50 --warm-up-time 1 \
  --measurement-time 3
```

Focused result:

| impl | criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
|---|---:|---:|---:|---:|---:|
| FrankenLibC | `[264.68 ns 270.14 ns 275.81 ns]` | 283.178 | 287.507 | 320.500 | 357.110 |
| host glibc | `[321.10 ns 323.67 ns 326.60 ns]` | 321.977 | 326.649 | 352.852 | 431.000 |

## Verdict

NO-CODE REJECTED.

The focused same-worker gate collapsed and reversed the broad routing signal:
FrankenLibC is already faster than host glibc on p50 and mean for this row on
`vmi1227854`. The temporary exact-grid candidate was restored before closeout.

## Isomorphism

- Ordering preserved: yes, source unchanged.
- Tie-breaking unchanged: yes, source unchanged.
- Floating-point behavior: unchanged by construction.
- RNG: N/A.
- Golden outputs: unchanged by construction; `float32.rs` SHA-256 is
  `e7a1c94c56077c386aa43182a7ead70315bc74c6534a256692ad52d3a75567b6`.

## Route

Do not keep an `exp10f` source lever from this focused gate. Reprofile before
returning to `exp10f`; if it reappears, require a reproduced p50 and mean gap on
the focused worker before applying a new generated minimax/table primitive.
