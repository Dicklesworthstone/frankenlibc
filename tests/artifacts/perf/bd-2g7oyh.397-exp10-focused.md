# bd-2g7oyh.397 exp10 focused gate

Date: 2026-06-13
Agent: BoldFalcon
Worker: `vmi1227854`
Status: NO-CODE REJECTED

## Target

Current broad profile on `vmi1227854` showed a renewed `exp10` row:

| row | FrankenLibC p50 ns | host p50 ns | FrankenLibC mean ns | host mean ns |
| --- | ---: | ---: | ---: | ---: |
| broad `exp10` | 381.467 | 332.071 | 391.031 | 333.009 |

Prior no-retry families for this lane:

- surface 1/16-centered `exp10` table plus degree-12 Horner profile-band route
- 1/64 `exp2` table/residual profile-band route

Any source edit would require a generated proof-carrying `exp2` kernel
replacement with coefficient synthesis, not another table/residual retune.

## Focused Gate

```text
RCH_BUILD_SLOTS=1 RCH_WORKER=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_QUEUE_WHEN_BUSY=1
RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1200 rch exec -- env
AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd397-exp10-baseline-target-20260614T0001
CRITERION_HOME=/data/tmp/frankenlibc-bd397-exp10-baseline-criterion-20260614T0001
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_math/exp10 --noplot --sample-size 60 --warm-up-time 1
--measurement-time 3
```

RCH selected `vmi1227854`. Remote duration: `244.8s`.

The filter also matched `exp10f`; both rows are recorded below.

| row | implementation | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `exp10` | FrankenLibC | `[293.97 ns 300.13 ns 307.06 ns]` | 309.195 | 316.978 | 365.013 | 445.500 |
| `exp10` | host glibc | `[329.19 ns 331.66 ns 334.43 ns]` | 339.945 | 351.043 | 370.500 | 651.000 |
| `exp10f` | FrankenLibC | `[258.89 ns 262.98 ns 267.11 ns]` | 264.226 | 264.481 | 292.265 | 300.500 |
| `exp10f` | host glibc | `[322.64 ns 324.22 ns 325.80 ns]` | 322.905 | 321.527 | 333.913 | 344.008 |

## Isomorphism

No source code changed.

- Exact integer powers, range fallback ordering, finite/special floating-point
  behavior, errno/fenv behavior, ABI forwarding, allocation behavior, and RNG
  behavior are unchanged by construction.
- Golden outputs are unchanged by construction.

`git diff --exit-code -- crates/frankenlibc-core/src/math/exp.rs
crates/frankenlibc-core/src/math/float.rs
crates/frankenlibc-core/src/math/float32.rs
crates/frankenlibc-bench/benches/glibc_baseline_bench.rs` passed before this
artifact was written.

## Verdict

NO-CODE REJECTED. Score `0.0`.

The focused same-worker gate reversed the broad result:

- `exp10` FrankenLibC was faster than host by p50 (`309.195` vs `339.945 ns`)
  and mean (`316.978` vs `351.043 ns`).
- `exp10f` also stayed faster than host by p50 (`264.226` vs `322.905 ns`) and
  mean (`264.481` vs `321.527 ns`).

Do not retry `exp10` without a future material same-worker focused gap and a
generated proof-carrying `exp2` primitive.
