# bd-2g7oyh.435 / pass 154 - memmove_4096 focused repeat no-code closeout

Date: 2026-06-16
Agent: BoldFalcon
Worker: `vmi1227854`
Status: no-code rejected

## Target

Profile-backed row: `glibc_baseline_memmove_4096`.

This pass followed the clean focused `erfc` route-out. The route was admissible
only if a fresh focused same-worker gap reproduced and the next source lever
was materially different from prior memmove families.

Prior no-retry families for this row remain active:

- wrapper inlining;
- exact safe-slice branchbacks;
- fixed chunk array-copy lowering;
- safe-SIMD copy panels;
- surface exact-copy lowering without new codegen proof.

The current source already contains the two retained memmove levers:

- exact `count == 4096` array-reference copy lowering;
- pre-clamp exact full-slice `n == len == 4096` branch.

## First focused gate

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass154-memmove-baseline-target-20260616T2058b
CRITERION_HOME=/data/tmp/frankenlibc-pass154-memmove-baseline-criterion-20260616T2058b
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memmove_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 3
```

Result:

| impl | Criterion interval | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| FrankenLibC | `[57.227 ns 58.754 ns 60.182 ns]` | 54.679 | 60.565 |
| host glibc | `[49.693 ns 50.596 ns 51.639 ns]` | 48.690 | 51.524 |

This looked material by p50 and mean, but it conflicted with the current
same-worker no-code closeout in `bd-2g7oyh.433`, where `memmove_4096`
collapsed to about `1.03x`.

## Repeat focused gate

After `vmi1227854` was briefly blocked by unrelated active builds, the repeat
remote-required command landed on the same worker:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_BUILD_SLOTS=1
RCH_QUEUE_WHEN_BUSY=1 RCH_DAEMON_WAIT_RESPONSE_TIMEOUT_SECS=1800
RCH_ENV_ALLOWLIST=AGENT_NAME,CARGO_TARGET_DIR,CRITERION_HOME,CARGO_BUILD_JOBS,FRANKENLIBC_BENCH_PIN
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1
CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass154-memmove-baseline-target-20260616T2100-ovhb
CRITERION_HOME=/data/tmp/frankenlibc-pass154-memmove-baseline-criterion-20260616T2100-ovhb
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
glibc_baseline_memmove_4096 --noplot --sample-size 80 --warm-up-time 1
--measurement-time 3
```

Result:

| impl | Criterion interval | p50 ns | mean ns |
| --- | --- | ---: | ---: |
| FrankenLibC | `[34.790 ns 35.225 ns 35.736 ns]` | 34.719 | 37.011 |
| host glibc | `[32.385 ns 32.863 ns 33.378 ns]` | 32.831 | 33.586 |

The repeat same-worker gap collapsed to `1.057x` by p50 and `1.102x` by mean.
That is below the threshold for another memmove source edit, especially after
the rejected fixed-chunk, panel-copy, and inlining families.

## Behavior proof

No production source changed. The current `memmove` source SHA-256 is:

```text
78b1a298993e2ed8983de3425dbf1675132cd978179fce0a9a3fa84933c7c41d  crates/frankenlibc-core/src/string/mem.rs
```

By construction, copied prefix bytes, returned count, destination suffix
preservation, safe-core non-overlap behavior, ABI raw-pointer overlap behavior,
floating-point state, RNG state, allocation behavior, errno, locale, and the
existing memmove golden outputs are unchanged.

## Verdict

NO-CODE REJECTED. Score: `0.0`.

Do not retry `memmove_4096` without both:

- a fresh material focused same-worker reproduction; and
- a genuinely different backend/generated primitive, such as a disassembly-
  proven no-libcall copy sequence or an ABI-level non-overlap classification
  proof that does not affect the safe-core contract.
