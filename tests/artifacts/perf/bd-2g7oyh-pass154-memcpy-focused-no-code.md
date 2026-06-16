# bd-2g7oyh.436 - memcpy_4096 focused no-code route-out

Date: 2026-06-16
Agent: BoldFalcon
Worker: RCH `vmi1227854`
Status: no-code route-out

## Target

Pass 154 rechecked `glibc_baseline_memcpy_4096` after the pass 148 broad
`ovh-a` routing profile showed a possible current-head residual:

- FrankenLibC p50/mean `43.510/46.645 ns`
- host glibc p50/mean `32.888/36.085 ns`

Prior no-repeat families for this row include exact full-slice branching,
exact-4096 portable-SIMD tiled copy, safe-SIMD copy panels, and surface
copy-shape retunes.

## Focused Gate

Command:

```text
RCH_WORKER=ovh-a RCH_PREFERRED_WORKER=ovh-a RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass154-memcpy-baseline-ovha \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memcpy_4096 --noplot --sample-size 80 --warm-up-time 1 \
  --measurement-time 3
```

RCH admitted the job on `vmi1227854`.

Result:

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[30.238, 30.826, 31.468]` | `31.002` | `33.495` | `38.188` | `75.000` |
| host glibc | `[29.803, 30.228, 30.662]` | `30.393` | `31.932` | `35.000` | `69.456` |

The focused same-worker ratio collapsed to `1.020x` p50 and `1.049x` mean.
That is below the edit threshold, especially after the prior rejected
copy-shape families.

## Behavior Proof

No production source changed. Copied byte order, returned count, destination
tail behavior, overlap policy, floating-point state, RNG state, allocation
behavior, errno, locale behavior, and existing string-memory golden outputs are
unchanged by identity.

## Verdict

NO-CODE ROUTED OUT. Score: `0.0`.

Next route: fresh current-head broad profile. The pass 148 residual queue has
been drained or invalidated by focused gates: `strlen_4096` codegen-blocked,
`exp10f` reversed, `exp10` collapsed, `erfc` collapsed, `memchr_absent`
rejected by peer, `memmove_4096` routed out, and `memcpy_4096` collapsed.
