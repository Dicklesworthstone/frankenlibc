# bd-2g7oyh.435 - memmove_4096 focused no-code route-out

Date: 2026-06-16
Agent: BoldFalcon
Worker: RCH `ovh-a`
Status: no-code route-out

## Target

Pass 153 rechecked `glibc_baseline_memmove_4096` after the pass 148 broad
routing profile showed a possible current-head residual:

- FrankenLibC p50/mean `36.408/38.155 ns`
- host glibc p50/mean `30.445/32.822 ns`

Prior no-repeat families for this row include wrapper inlining, exact full-slice
branchbacks, safe-SIMD copy panels, fixed chunk array-copy lowering, surface
`copy_from_slice` branchbacks, and exact 4096 copy-shape retunes.

## Focused Gate

Command:

```text
RCH_WORKER=hz1 RCH_PREFERRED_WORKER=hz1 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary \
  rch exec -- env AGENT_NAME=BoldFalcon \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass153-memmove-baseline-hz1 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memmove_4096 --noplot --sample-size 80 --warm-up-time 1 \
  --measurement-time 3
```

RCH admitted the job on `ovh-a`.

Result:

| impl | Criterion interval | p50 ns | mean ns | p95 ns | p99 ns |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[32.905, 32.914, 32.923]` | `32.928` | `34.221` | `37.500` | `45.000` |
| host glibc | `[28.906, 28.913, 28.920]` | `28.918` | `30.442` | `31.912` | `55.000` |

The focused same-worker ratio was `1.139x` p50 and `1.124x` mean. That is a
real residual, but it is smaller than the prior keep threshold and does not
justify repeating the already-rejected micro-families.

## Source Screen

Current `crates/frankenlibc-core/src/string/mem.rs` already contains the retained
exact-4096 pre-clamp full-slice branch:

- `n == 4096`
- `dest.len() == 4096`
- `src.len() == 4096`
- direct safe `copy_from_slice`

The next admissible memmove primitive is not another branch or wrapper hint. It
needs a generated/backend-lowering artifact or an ABI-level no-overlap
classification proof that changes the remaining call/lowering cost without
changing the safe core contract.

## Behavior Proof

No production source changed. Copied byte order, returned count, destination
tail behavior, overlap semantics, floating-point state, RNG state, allocation
behavior, errno, locale behavior, and existing memmove golden outputs are
unchanged by identity.

## Verdict

NO-CODE ROUTED OUT. Score: `0.0`.

Next route: clean focused `memcpy_4096` gate from the pass 148 broad residual.
If it reproduces, the admissible primitive must be structurally different from
prior exact full-slice and portable-SIMD tiled copy attempts.
