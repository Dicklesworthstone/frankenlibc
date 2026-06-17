# bd-2g7oyh.471 pass189 strlen4096 focused no-code

Date: 2026-06-17T11:00:00Z

Head: `2537fb1a0 chore(perf): route current head pass 188`

Reason: pass188 broad routing showed `strlen_4096` as the next admissible non-repeat target: FrankenLibC `28.658 / 33.768 ns` p50/mean vs host `21.342 / 23.009`. Before any source edit, this pass ran a focused local gate because broad rows have been noisy and recent `strlen` surface levers had rejected.

## Focused Gate

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass189-baseline-target-20260617T1057 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strlen_4096 --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass189-strlen-baseline.log`

Log SHA-256: `654a63c0abc15ff4d365c272a956282c29860a360ce653721f365daa3bc9337a`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC | `18.214` | `21.385` | `[18.026 ns 18.400 ns 18.829 ns]` |
| host glibc | `21.103` | `22.144` | `[21.337 ns 21.761 ns 22.186 ns]` |

The focused row reversed the broad profile: FrankenLibC is faster by `1.159x` p50 and `1.036x` mean.

## Behavior Proof

No source changes were made. Isomorphism is identity:

- First-NUL ordering and returned length: unchanged.
- `strnlen`, `strcpy`, substring callers: unchanged.
- Floating point/RNG/allocation/errno/locale state: unchanged.
- Golden outputs: unchanged by identity.

Source hash:

- `crates/frankenlibc-core/src/string/str.rs`: `63af120d4c9ee3a3af6db0ec78f48d210b8d87dc17df67fdcdab8be975506d92`

## Verdict

NO-CODE ROUTED OUT. Score `0.0`: no implementation lever attempted because the focused profile showed FrankenLibC ahead of host.

Next route: reprofile current head again. Do not edit `strlen_4096` from the pass188 broad row alone; require a fresh focused regression before any future source lever.
