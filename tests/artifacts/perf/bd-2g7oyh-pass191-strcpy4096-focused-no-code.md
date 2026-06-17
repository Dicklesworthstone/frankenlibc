# bd-2g7oyh.473 pass191 strcpy4096 focused no-code

Date: 2026-06-17T11:09:00Z

Head: `9cc3b08a0 chore(perf): route current head pass 190`

Reason: pass190 broad routing selected `strcpy_4096` as the largest material residual. Because pass179 and pass183 recently kept source levers in this exact family, this pass first ran a focused gate before any edit.

## Focused Gate

```bash
env RCH_REQUIRE_REMOTE=0 RCH_VISIBILITY=summary CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass191-baseline-target-20260617T1105 \
  rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --sample-size 80 --warm-up-time 1 --measurement-time 3
```

Log: `target/perf-logs/bd-2g7oyh-pass191-strcpy-baseline.log`

Log SHA-256: `989204510880813302d1dc5c7f758a423ddfc55c038c99ac1914f9fbd378f891`

Rows:

| Impl | p50 ns/op | mean ns/op | Criterion interval |
| --- | ---: | ---: | --- |
| FrankenLibC | `61.775` | `65.196` | `[63.420 ns 64.473 ns 65.772 ns]` |
| host glibc | `42.880` | `44.454` | `[44.257 ns 45.181 ns 46.136 ns]` |

The focused row reproduces a real gap, but this pass does not have an admissible one-lever source edit that is not a repeat of recent closed source families.

## No-Repeat Constraint

Do not repeat these recent `strcpy_4096` source families:

- pass179 kept strlen-prefix copy
- pass183 kept certified scan-copy
- older closed families: whole-source NUL certificate/full-copy, SWAR/global certificate, terminal split, dispatch hoist, array-copy lowering, wrapper inline, typed-exact lowering

The current exact path already uses `copy_nul_free_block_512` over the exact 4097-byte source and preserves early-NUL destination-tail behavior. Repeating a whole-source certificate/full-copy would violate the no-repeat rule even though it is an obvious micro-benchmark shape.

## Behavior Proof

No source changes were made. Isomorphism is identity:

- First-NUL ordering and inclusive-NUL copy count: unchanged.
- Copied bytes and destination-tail preservation: unchanged.
- Panic/overlap policy: unchanged.
- Floating point/RNG/allocation/errno/locale state: unchanged.
- Golden outputs: unchanged by identity.

Source hash:

- `crates/frankenlibc-core/src/string/str.rs`: `63af120d4c9ee3a3af6db0ec78f48d210b8d87dc17df67fdcdab8be975506d92`

## Verdict

FOCUSED NO-CODE ROUTE-OUT. Score `0.0`: gap reproduced, but no admissible non-repeat source lever was attempted in this pass.

Next route: move to another profile-backed row for immediate shipping, or return to `strcpy_4096` only with a genuinely new alien primitive that preserves early-NUL tail behavior without repeating the closed certificate/copy families.
