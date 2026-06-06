# bd-2g7oyh.170 memcmp_4096 baseline miss

Date: 2026-06-06
Agent: BoldFalcon
Worker: ts1

## Target

Profile-backed bead target from the prior clean-source memory profile:

- `glibc_baseline_memcmp_4096`, equal N-byte buffers
- FrankenLibC p50 `67.753 ns`, mean `75.779 ns`
- host glibc p50 `52.012 ns`, mean `67.503 ns`
- Reported residual: `1.30x` p50

## Focused baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'glibc_baseline_memcmp_(16|256|4096)' --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected `ts1`.

Rows:

| Workload | Impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | --- | ---: | ---: | ---: | ---: |
| `memcmp_16` | FrankenLibC | 4.218 | 6.686 | 20.500 | 5.192 |
| `memcmp_16` | host glibc | 2.369 | 3.697 | 15.000 | 3.351 |
| `memcmp_256` | FrankenLibC | 5.090 | 7.500 | 15.000 | 6.002 |
| `memcmp_256` | host glibc | 3.470 | 5.062 | 20.000 | 4.482 |
| `memcmp_4096` | FrankenLibC | 49.896 | 64.069 | 68.597 | 52.192 |
| `memcmp_4096` | host glibc | 46.250 | 51.690 | 60.000 | 48.294 |

## Decision

The focused same-worker baseline did not reproduce the target p50 residual:

- Bead target p50 ratio: `67.753 / 52.012 = 1.303x`
- Focused baseline p50 ratio: `49.896 / 46.250 = 1.079x`
- Focused baseline mean ratio: `52.192 / 48.294 = 1.081x`

No source lever was attempted because the mandatory baseline did not support the bead's profiled hotspot. The expected Impact for a one-lever vector-mask/equality-certificate change is too small to clear Score `>= 2.0` with credible confidence once the target shrinks to an 8% same-worker gap.

Score: `0.0` (no code change; baseline miss).

## Behavior proof

No source files changed. `git diff -- crates/frankenlibc-core/src/string/mem.rs` was empty after RCH artifact retrieval, so ordering, tie-breaking, floating-point behavior, and RNG behavior are unchanged by this closeout.
