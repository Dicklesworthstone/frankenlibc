# bd-2g7oyh.321 - memset_4096 focused baseline gate

## Target

- Bead: `bd-2g7oyh.321`
- Profile row: `glibc_baseline_memset_4096`
- Broad-profile basis: the post-`bd-2g7oyh.319` sweep showed a small
  `memset_4096` residual after excluding peer-owned `pow*` and `strncmp`.
- Prior-route constraint: simple `memset` loop lowering to `slice::fill` was
  already tried under `bd-2g7oyh.165` / `bd-2g7oyh.177`, so this pass required
  a focused same-worker gate before considering any structurally different
  safe-Rust fill primitive.

## Focused RCH baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
  RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-321-memset4096-baseline-target-20260610T0752 \
  CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-321-memset4096-baseline-criterion-20260610T0752 \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_memset_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Selected worker: `vmi1227854`.

Results:

| impl | criterion interval | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[20.664 ns 21.096 ns 21.658 ns]` | `21.058` | `22.053` | `25.005` | `45.000` |
| host glibc | `[21.210 ns 21.757 ns 22.274 ns]` | `22.295` | `24.627` | `40.000` | `70.000` |

Focused ratio:

- p50: FrankenLibC is `1.06x` faster than host.
- mean: FrankenLibC is `1.12x` faster than host.

## Source state

No source was edited. The current implementation remains the safe byte-loop
prefix fill in `frankenlibc_core::string::mem::memset`.

- `crates/frankenlibc-core/src/string/mem.rs` sha256:
  `561924f9cec259aaeb5f38c20cc40325b18b6eea2a2ca52cf6d3cb1ea78d79dd`
- `git diff --exit-code -- crates/frankenlibc-core/src/string/mem.rs`: passed

## Isomorphism

No behavioral transform was applied. The existing contract remains:

- Return `min(n, dest.len())`.
- Write exactly that prefix to `value`.
- Leave `dest[count..]` unchanged.
- Ordering, tie-breaking, floating-point, RNG, and errno are not involved.

Because the focused gate shows FrankenLibC already faster than host for this
row, attempting a fill rewrite would violate the profile-backed edit rule.

## Decision

NO-CODE REJECTED, Score `0.0`.

The broad-profile residual did not reproduce under the focused same-worker RCH
gate. Do not retry simple `memset` loop lowering or `slice::fill` from this
noise band. Route to the next reproduced unowned residual instead; only return
to `memset_4096` with a material focused gap and a structurally different
safe-Rust primitive backed by prefix-mutation proof and golden SHA evidence.
