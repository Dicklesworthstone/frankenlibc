# bd-2g7oyh.275 exp10f range-polynomial baseline miss

Status: NO-CODE REJECTED on 2026-06-09.

## Target

- Bead: `bd-2g7oyh.275`
- Scope: `crates/frankenlibc-core/src/math/float32.rs`
- Profile-backed target: `glibc_baseline_math/exp10f`
- Proposed lever: f32-specialized range-reduced polynomial fast path for
  `exp10f(x)` on `x in [0.5, 2.5)`.

The bead was opened from a broad RCH profile on `vmi1167313` after
`bd-2g7oyh.274`, which reported FrankenLibC behind host glibc:

| Row | FrankenLibC p50 | FrankenLibC mean | host p50 | host mean |
| --- | ---: | ---: | ---: | ---: |
| `exp10f` | 694.423 ns | 1029.238 ns | 459.377 ns | 477.548 ns |

## Focused Same-worker Baseline

Before keeping or reapplying any source lever, the focused RCH baseline was
rerun on `vmi1227854` against the current shared tree. `float32.rs` was clean,
so no `exp10f` candidate was present in this baseline.

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_BUILD_SLOTS=2 \
  rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd275-baseline-vmi1227854c \
  cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_math/exp10f --noplot --sample-size 30 --warm-up-time 1 \
  --measurement-time 3
```

Worker: `vmi1227854`

| Impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC | 318.455 | 320.054 | 348.000 | 471.312 |
| host glibc | 324.698 | 325.358 | 335.500 | 360.500 |

The focused baseline shows FrankenLibC already slightly faster than host glibc
on p50 and mean. The broad-profile gap did not reproduce, so the required
profile-backed target is absent.

## Candidate Audit

A sidecar audit reviewed the interrupted candidate shape before the live diff
disappeared:

- existing integer fast path and special-value fallback ordering were preserved;
- overflow and underflow remained on the existing fallback path;
- the polynomial was plausible, but not keep-ready without stronger boundary
  and exhaustive/near-exhaustive ULP proof around `[0.5, 2.5)`, especially the
  `0.5`, `1.5`, and `2.5` branch boundaries.

No source code was kept or modified for this bead.

## Behavior Proof

No behavior changed:

- `git diff -- crates/frankenlibc-core/src/math/float32.rs` was empty before
  closeout.
- Ordering, tie-breaking, floating-point behavior, special values, integer
  exactness, overflow/underflow, and RNG behavior are unchanged by construction.
- Golden fixture SHA-256 values are unchanged by construction because no source
  or fixture files were edited.

## Verdict

Rejected as a no-code baseline miss. Score: `0.0`.

Next route: reprofile first. If `exp10f` reappears as a focused same-worker gap,
do not reapply the raw two-center Taylor split as-is; use a structurally
different generated Remez/minimax `exp10f` kernel with a small `10^(k/16)` table,
Estrin evaluation, coefficient certificate, boundary corpus, and glibc ULP
replay.
