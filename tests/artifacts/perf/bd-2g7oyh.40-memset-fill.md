# bd-2g7oyh.40 - memset fill kernel pass

Status: rejected/no-op.

## Profile Target

- Target row: `glibc_baseline_memset_4096`.
- File surface considered: `crates/frankenlibc-core/src/string/mem.rs::memset`.
- Broad profile evidence from the prior campaign pass: `memset_4096` FrankenLibC p50 `19.526 ns/op`, p95 `23.188`, p99 `50.000`, mean `20.996`; host glibc p50 `17.094`, p95 `21.055`, p99 `45.000`, mean `18.493`.
- Coordination: skipped `str.rs` because BlackThrush owns the active strlen residual lane; skipped allocator because allocator surfaces are peer-dirty/contended.

## Alien Primitive

- `/alien-graveyard` match: vectorized hot operators and cache-local panel processing.
- `/alien-artifact-coding` proof contract: exact prefix-fill isomorphism; a valid lever would only change how bytes are written, not which bytes are written.

## Focused RCH Baseline

Command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_40_memset_baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench glibc_baseline_memset_4096 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `vmi1264463`.

Result:

- FrankenLibC p50 `58.740 ns/op`, p95 `335.486`, p99 `744.551`, mean `102.433`.
- Host glibc p50 `75.130 ns/op`, p95 `536.762`, p99 `648.463`, mean `131.449`.

## Decision

The focused profile did not show a current vs-host gap: FrankenLibC was faster than host on p50, p95, and mean for this row. No optimization lever was applied because the pass lacked a profile-backed slower-than-upstream target. Score after measurement: `0.0`, rejected/no-op.

## Isomorphism

No source behavior changed. If a future memset lever is attempted, the required invariant remains: return `min(n, dest.len())`; write exactly that prefix to the requested byte value; leave bytes after the prefix unchanged; no ordering, tie-breaking, floating-point, RNG, errno, or ABI-visible behavior changes.
