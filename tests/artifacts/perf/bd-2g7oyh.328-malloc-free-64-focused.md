# bd-2g7oyh.328 malloc_free_64 focused gate

Date: 2026-06-10T19:02:50Z
Agent: BoldFalcon
Worker: vmi1227854
RCH build: 29879662679165348
Commit under test: ce76fcac

## Broad route basis

Pass-54 broad Criterion artifacts at `/data/tmp/frankenlibc-pass54-broad-profile-target-20260610T1842` showed:

- `malloc_free_64` FrankenLibC median `6.056 ns`, mean `6.051 ns`
- `malloc_free_64` host glibc median `3.381 ns`, mean `3.503 ns`
- Ratio: `1.791x` median, `1.727x` mean

`pow*` was excluded as peer-owned by MossyFern, `strncmp_256_equal` as peer-owned by SilverCedar, and `bd-2g7oyh.327` closed after its focused fnmatch gate reversed.

## Focused same-worker baseline

Command shape:

```text
RCH_WORKERS=vmi1227854 RCH_REQUIRE_REMOTE=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd328-malloc64-baseline-target-20260610T1859 CRITERION_HOME=/data/tmp/frankenlibc-bd328-malloc64-baseline-criterion-20260610T1859 cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

RCH selected `vmi1227854` and ran remotely. RCH rewrote `CARGO_TARGET_DIR` to worker-scoped `.rch-target-vmi1227854-job-29879662679165348-1781117926529525210-0`.

Focused output:

- FrankenLibC Criterion interval: `[5.9993 ns, 6.0817 ns, 6.1887 ns]`
- FrankenLibC profile line: p50 `6.193 ns`, mean `7.735 ns`, p95 `8.750 ns`, p99 `35.500 ns`
- Host glibc Criterion interval: `[5.4235 ns, 5.7286 ns, 5.9809 ns]`
- Host glibc profile line: p50 `4.949 ns`, mean `8.112 ns`, p95 `7.130 ns`, p99 `40.000 ns`

## Source and behavior proof

No allocator source was edited.

```text
c126320efbc34e01a1ae36a9d4fdf2b3dbde9b796a3dbbb82f821e3dedb900fd  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
```

`git diff --exit-code -- crates/frankenlibc-core/src/malloc/allocator.rs crates/frankenlibc-core/src/malloc/thread_cache.rs` passed.

Isomorphism: behavior is unchanged by construction. Allocation/free order, LIFO reuse, active/total accounting, lifecycle Trace record ordering, shared-elimination ordering, backend release behavior, tie-breaking, FP state, and RNG state are not touched. Golden-output equivalence is implied by identical source SHA and no source diff in the allocator files.

## Verdict

NO-CODE REJECTED, Score `0.0`.

The focused same-worker gate collapsed from the broad `1.79x` median gap to p50 `6.193 ns` vs `4.949 ns` (`1.251x`, `1.244 ns` absolute) while the mean reversed in FrankenLibC's favor: `7.735 ns` vs host `8.112 ns`. This is not a material enough target for a structural allocator lever.

Next route: reprofile and attack a different reproduced unowned residual. Only return to allocator if a fresh focused same-worker gate shows a material median and mean gap and the candidate is a true structural LIFO/slab or hot/cold observability primitive, not another metadata/layout/lifecycle/certificate micro-lever.
