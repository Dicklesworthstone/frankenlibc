# bd-j97ei3 - malloc_free_64 focused allocator gate

Date: 2026-06-10
Agent: BoldFalcon
Status: NO-CODE REJECTED

## Target

Fresh RCH broad profiling on current `main` after the erfc closeout showed
`malloc_free_64` as the strongest unowned p50 residual:

```text
FrankenLibC malloc_free_64: p50 6.060 ns, p95 15.000 ns, p99 90.000 ns, mean 9.838 ns
host glibc malloc_free_64: p50 3.817 ns, p95 12.500 ns, p99 60.000 ns, mean 6.327 ns
```

The candidate route was deliberately structural: a safe-Rust intrusive
small-object LIFO/slab hot-cycle primitive. No allocator source was edited before
the focused baseline.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_WORKER=vmi1227854 RCH_ENV_ALLOWLIST='CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS' \
CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass35-malloc64-baseline-target-20260609T231000Z \
CRITERION_HOME=/data/tmp/frankenlibc-pass35-malloc64-baseline-criterion-20260609T231000Z \
rch exec -- cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --quiet
```

Worker: `vmi1227854`

```text
FrankenLibC malloc_free_64: p50 6.043 ns, p95 15.000 ns, p99 80.000 ns, mean 9.382 ns
host glibc malloc_free_64: p50 5.386 ns, p95 15.000 ns, p99 80.000 ns, mean 8.887 ns
```

## Isomorphism

No source code was changed. Allocation/free ordering, reuse behavior, error
semantics, metrics, floating point, tie-breaking, and RNG behavior are unchanged
by construction.

Golden outputs are unchanged by construction because the candidate was not
implemented.

## Verdict

NO-CODE REJECTED.

The focused same-worker gap collapsed to `1.12x` by p50 and `1.06x` by mean.
That does not satisfy the profile-backed edit gate, so no allocator source was
changed and the slab/LIFO primitive was not attempted on this evidence.

Score: `0.0`.

Next route: reprofile/route to a different residual. Do not repeat allocator
metadata or hot-cycle micro-levers unless a focused same-worker baseline
reproduces a material gap; if allocator becomes hot again, the next admissible
candidate remains a genuinely structural slab/LIFO replacement with lifecycle
goldens.
