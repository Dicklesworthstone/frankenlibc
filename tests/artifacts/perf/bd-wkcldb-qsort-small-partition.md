# bd-wkcldb qsort small-partition insertion cutoff

Date: 2026-06-02
Agent: BlackThrush
Bead: bd-wkcldb

## Profile-backed target

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_qsort_128_i32 --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Baseline worker: vmi1156319

Baseline p50:

- frankenlibc_core: 5380.495 ns/op
- host_glibc: 4150.123 ns/op
- gap: FrankenLibC 1.30x slower p50

Baseline p95/p99:

- frankenlibc_core: p95 6147.209 ns/op, p99 6313.427 ns/op
- host_glibc: p95 5123.539 ns/op, p99 5170.096 ns/op

Target surface: `crates/frankenlibc-core/src/stdlib/sort.rs`, `quicksort_safe`.

Correction to bead description: the current implementation did not allocate a pivot `Vec` per partition. The profile-backed lever targets recursive partition, median-three, and swap overhead on tiny partitions before the existing depth-limit-only insertion-sort fallback.

## Alien primitive recommendation card

Primitive: cache-local hybrid quicksort, using insertion sort for small partitions where branch, recursion, and partition overhead dominate the actual comparison/swap work.

Recommendation card:

- Impact: 3
- Confidence: 4
- Reuse: 2
- Effort: 1
- Friction: 1
- EV: `(3 * 4 * 2) / (1 * 1) = 24.0`

Fallback trigger: revert the lever if existing sort-test golden output changes, sorted permutation behavior changes, or RCH post p50 fails to beat the baseline.

## One lever

Added a single small-partition cutoff:

- `QSORT_INSERTION_CUTOFF = 16`
- `quicksort_safe` calls `insertion_sort` directly for `count <= 16`
- Added a 16-element duplicate-bearing regression test proving sorted multiset preservation.

## Behavior proof

Baseline command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core 'stdlib::sort' --lib -- --nocapture --test-threads=1
```

Baseline result: 24/24 `stdlib::sort` tests passed on vmi1153651.

Baseline hashes:

- existing test-line sha256: `79813919c2285067a39ded724b4bfb207599fb72692c708fa69ee716ef699ab1`
- transcript sha256: `11e03bec4e9302813ae9ea2086549327d7c4c8c8452f04a8aabce8e5e93306eb`
- source sha256: `bb37c46c840cf3469f6662d583f8d4e097cc2961b66f49dfe75016d97eac0283`

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core 'stdlib::sort' --lib -- --nocapture --test-threads=1
```

Post result: 25/25 `stdlib::sort` tests passed on vmi1227854.

Post hashes:

- existing test-line sha256: `79813919c2285067a39ded724b4bfb207599fb72692c708fa69ee716ef699ab1`
- full post transcript sha256 including the new test: `54cedf87b745df0c0948299a8de213593c5941cd27ed8c23cd134b7c7116c130`
- source sha256: `f54102e160c31e4c53f9cf18baeb08284f2a0dc26eebe6cb7d42e399c85537af`

Isomorphism:

- `qsort` promises sorted output according to the comparator; it does not promise stability or comparator-call ordering.
- The cutoff only changes the algorithm used inside partitions of 16 elements or fewer.
- Insertion sort preserves the input multiset and uses the same comparator relation to produce a sorted output.
- Duplicate tie stability may differ from quicksort internals, but stability is not an observable contract for this implementation.
- Floating-point behavior, RNG state, errno/error class, and ABI-visible return behavior are unaffected.

## Re-benchmark

Post worker: vmi1149989

Post command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_qsort_128_i32 --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Post p50:

- frankenlibc_core: 2878.460 ns/op
- host_glibc: 2329.633 ns/op
- residual gap: FrankenLibC 1.24x slower p50 on this worker

Post p95/p99:

- frankenlibc_core: p95 3845.803 ns/op, p99 4037.938 ns/op
- host_glibc: p95 2871.452 ns/op, p99 3154.000 ns/op

Before/after:

- frankenlibc_core p50: 5380.495 -> 2878.460 ns/op
- speedup: 1.87x
- p50 reduction: 46.5%

Score: Impact 3 x Confidence 4 / Effort 1 = 12.0, kept.

## Validation

Passed:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core 'stdlib::sort' --lib -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings
TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core
git diff --check
```

Remote check/clippy emitted only the existing build-script warning that no SMT solver was available for generated stdio proof checking.
