# bd-2g7oyh.281 malloc hot-cycle structural rejection

## Target

Focused RCH baseline on clean `origin/main` selected `malloc_free_256` as the
current allocator residual.

Baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary cargo bench -p frankenlibc-bench \
  --profile release-perf --bench glibc_baseline_bench malloc_free_256 -- --quiet
```

Baseline rows:

| row | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC `malloc_free_256` | 13.130 | 15.891 | 25.000 | 80.000 |
| host glibc `malloc_free_256` | 4.897 | 6.901 | 10.000 | 50.000 |

Guard baseline:

| row | p50 ns/op | mean ns/op |
| --- | ---: | ---: |
| FrankenLibC `malloc_free_64` | 12.460 | 15.228 |
| host glibc `malloc_free_64` | 5.114 | 7.318 |

## Candidate A: affine small-front lease

Primitive: cache a generic affine `SmallFrontLease { ptr, requested_size, bin }`
when a small object is checked out from a local cache, then consume it on an
exact matching `free` to reuse the proven size-class bin.

Behavior proof completed before benchmark:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary cargo test -p frankenlibc-core \
  --lib malloc -- --nocapture --test-threads=1
rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs
git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary cargo check -p frankenlibc-core --all-targets
```

Proof results:

- `cargo test -p frankenlibc-core --lib malloc` passed 67 malloc-family tests.
- Existing lifecycle SHA goldens stayed unchanged:
  - `hot_cycle_lifecycle_record_sha256_is_stable`: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`
  - `hot_slot_lifecycle_record_sha256_is_stable`: `eca20f7a00fb7f2dc41fcafde6f1d9f7184f585b492b87616dd9ef07e16e2729`
- Added local proof tests in the scratch candidate for exact lease consumption
  and preservation of waiting elimination consumers.
- Ordering/tie-breaking proof: cached free placement still used the existing
  `cache_small_object` transition, so hot-slot, magazine, central-bin spill, and
  backend-release order were unchanged. Shared-elimination paths fell back to
  the existing `try_offer` order.
- FP/RNG: not involved.
- `cargo check -p frankenlibc-core --all-targets` passed with pre-existing
  `unused_mut` warnings in `wcslen_fold_isomorphism.rs` and
  `wcsnlen_fold_isomorphism.rs`.

Post row:

| row | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC candidate | 15.283 | 18.201 | 25.000 | 81.000 |
| host glibc same run | 5.293 | 7.512 | 11.375 | 50.000 |

Verdict: rejected. p50 regressed 16.5 percent and mean regressed 14.5 percent
against the clean baseline. Score `(Impact 0 * Confidence 4) / Effort 2 = 0.0`.
No lease source was kept.

## Candidate B: compact hot-slot bitset

The shared checkout contained an uncommitted `ThreadCacheHotSlots` bitset diff
whose ownership was unclear. It was measured as a standalone hot/cold metadata
split candidate from `/data/projects/frankenlibc` and was not staged by this
pass.

Post row:

| row | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| FrankenLibC bitset-only | 14.154 | 16.968 | 25.000 | 90.000 |
| host glibc same run | 5.012 | 7.539 | 12.500 | 60.000 |

Verdict: rejected. p50 regressed 8.0 percent and mean regressed 6.1 percent
against the clean baseline. Score `(Impact 0 * Confidence 3) / Effort 2 = 0.0`.

Agent Mail thread `bd-2g7oyh.281` message `43071` notified the active cc agents
that the live bitset diff did not clear the keep gate and was left unstaged
because ownership was unclear.

## Next primitive

Do not retry hot-slot metadata, exact-size cache bypass, Trace lifecycle call
gates, fixed magazine storage, or size-class certificate micro-specialization.

Next allocator attack should be the deeper primitive from
`tests/artifacts/perf/bd-4scbmf-malloc-structural-analysis.md`: a safe-Rust
intrusive index-linked small-object LIFO/slab with deferred hot-path counters,
preserving deterministic LIFO reuse, active/total accounting, lifecycle Trace
goldens, shared-elimination ordering, and backend release behavior.
