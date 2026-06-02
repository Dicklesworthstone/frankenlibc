# bd-2g7oyh.2 malloc/free adaptive elimination pass

Date: 2026-06-02

## Profile target

Bead: `bd-2g7oyh.2` (`[perf] Close direct malloc/free 64B gap vs glibc`)

RCH baseline command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_malloc_profile_baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Worker: `vmi1156319`

Baseline profile rows:

| impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op | throughput ops/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| `frankenlibc_core_state` | 4131.462 | 4556.850 | 6159.813 | 3827.264 | 243067.471 |
| `host_glibc` | 8.091 | 13.750 | 45.064 | 10.417 | 122648596.119 |

Gap: `frankenlibc_core_state` was ~510.6x slower by p50.

## Alien primitive card

Symptom: one-sided small-object `free` traffic probes the elimination handoff path even when there is no waiting consumer, so the allocator pays repeated no-partner wait/probe cost before the same fallback path stores the pointer in the thread cache.

Matched primitive: adaptive sparse probing for contention structures. Treat direct handoff as a sampled optimization under low-success evidence, not a mandatory pre-cache stop on every single-thread free.

Expected value: `Impact=5`, `Confidence=4`, `Effort=1`, score `20.0`.

Fallback: if Criterion p50 did not improve, restore the previous adaptive constants and pursue lifecycle-log cold-path separation instead.

## One lever

Only the adaptive elimination controller horizon changed:

```rust
ADAPTIVE_WINDOW: 1000 -> 64
ADAPTIVE_DISABLE_WINDOW: 1000 -> 4096
```

This makes one-sided traffic disable direct-handoff probes after 64 failed attempts and stay in the cheap disabled path for 4096 subsequent attempts before probing again. Successful producer/consumer exchange behavior is still covered by the existing symmetric and cross-thread elimination tests.

## Isomorphism proof

Observable allocator behavior is unchanged:

- Allocation/free return values and error classes are unchanged; this lever only changes how often a failed direct-handoff probe is attempted after low-success evidence.
- `MallocState` fallback order after an unmatched elimination attempt still reaches the same thread-cache/central-bin paths and lifecycle records for the no-partner 64B cycle.
- Successful direct exchange remains supported and tested by `free_matches_waiting_consumer_through_elimination`, `offer_matches_pop_across_threads`, `publish_then_pop_claims_parked_value`, and `symmetric_workload_exceeds_target_success_rate`.
- No ordering/tie-breaking, floating-point, or RNG behavior is involved.
- Internal `EliminationStats.disabled_remaining` changes by design; it is controller telemetry, not ABI-visible libc behavior.

Golden behavior command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc -- --nocapture
```

Normalized test transcript hash, after stripping ANSI and elapsed durations:

```text
baseline 6d2a95f4e32d2a92e56ebcc3bb9e1e130e645ea61c1672380fc6c130866bffdc
post     6d2a95f4e32d2a92e56ebcc3bb9e1e130e645ea61c1672380fc6c130866bffdc
```

Source sha256 after change:

```text
00d25c49f87b9eac13126fb6639920b040c64f6fd2428a8b1ab2615d0ac09745  crates/frankenlibc-core/src/malloc/elimination.rs
```

## Post benchmark

RCH post command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_malloc_profile_post cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1
```

Worker: `vmi1149989`

Post rows:

| impl | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op | throughput ops/s |
| --- | ---: | ---: | ---: | ---: | ---: |
| `frankenlibc_core_state` | 488.928 | 769.938 | 937.898 | 529.911 | 2045664.656 |
| `host_glibc` | 3.864 | 5.708 | 20.000 | 5.038 | 256674547.430 |

Result: `4131.462 -> 488.928 ns/op` p50, an 8.45x speedup and 88.2% p50 reduction for the direct 64B core malloc/free path.

Keep score: `Impact=5 * Confidence=4 / Effort=1 = 20.0`, keep.

## Validation

Passed:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc -- --nocapture
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings
TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core
```

Workspace `cargo fmt --check` is not a valid blocker for this pass because it currently fails on unrelated `frankenlibc-harness` test formatting outside the reserved/touched surface.
