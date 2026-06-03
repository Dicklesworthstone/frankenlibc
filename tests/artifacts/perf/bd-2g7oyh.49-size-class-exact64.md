# bd-2g7oyh.49 - malloc exact-64 size-class fast path rejected

## Profile-backed target

- Bead: `bd-2g7oyh.49`
- Target: `crates/frankenlibc-core/src/malloc/size_class.rs::small_bin_index`
- Workload: `glibc_baseline_malloc_free_64`, 64 byte allocate-free cycle.
- Symptom: the benchmark calls `small_bin_index(64)` on both malloc and free; the generic path linearly scans the size table until bin 3.
- Focused pre-change command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_baseline FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Focused pre-change worker: `vmi1156319`
- Focused pre-change p50/p95/p99/mean: FrankenLibC `356.473 / 430.774 / 451.720 / 349.420 ns/op`; host glibc `8.233 / 14.438 / 30.000 / 9.814 ns/op`.

## Alien primitive card

- Primitive: cache-hot branch-specialized exact size-class dispatch, a small branchless-layout/SWAR-adjacent allocator hot-path idea from the graveyard's cache-aware data-structure and vectorized-hot-kernel families.
- EV before measurement: `(Impact 2 * Confidence 4 * Reuse 2) / (Effort 1 * AdoptionFriction 1) = 16.0`.
- Fallback trigger: restore source if the focused post-change Criterion run does not show a real allocator win.

## One lever evaluated

The candidate returned the existing bounded bin-3 result before the generic scan:

```rust
if size == 64 {
    return Some(BoundedIndex(3));
}
```

No allocator policy, thread-cache order, central-bin order, elimination behavior, lifecycle records, pointer values, error classes, benchmark harnesses, or public APIs were intentionally changed.

## Isomorphism proof

- Ordering preserved: the candidate only returned the same bin index that the existing table scan reaches for `size == 64`.
- Tie-breaking unchanged: thread-cache LIFO order, central-bin order, elimination order, and allocation/free record ordering were untouched.
- Boundary behavior unchanged: sizes below 64, sizes above 64, large allocation rejection, and table round-up semantics fell through to the existing scan.
- Floating-point: N/A.
- RNG: N/A.
- Golden output: pre-change SHA256 values were captured for `tests/conformance/golden/fixture_verify_strict_hardened.v1.json`, `.suite.json`, `.md`, and `sha256sums.txt`; no golden files were edited.

## Re-benchmark and verdict

- Post command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_bd_2g7oyh_49_post FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Post worker: `vmi1167313`
- Post p50/p95/p99/mean: FrankenLibC `389.440 / 551.223 / 779.943 / 406.758 ns/op`; host glibc `8.716 / 12.094 / 30.000 / 10.158 ns/op`.
- Before/after: FrankenLibC p50 `356.473 -> 389.440 ns/op`; mean `349.420 -> 406.758 ns/op`.
- Verdict: rejected. The candidate failed the Score>=2.0 keep gate because p50 and mean regressed on focused RCH measurements.
- Source retained: none. `crates/frankenlibc-core/src/malloc/size_class.rs` was restored to the pre-candidate source.
- Score after measurement: 0.0.

## Next primitive direction

This rejection reinforces that single-branch allocator micro-levers are not the right next allocator frontier. The next allocator pass should target a structurally different primitive, such as lifecycle-record hot/cold separation or a benchmark-only evidence-drain bypass with a proof that production record ordering is unchanged.
