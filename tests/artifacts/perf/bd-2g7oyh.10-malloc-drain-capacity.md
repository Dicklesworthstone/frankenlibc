# bd-2g7oyh.10 - malloc lifecycle drain capacity retention

## Profile-backed target

- Campaign profile command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- --noplot`
- Campaign profile worker: `vmi1227854`
- Campaign residual: `malloc_free_64` FrankenLibC p50 `762.470 ns/op`, p95 `1462.652`, p99 `1903.000`; host glibc p50 `5.000`, p95 `12.500`, p99 `80.000`
- Focused pre-edit baseline command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench glibc_baseline_malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Focused pre-edit worker: `vmi1153651`
- Focused pre-edit p50/p95/p99: FrankenLibC `1346.311 / 1713.000 / 1997.703 ns/op`; host glibc `8.494 / 11.875 / 40.500 ns/op`

## Alien primitive card

- Symptom: allocator hot loop pays repeated evidence-log buffer regrowth after benchmark-triggered drains at `lifecycle_logs().len() > 2048`.
- Primitive: hot/cold path separation plus capacity-retaining evidence-log buffers; keep observable evidence records unchanged while avoiding avoidable buffer churn.
- EV: `(Impact 2 * Confidence 5 * Reuse 3) / (Effort 1 * AdoptionFriction 1) = 30.0`.
- Fallback: revert if allocator record ordering/hash changes or if post-RCH benchmark fails the Score>=2.0 gate.

## One lever

`MallocState::drain_lifecycle_logs` now drains records while retaining the allocator state's internal `Vec` capacity:

```rust
self.lifecycle_logs.drain(..).collect()
```

No allocator policy, size-class, thread-cache, elimination, large-allocation, counter, or benchmark-harness behavior changed.

## Isomorphism proof

- Ordering preserved: returned lifecycle records are moved out through full-range `Vec::drain(..)`, preserving original order.
- Tie-breaking unchanged: malloc/free reuse order, thread-cache LIFO order, central-bin order, and elimination behavior are untouched.
- Observable record fields unchanged: `decision_id`, `trace_id`, `symbol`, `event`, `outcome`, `details`, pointer, size, bin, and counter snapshots are unchanged for existing tests.
- Drain postcondition unchanged: `lifecycle_logs()` is empty immediately after drain.
- Floating-point: N/A.
- RNG: N/A.
- Non-contractual difference: internal `Vec` capacity is retained for reuse after drain.

## Golden output

- Pre-existing allocator test-line sha256: `7f23ca2d04850e50e6f1c24919633e0d02d1dbfcfdd07df72eb43baed086c6ba`
- Post-existing allocator test-line sha256: `7f23ca2d04850e50e6f1c24919633e0d02d1dbfcfdd07df72eb43baed086c6ba`
- Full post allocator test-line sha256, including new regression: `84e19d13519813915f6f97e61d4920dbd766d656bfb3f532ac0e694d22365ce0`
- Post source sha256: `07ef3731cb393f62293f714cb65d9944275939d80f7af00d28597b29b82a45a1`

## Re-benchmark

- Post command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench glibc_baseline_malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Post worker: `vmi1227854`
- Post p50/p95/p99: FrankenLibC `687.692 / 743.009 / 832.652 ns/op`; host glibc `4.506 / 10.281 / 40.000 ns/op`
- Before/after against campaign same-worker profile: FrankenLibC p50 `762.470 -> 687.692 ns/op`; p95 `1462.652 -> 743.009`; p99 `1903.000 -> 832.652`.
- Score: Impact 2 x Confidence 5 / Effort 1 = 10.0, kept.

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests:: -- --nocapture`: passed 11/11.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc:: -- --nocapture`: passed 55/55.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`: passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed.
- `TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core`: passed locally.
- `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs`: passed locally.
