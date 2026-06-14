# bd-jc3vp4 malloc cache-pressure allocator gate

Date: 2026-06-14
Agent: BoldFalcon
Worker: RCH remote `vmi1153651`
Base commit: `8c7793e5357024e9c1a64a8fd2826056a49f268a`

## Target

Follow-up to `bd-2g7oyh.404`. The previous one-live `malloc_free_64/256`
gate only exercised the already-exhausted hot-slot family. This pass added a
focused glibc-baseline row:

- `glibc_baseline_malloc_cache_pressure_256`
- workload: 65 object 256 byte allocate-free-reallocate cycle
- route: one more than `MAGAZINE_CAPACITY`, so the run crosses hot-slot,
  thread-cache magazine, and central-bin spill/refill behavior.

No allocator implementation source was changed.

## Validation

Shared checkout RCH attempts were rejected before execution by dependency
preflight (`RCH-E326` on `vmi1227854`, `RCH-E324` on `vmi1153651`). A clean
detached worktree was created at:

`/data/projects/.scratch/frankenlibc-bdjc3vp4-clean-20260614T2308`

Remote validation from that clean worktree:

1. `rustfmt --edition 2024 --check crates/frankenlibc-bench/benches/glibc_baseline_bench.rs`
   - passed locally before RCH
2. `cargo check -j 1 -p frankenlibc-bench --bench glibc_baseline_bench`
   - RCH remote `vmi1153651`
   - passed
   - existing unrelated warnings observed in current `main`:
     `math/float32.rs`, `math/special.rs`, and benchmark `getenv_miss`
     `unused_mut`
3. `cargo test -j 1 -p frankenlibc-core --lib hot_slot -- --nocapture --test-threads=1`
   - RCH remote `vmi1153651`
   - passed 3/3:
     - `hot_slot_lazy_accounting_is_exact_and_materializes_before_next_shape`
     - `hot_slot_lifecycle_record_sha256_is_stable`
     - `thread_cache_hot_slot_preserves_lifo_order_and_capacity`

Clean-worktree source hashes used for the profile:

```text
4817d9da746ae05c863006bbc7523ed6d1dfb17e38129b2a8a7c23a04b38b45e  crates/frankenlibc-core/src/malloc/allocator.rs
4fb8745dbed318d518714333ee26a9edaafa4c2cc309686299c7a62ced439174  crates/frankenlibc-core/src/malloc/thread_cache.rs
e267398a2ef69ed24c3adf3a23fe82ccea0a01a54d5fb93c3c48b07fff9dadef  crates/frankenlibc-core/src/malloc/size_class.rs
8486187fd419f8243525326f2b7dc41b06cb7abef9828a564009b6c7c33b1412  crates/frankenlibc-bench/benches/glibc_baseline_bench.rs
```

Behavior proof: allocation/free ordering, hot-slot LIFO, thread-cache magazine
capacity behavior, lifecycle SHA, active accounting, FP, and RNG behavior are
unchanged by construction because only the benchmark harness changed. The
focused hot-slot/lifecycle tests above passed on RCH.

## Focused baseline

Command shape:

`cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_malloc_cache_pressure_256 --noplot --sample-size 80 --warm-up-time 1 --measurement-time 4`

Results on `vmi1153651`:

| impl | Criterion interval | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op | throughput ops/s |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| FrankenLibC | `[1.5370 us 1.6180 us 1.7095 us]` | 1494.315 | 2241.192 | 2605.000 | 1551.245 | 642844.924 |
| host glibc | `[6.4664 us 6.7298 us 7.0020 us]` | 6240.591 | 8105.278 | 9165.288 | 6457.005 | 150396.118 |

FrankenLibC is faster than host glibc here:

- p50 ratio: `6240.591 / 1494.315 = 4.18x` in FrankenLibC's favor
- mean ratio: `6457.005 / 1551.245 = 4.16x` in FrankenLibC's favor

## Decision

Rejected as an allocator implementation target. Score `0.0`.

This deeper cache-pressure route does not expose a vs-glibc gap. Do not tune
allocator hot-slot, magazine, central-bin, or slab internals from this bead.
The next optimization pass should reprofile and choose a different
profile-backed residual.
