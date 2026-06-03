# bd-2g7oyh.34 malloc single-owner elimination skip

Status: kept.

## Target

- Hotspot: `MallocState::free` in `crates/frankenlibc-core/src/malloc/allocator.rs`.
- Profile evidence: RCH `glibc_baseline_bench` after commit `dfe3d335` measured `malloc_free_64` as the dominant residual allocator gap on `vmi1156319`: FrankenLibC p50 `494.034 ns/op`, p95 `536.822`, p99 `649.108`, mean `486.069`; host glibc p50 `8.655`, p95 `14.899`, p99 `45.000`.
- Lever: skip `elimination.try_offer` when `Arc::strong_count(&self.elimination) == 1`. With only the allocator-owned handle alive, no consumer can be waiting on the elimination array, so the old path can only fall through with the same pointer to thread-cache, central-bin, or backend logic. When another handle exists, the original elimination-first branch is preserved.
- Score: Impact 2 x Confidence 4 / Effort 1 = 8.0.

## Baseline

Focused pre-edit baseline restored the old elimination-first block for measurement only:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Result on `vmi1153651`:

- FrankenLibC p50 `503.022 ns/op`, p95 `721.973`, p99 `1009.732`, mean `521.706`.
- Host glibc p50 `9.321 ns/op`, p95 `16.240`, p99 `40.000`, mean `12.600`.

## Golden

Post-change golden command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1
```

Result:

- Passed on `vmi1153651`.
- Pinned lifecycle golden SHA256: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.

## Isomorphism

- Ordering preserved for single-owned state: yes. The skipped path had no possible waiting consumer, so the old `OfferOutcome::Fallback` continuation and the new direct continuation reach the same thread-cache, central-bin, and backend ordering.
- Elimination tie-breaking preserved for shared state: yes. When a consumer or other observer has cloned the elimination handle, `Arc::strong_count(&self.elimination) > 1`, and the old `try_offer` branch runs before thread-cache fallback exactly as before.
- Pointer identity preserved: yes. In the skipped single-owned case, the old fallback returned the same pointer value that entered `free`.
- Counters and log fields preserved: yes. The skipped single-owned `try_offer` fallback emitted no allocator lifecycle record; golden hot-cycle SHA is unchanged. Shared-handle elimination records remain covered by `free_matches_waiting_consumer_through_elimination`.
- Floating-point: N/A. The edit touches no FP data or arithmetic.
- RNG: N/A. No random state or seed is touched.

## Post-Benchmark

First post-change focused benchmark on `vmi1293453`:

- FrankenLibC p50 `160.995 ns/op`, p95 `203.031`, p99 `224.241`, mean `173.149`.
- Host glibc p50 `4.224 ns/op`, p95 `8.219`, p99 `35.500`, mean `7.085`.

Confirmation post-change focused benchmark on `vmi1156319`:

- FrankenLibC p50 `385.510 ns/op`, p95 `467.191`, p99 `1102.000`, mean `397.912`.
- Host glibc p50 `8.726 ns/op`, p95 `14.993`, p99 `172.750`, mean `16.741`.

Kept against the bead profile and focused baseline:

- Bead profile p50 `494.034 -> 385.510 ns/op` on `vmi1156319`.
- Focused old-path baseline p50 `503.022 -> 385.510 ns/op`.
- Best observed post p50 `160.995 ns/op` on `vmi1293453`.

## Validation

- RCH `cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1`: passed on `vmi1153651`.
- RCH `cargo test -p frankenlibc-core malloc::allocator::tests:: --lib -- --test-threads=1`: 14/14 passed on `vmi1153651`.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed on `vmi1153651`.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed on `vmi1153651`.
- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs`: passed.
- Local `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs .beads/issues.jsonl`: passed.
