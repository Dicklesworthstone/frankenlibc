# bd-2g7oyh.32 malloc cache-hit-rate derived snapshot

Status: rejected, no source change retained.

## Target

- Hotspot: `MallocState::record_lifecycle` cache-hit-rate snapshot in `crates/frankenlibc-core/src/malloc/allocator.rs`.
- Profile evidence: bead-created RCH profile after `66f494a1`/`0dafc72b` measured `malloc_free_64` at FrankenLibC p50 `561.261 ns/op`, p95 `850.736`, p99 `969.135`, host p50 `8.880`.
- Lever tested: cache `cache_hit_rate_permille` in `MallocState`, refreshing only after `thread_cache_hits` or `thread_cache_misses` changes.
- Score before measurement: Impact 2 x Confidence 4 / Effort 1 = 8.0.

## Baseline

Command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench glibc_baseline_malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Measured on `vmi1227854` with the candidate diff removed:

- FrankenLibC p50 `242.360 ns/op`, p95 `277.292`, p99 `286.346`, mean `232.038`.
- Host glibc p50 `3.768 ns/op`, p95 `4.893`, p99 `30.000`, mean `4.960`.

## Golden

Pre-change command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1
```

Post-change command: same.

Result:

- Pre-change: passed on `vmi1167313`.
- Post-change: passed on `vmi1293453`.
- Pinned lifecycle golden SHA256: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.

## Isomorphism

- Ordering preserved: yes. The candidate only changed how a derived snapshot was stored; lifecycle record emission points and event order were unchanged.
- Tie-breaking unchanged: yes. Allocation path selection, thread-cache LIFO order, central-bin order, elimination behavior, and pointer reuse were unchanged.
- Floating-point: N/A. The path uses integer counters and integer division only.
- RNG: N/A. No random state or seed is touched.
- Golden outputs: unchanged via the pinned lifecycle SHA test above.

## Post-Benchmark

Post-change command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench glibc_baseline_malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Measured on `vmi1293453`:

- FrankenLibC p50 `256.196 ns/op`, p95 `323.097`, p99 `550.000`, mean `263.091`.
- Host glibc p50 `3.805 ns/op`, p95 `6.471`, p99 `30.000`, mean `5.148`.

Verdict: rejected. The candidate regressed p50 (`242.360 -> 256.196 ns/op`) and worsened tail latency, so it failed the Score >= 2.0 keep gate. `allocator.rs` was restored to the pre-candidate implementation before closeout.
