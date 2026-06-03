# bd-2g7oyh.41 - malloc elimination handle gate

Verdict: rejected. The production-only gate candidate was restored because the
post-change RCH benchmark did not show a real win.

## Profile-Backed Target

Fresh post-`27e332a7` broad RCH profile kept `malloc_free_64` as the dominant
remaining clean residual gap:

- FrankenLibC: p50 `163.665 ns/op`, p95 `221.719`, p99 `328.539`, mean `174.630`
- Host glibc: p50 `4.810 ns/op`, p95 `10.000`, p99 `40.000`, mean `7.049`

Focused pre-change baseline for this candidate:

```text
RCH worker: vmi1149989
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC malloc_free_64:
  p50 156.635 ns/op
  p95 189.048 ns/op
  p99 300.438 ns/op
  mean 154.100 ns/op

Host glibc malloc_free_64:
  p50 4.139 ns/op
  p95 8.750 ns/op
  p99 35.000 ns/op
  mean 5.890 ns/op
```

## Candidate Lever

One safe-Rust hot-path lever in `crates/frankenlibc-core/src/malloc/allocator.rs`:
avoid the production `Arc::strong_count(&self.elimination)` load on `free`,
while preserving the exact existing `strong_count > 1` gate under `cfg(test)`.

This was grounded in the allocator ownership invariant: in production, the
elimination array is private to `MallocState`; tests expose an extra handle to
exercise direct handoff behavior.

## Behavior Proof

Golden output was checked before and after the candidate with the exact
allocator lifecycle SHA test:

```text
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture
Pre-change worker: vmi1149989, passed 1/1
Post-change worker: vmi1293453, passed 1/1
hot_cycle_lifecycle_record_sha256 = 01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455
```

Isomorphism:

- Production ordering would remain unchanged because the candidate only skipped an impossible external-handle check before the existing thread-cache and central-bin paths.
- Test ordering would remain unchanged because `cfg(test)` retained the exact `Arc::strong_count > 1` elimination-first gate.
- Tie-breaking and pointer reuse would remain unchanged because size-class selection, thread-cache LIFO, central-bin order, and elimination slot selection logic were not modified.
- Floating-point and RNG behavior were unaffected.
- No `malloc/elimination.rs` behavior or peer-owned dirty work was touched.

## Re-Benchmark

Post-change focused RCH benchmark:

```text
RCH worker: vmi1293453
Command: RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench malloc_free_64 -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot

FrankenLibC malloc_free_64:
  p50 156.085 ns/op
  p95 191.135 ns/op
  p99 196.388 ns/op
  mean 157.231 ns/op

Host glibc malloc_free_64:
  p50 3.661 ns/op
  p95 6.250 ns/op
  p99 25.000 ns/op
  mean 5.036 ns/op
```

## Decision

Rejected. The candidate changed FrankenLibC p50 by only `0.550 ns/op` versus
the focused baseline and regressed mean:

```text
FrankenLibC p50: 156.635 -> 156.085 ns/op
FrankenLibC mean: 154.100 -> 157.231 ns/op
```

That is below the real-win threshold and does not satisfy `Score >= 2.0`.
`allocator.rs` was restored with no source change retained.

Score after measurement: `0.0`.
