# bd-2g7oyh.36 malloc hot bin/class shortcut

Status: rejected.

## Target

- Hotspot: 64-byte malloc/free cycle in `crates/frankenlibc-core/src/malloc/allocator.rs`.
- Profile evidence: post-`33989f35` RCH `glibc_baseline_bench` on `vmi1227854` measured `malloc_free_64` as the largest clean residual broad-bench gap: FrankenLibC p50 `177.986 ns/op`, p95 `221.535`, p99 `306.625`, mean `185.595`; host glibc p50 `3.571`, p95 `4.897`, p99 `25.000`, mean `5.139`.
- Candidate lever: add a constant 64-byte size-class index and use it for the exact 64-byte allocator path, avoiding the generic `small_bin_index` scan and `size_for_index` table lookup. All non-64 sizes delegated to the existing generic lookup.
- Score before measurement: Impact 1 x Confidence 3 / Effort 1 = 3.0.

## Baseline

Focused pre-change command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- malloc_free_64 --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Result on `vmi1227854`:

- FrankenLibC p50 `166.312 ns/op`, p95 `199.002`, p99 `546.168`, mean `175.132`.
- Host glibc p50 `4.441 ns/op`, p95 `10.000`, p99 `45.000`, mean `7.231`.

## Golden

Pre-change and post-change command:

```sh
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core malloc::allocator::tests::hot_cycle_lifecycle_record_sha256_is_stable --lib -- --exact --nocapture --test-threads=1
```

Result:

- Pre-change: passed on `vmi1153651`.
- Post-change: passed on `vmi1293453`.
- Pinned lifecycle golden SHA256: `01df8806e2bfd0fda041e153ec61ec4737ad2d3cb1ce22050a2e35bab1688455`.

## Isomorphism

- Intended ordering preservation: the shortcut changed only the lookup mechanism for the exact 64-byte bin/class pair; lifecycle emission points were unchanged.
- Intended tie-breaking preservation: allocation/free path order, thread-cache LIFO order, central-bin order, elimination behavior, and pointer reuse were unchanged.
- Intended numeric preservation: the 64-byte path still mapped to bin index `3`, class size `64`, and certificate value `150000`; non-64 sizes delegated to the existing generic lookup.
- Floating-point: N/A. The candidate touched integer size-class selection only.
- RNG: N/A. No random state or seed was touched.
- Golden output: unchanged while the candidate was applied.

## Post-Benchmark

First post-change focused benchmark on `vmi1153651`:

- FrankenLibC p50 `363.191 ns/op`, p95 `437.874`, p99 `791.000`, mean `375.272`.
- Host glibc p50 `8.781 ns/op`, p95 `15.170`, p99 `40.000`, mean `11.371`.

Confirmation post-change focused benchmark on `vmi1153651`:

- FrankenLibC p50 `362.618 ns/op`, p95 `451.000`, p99 `583.733`, mean `374.936`.
- Host glibc p50 `8.776 ns/op`, p95 `11.548`, p99 `30.000`, mean `10.042`.

Verdict:

- Rejected. The candidate did not show a real win and repeated a raw p50 regression on the same post worker.
- Source restored: no `allocator.rs` or `size_class.rs` change retained.
- Score after measurement: 0.0.

## Validation

- Pre-change RCH golden passed.
- Post-change RCH golden passed with unchanged pinned SHA.
- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/malloc/allocator.rs crates/frankenlibc-core/src/malloc/size_class.rs`: passed after source restore.
- Local `git diff --check -- crates/frankenlibc-core/src/malloc/allocator.rs crates/frankenlibc-core/src/malloc/size_class.rs .beads/issues.jsonl .skill-loop-progress.md tests/artifacts/perf/bd-2g7oyh.36-malloc-hot-bin-shortcut.md`: passed after source restore.
