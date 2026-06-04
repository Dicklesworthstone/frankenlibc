# bd-2g7oyh.106 stdio lazy buffer backing allocation

Date: 2026-06-04
Agent: BlackThrush
Target:

- `crates/frankenlibc-core/src/stdio/buffer.rs`

## Profile Target

Baseline after `bd-2g7oyh.104`, RCH criterion on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
stdio_stream_buffer/full_buffered_write time: [384.15 ns 385.45 ns 386.96 ns]
stdio_stream_buffer/line_buffered_write time: [290.89 ns 292.07 ns 293.60 ns]
baseline benchmark transcript sha256: 32f8685c2d39da710ca22112f9339b3e1aea790dd644777b3533568283503885
```

Root cause: `StreamBuffer::new` and `set_mode` materialized and zeroed the backing `Vec`
before any buffered I/O. The post-`bd-2g7oyh.104` line-buffer benchmark direct-flushes
borrowed caller data and often never needs backing storage, while the full-buffer benchmark
only needs storage at the first staged write.

## Lever

Single lever: keep a logical `capacity` and allocate/zero backing storage lazily.

- `capacity()` and setvbuf sizing semantics are unchanged.
- Empty pending write data still returns an empty slice without materializing backing storage.
- `fill`, `unget`, full-buffer writes, and line-buffer remainders materialize storage before
  copying bytes.
- Direct flush ordering and `Cow` borrow/own behavior from `bd-2g7oyh.104` are unchanged.
- Floating point: N/A.
- RNG: N/A.

## Behavior Proof

Pre-change RCH proof from `bd-2g7oyh.104`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core stdio -- --nocapture
259 passed; 0 failed
buffer/file test-line count: 53
buffer/file test-line sha256: 0a371fc887d85fc552a201b1552f4e24b0301c55d186e7d53ba5ad228f0d6582
full transcript sha256: a06965d43338b5ed76ef33559a236ca6a97b96039424a2885dc742f372641e89
```

Post-change RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core --lib stdio -- --nocapture
259 passed; 0 failed
buffer/file test-line count: 53
buffer/file test-line sha256: 0a371fc887d85fc552a201b1552f4e24b0301c55d186e7d53ba5ad228f0d6582
full transcript sha256: f9dfe1f8733d6437ae16cc93ddad3a8f75815ddfd97bacc7a50a4f9aedbb85f5
```

The broader `cargo test -p frankenlibc-core stdio -- --nocapture` lane was blocked by an
unrelated peer-owned integration test compile error in
`crates/frankenlibc-core/tests/glob_brace_dos_robustness.rs`, where `r.err()` moves `r`
before later formatting `r`.

Additional validation:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/stdio/buffer.rs crates/frankenlibc-core/src/stdio/file.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --lib -- -D warnings -A clippy::cmp_owned
```

`cargo clippy -p frankenlibc-core --all-targets -- -D warnings` remains blocked by unrelated
lint debt in `malloc/allocator.rs` (`cmp_owned`) and `stdlib/sort.rs` test code
(`unnecessary_cast`).

## Benchmark Result

Post-change RCH criterion run on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
stdio_stream_buffer/full_buffered_write time: [294.03 ns 296.59 ns 299.36 ns]
stdio_stream_buffer/line_buffered_write time: [127.33 ns 127.53 ns 127.78 ns]
post benchmark transcript sha256: 3d117edc4f44d1ad198dc95c4124a9f5b0baf94b1cebc651bca48db9c859572a
```

Before/after midpoint deltas:

- full-buffered write: `385.45 ns -> 296.59 ns`, 88.86 ns faster, 23.05% improvement
- line-buffered write: `292.07 ns -> 127.53 ns`, 164.54 ns faster, 56.34% improvement

Score: Impact 5 x Confidence 5 / Effort 2 = 12.5. Keep.
