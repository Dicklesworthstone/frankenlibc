# bd-2g7oyh.104 stdio zero-copy direct flush slices

Date: 2026-06-04
Agent: BlackThrush
Target:

- `crates/frankenlibc-core/src/stdio/buffer.rs`
- `crates/frankenlibc-core/src/stdio/file.rs`

## Profile Target

Baseline after `bd-2g7oyh.102`, RCH criterion on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
stdio_stream_buffer/full_buffered_write time: [395.67 ns 396.83 ns 398.21 ns]
stdio_stream_buffer/line_buffered_write time: [424.99 ns 426.26 ns 427.53 ns]
```

Root cause: direct flush paths materialized caller-owned bytes into `WriteResult::flush_data: Vec<u8>` even when no pending internal buffer bytes needed concatenation. The line-buffer benchmark writes a newline-terminated slice 16 times, so it paid 16 small heap materializations per iteration.

## Lever

Single lever: change `WriteResult::flush_data` to `Cow<[u8]>`.

- Direct unbuffered/full-overflow/line-flush paths with no pending buffer bytes borrow caller input.
- Paths that concatenate pending internal bytes plus caller input still return an owned `Vec`.
- Full, line, and unbuffered write ordering is unchanged.
- `buffered`, `flush_needed`, and `flushed_from_buffer` semantics are unchanged.
- Floating point: N/A.
- RNG: N/A.

## Behavior Proof

Pre-change RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core stdio -- --nocapture
259 passed; 0 failed
buffer/file test-line count: 53
buffer/file test-line sha256: 0a371fc887d85fc552a201b1552f4e24b0301c55d186e7d53ba5ad228f0d6582
full transcript sha256: 41d7ba7987e9af0f5031601ba5331c01a87971356b339af92990a6d737fe041d
```

Post-change RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core stdio -- --nocapture
259 passed; 0 failed
buffer/file test-line count: 53
buffer/file test-line sha256: 0a371fc887d85fc552a201b1552f4e24b0301c55d186e7d53ba5ad228f0d6582
full transcript sha256: a06965d43338b5ed76ef33559a236ca6a97b96039424a2885dc742f372641e89
```

Additional validation:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/stdio/buffer.rs crates/frankenlibc-core/src/stdio/file.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --lib -- -D warnings -A clippy::cmp_owned
```

`cargo clippy -p frankenlibc-core --all-targets -- -D warnings` remains blocked by unrelated pre-existing lints in `malloc/allocator.rs` (`cmp_owned`) and `stdlib/sort.rs` test code (`unnecessary_cast`).

## Benchmark Result

Post-change RCH criterion run on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
stdio_stream_buffer/full_buffered_write time: [384.15 ns 385.45 ns 386.96 ns]
stdio_stream_buffer/line_buffered_write time: [290.89 ns 292.07 ns 293.60 ns]
post benchmark transcript sha256: 32f8685c2d39da710ca22112f9339b3e1aea790dd644777b3533568283503885
```

Before/after midpoint deltas:

- full-buffered write: `396.83 ns -> 385.45 ns`, 11.38 ns faster, 2.87% improvement
- line-buffered write: `426.26 ns -> 292.07 ns`, 134.19 ns faster, 31.48% improvement

Score: Impact 4 x Confidence 4 / Effort 2 = 8.0. Keep.
