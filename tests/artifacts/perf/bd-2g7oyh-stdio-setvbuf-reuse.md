# bd-2g7oyh.102 stdio setvbuf buffer reuse

Date: 2026-06-04
Agent: BlackThrush
Target: `crates/frankenlibc-core/src/stdio/buffer.rs`

## Profile Target

RCH criterion baseline on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
stdio_stream_buffer/full_buffered_write time: [433.99 ns 436.52 ns 439.08 ns]
stdio_stream_buffer/line_buffered_write time: [444.33 ns 447.52 ns 450.71 ns]
```

Root cause: `StdioStream::with_mode` allocated the default `BUFSIZ` buffer, then the benchmark and normal `setvbuf` setup path immediately called `set_buffering(..., 4096)`. `StreamBuffer::set_mode` always replaced `data` with a fresh `vec![0; cap]`, so the setup path allocated a second buffer even when the existing allocation was already large enough.

## Lever

Single lever: reuse the existing `Vec` allocation inside `StreamBuffer::set_mode` when the requested logical capacity fits in the allocation, while preserving:

- `capacity()` as `data.len()`
- `BufMode::None` logical capacity `0`
- `io_started` rejection
- read/write cursor reset
- zeroed logical buffer contents after mode changes

Ordering/tie-breaking: unchanged.
Floating point: N/A.
RNG: N/A.

## Behavior Proof

Pre-change RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core stdio::buffer -- --nocapture
15 passed; 0 failed
stable pre-existing test-line sha256: 214e9b44aa05fc21e21a0813e91dbf69a60c4ccdc31d7ca1ccc98fc40ea6eaeb
full transcript sha256: 30f6895459389d5d13de76afb865aaeb8c28596b939e6112a4c67024f8fc7fac
```

Post-change RCH proof:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core stdio::buffer -- --nocapture
16 passed; 0 failed
stable pre-existing test-line sha256: 214e9b44aa05fc21e21a0813e91dbf69a60c4ccdc31d7ca1ccc98fc40ea6eaeb
full test-line sha256 including new allocation-reuse test: 3333fbd45a02fee480efacee02509f4fc8f0c3cc871c16567126904b2145cd6b
full transcript sha256: b8b55a6af49396358a1d225648279400719089b35db819fd177682d38e54db69
```

Additional validation:

```text
rustfmt --check crates/frankenlibc-core/src/stdio/buffer.rs
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --lib -- -D warnings -A clippy::cmp_owned
```

`cargo clippy -p frankenlibc-core --all-targets -- -D warnings` remains blocked by unrelated pre-existing lints in `malloc/allocator.rs` (`cmp_owned`) and `stdlib/sort.rs` test code (`unnecessary_cast`).

## Benchmark Result

Post-change RCH criterion run on worker `ts2`:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
stdio_stream_buffer/full_buffered_write time: [395.67 ns 396.83 ns 398.21 ns]
stdio_stream_buffer/line_buffered_write time: [424.99 ns 426.26 ns 427.53 ns]
post benchmark transcript sha256: 38eff15a51a6bb0e9ff323c7291236fb3e51d8e1ac6718b887b3e988c3fda35e
```

Before/after midpoint deltas:

- full-buffered write: `436.52 ns -> 396.83 ns`, 39.69 ns faster, 9.09% improvement
- line-buffered write: `447.52 ns -> 426.26 ns`, 21.26 ns faster, 4.75% improvement

Score: Impact 3 x Confidence 3 / Effort 1 = 9.0. Keep.
