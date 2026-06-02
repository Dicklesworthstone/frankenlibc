# bd-usvgpi stdio line-buffer fast path proof

## Target

`StreamBuffer::write_line` in `crates/frankenlibc-core/src/stdio/buffer.rs`.

Baseline from the profile-backed bead:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench stdio_bench -- --sample-size 50 --noplot
```

Baseline rch worker: `vmi1293453`.

| Bench | Baseline |
|---|---:|
| `stdio_stream_buffer/line_buffered_write` | 405.94 ns |
| `stdio_stream_buffer/full_buffered_write` | 298.37 ns |

## Alien primitive recommendation card

- Symptom: line-buffered writes pay reverse-scan and flush-vector assembly cost even when the common case has no pending buffered bytes and the new data already ends with newline.
- Graveyard route: constants/cache hot-path elimination; remove redundant work on a proven state predicate before reaching heavier general logic.
- Primitive: guarded fast path for an already-complete line in an empty buffer.
- EV: Impact 3 x Confidence 5 x Reuse 3 / Effort 1 x AdoptionFriction 1 = 45.0.
- Fallback trigger: reject if post-rch `line_buffered_write` fails to improve or if focused line-buffer golden sha changes unexpectedly.

## One lever

Add one early return to `write_line`:

- predicate: `self.write_len == 0 && data.last().copied() == Some(b'\n')`
- result: `flush_needed=true`, `flush_data=data.to_vec()`, `buffered=0`, `flushed_from_buffer=0`

No benchmark harness, global state, buffering mode, read path, full-buffer path, or unbuffered path changed.

## Isomorphism proof

- Flush ordering is preserved: with an empty pending buffer and a trailing newline, the old path found the final newline at `data.len() - 1`, set `flush_end=data.len()`, and flushed exactly `data`.
- Pending state is preserved: old and new paths both leave `self.write_len=0` and no pending write data.
- `flushed_from_buffer` is preserved: the predicate requires `self.write_len==0`, so the old path also reported zero previously buffered bytes.
- Non-trailing newline cases are unchanged because they fall through to the original `rposition` path.
- No-newline cases are unchanged because the predicate is false and the function still delegates to `write_full`.
- Floating-point and RNG behavior are unaffected; this path only copies bytes into a returned `Vec`.

## Golden behavior

Post-edit direct rch test command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core line_buffer -- --nocapture
```

Post-edit rch job: `29869223945702339` on `vmi1156319`.

Result: 4/4 focused line-buffer tests passed.

Focused test-line sha256:

```text
08972ca971510cb55f25f1e39ecaeb9477f35f0fbc949e583d281e390f926288
```

## Post-benchmark

Post command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench stdio_bench line_buffered_write -- --sample-size 50 --noplot
```

Post rch job: `29869223945702354` on `vmi1227854`.

| Bench | Before | After | Delta |
|---|---:|---:|---:|
| `stdio_stream_buffer/line_buffered_write` | 405.94 ns | 380.45 ns | -6.3% |

Score: Impact 3 x Confidence 4 / Effort 1 = 12.0.

## Validation

- `TMPDIR=/data/tmp cargo fmt -p frankenlibc-core --check`: passed locally because `rch` refuses non-compilation fmt commands.
- `git diff --check -- crates/frankenlibc-core/src/stdio/buffer.rs .skill-loop-progress.md tests/artifacts/perf`: passed locally.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core line_buffer -- --nocapture`: passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`: passed via rch job `29869223945702367` on `vmi1227854`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: passed via rch job `29869223945702379` on `vmi1149989`.
