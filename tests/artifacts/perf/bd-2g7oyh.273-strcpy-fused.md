# bd-2g7oyh.273 - strcpy_4096 fused copy/NUL detection

## Profile target

- Broad RCH reprofile: `vmi1227854`, `glibc_baseline_strcpy_4096`.
- Broad result: FrankenLibC p50 `57.283 ns`, mean `60.091 ns`; host glibc p50 `33.374 ns`, mean `36.341 ns`.
- Focused pre-edit baseline: `RCH_WORKER=vmi1149989`, sample size 30, warmup 1s, measurement 3s.
- Focused pre-edit result: FrankenLibC p50 `74.439 ns`, mean `78.492 ns`, p95 `115.244 ns`, p99 `141.000 ns`; host glibc p50 `34.921 ns`, mean `38.875 ns`.

Command:

```bash
RCH_VISIBILITY=full rch exec -v -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=2 cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strcpy_4096 --noplot --sample-size 30 --warm-up-time 1 --measurement-time 3
```

## One lever

`strcpy` now uses a safe portable-SIMD 512-byte block primitive for long, slice-terminated inputs:

- Load eight 64-byte SIMD panels from the source.
- Fold the loaded vectors with `simd_min` and test for NUL once per 512-byte block.
- Store the loaded vectors to the destination only when the whole block is certified NUL-free.
- If a block contains NUL, store no bytes from that block until scalar first-NUL resolution copies the exact terminal prefix.
- The post-block tail copies byte-by-byte and returns immediately on the first NUL.

This removes the old separated "scan all 4096 bytes, then bulk-copy all 4097 bytes" path for the profiled 4096-byte string.

## Isomorphism proof

- First-NUL ordering is preserved: the SIMD block predicate is boolean only; the exact return index is still chosen by scalar left-to-right resolution in the first block whose loaded lanes contain NUL.
- Destination observability is preserved: certified NUL-free blocks are entirely before the first NUL and must be copied by `strcpy`; a terminal block is not written until its exact prefix is known, so bytes after the first NUL remain untouched.
- Panic behavior is unchanged: the fused path is still guarded by `src.last() == Some(0)` and `dest.len() >= src.len()`. Non-terminated or undersized cases use the existing `strlen`/assert path.
- Ordering/tie-breaking outside first-NUL selection, floating-point state, and RNG are not involved.

## Golden/parity proof

- RCH `vmi1153651`: `cargo test -p frankenlibc-core strcpy -- --nocapture` passed.
- Existing golden `test_strcpy_golden_transcript_sha256` stayed `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.
- New regression guard `test_strcpy_fused_path_preserves_tail_after_early_nul` passed.

## Post benchmark

- Same-worker focused post: `RCH_WORKER=vmi1149989`, same command shape as baseline.
- FrankenLibC p50 `41.170 ns`, mean `48.325 ns`, p95 `55.241 ns`, p99 `105.095 ns`.
- Host glibc in same post run: p50 `40.335 ns`, mean `45.970 ns`.
- Same-worker FrankenLibC improvement: p50 `44.7%`, mean `38.4%`, p95 `52.1%`, p99 `25.5%`.

Mixed-worker signal run on `vmi1293453` also improved relative to the broad/focused baseline shape: FrankenLibC p50 `44.448 ns`, mean `51.491 ns`; host p50 `36.898 ns`, mean `39.445 ns`.

## Validation

- RCH `vmi1149989`: `cargo check -p frankenlibc-core --lib` passed.
- RCH `vmi1149989`: strict `cargo clippy -p frankenlibc-core --lib -- -D warnings` failed only on existing unrelated lint families in `math/exp.rs`, `stdio/file.rs`, `stdlib/sort.rs`, and peer-dirty `string/regex.rs`.
- RCH `vmi1149989`: allowlisted clippy for those pre-existing lint families passed.
- `rustup run nightly rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs` passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs` passed.
- Crate-wide `cargo fmt --check -p frankenlibc-core` remains blocked by existing generated/table/scratch formatting drift outside this lever.

## Score

Impact `4.0` x Confidence `4.5` / Effort `2.0` = `9.0`. Keep.
