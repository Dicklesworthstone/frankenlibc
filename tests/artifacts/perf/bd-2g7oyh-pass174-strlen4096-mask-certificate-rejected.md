# bd-2g7oyh pass174: strlen4096 SIMD mask certificate rejected

## Target

- Bead: `bd-2g7oyh.458`
- Profile row: `glibc_baseline_strlen_4096`
- Source baseline: pass173 restored `str.rs` SHA-256 `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`
- Baseline timing reused from pass173 focused local gate while `ts1` was offline:
  - FrankenLibC: `25.466 ns` p50, `29.884 ns` mean
  - host glibc: `19.211 ns` p50, `21.986 ns` mean
  - baseline log SHA-256: `7383d14b6b7e0c61222f769732e012f54dd0087d5a18720bb521683b78bef761`

## Lever

One source lever was tested in clean worktree `/data/tmp/frankenlibc-pass174-clean-20260617T082316Z`:

- Replace the eight-panel `block_has_nul_512` folded `simd_min` zero certificate with explicit per-panel `simd_eq(0)` mask accumulation.
- No caller shape changed. `strlen` still resolves the exact first NUL by re-scanning the same 512-byte block, so ordering, first-NUL selection, no-read-past-slice behavior, zero-length behavior, allocation, errno, locale, FP, and RNG state are unchanged.
- `strcpy_4096_terminated` callers of `block_has_nul_512` see the same boolean predicate and still copy through the existing scalar terminal resolver when the block may contain NUL.

## Behavior proof

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass174-mask-test-target \
  cargo test -j 1 -p frankenlibc-core string::str::tests -- --nocapture
```

Result:

- Passed `141/141` filtered `string::str::tests`.
- Covered focused `strlen` unit/property tests, `strcpy_exact_4096_path_preserves_tail_after_early_nul`, and `test_strcpy_golden_transcript_sha256`.
- Existing unrelated warnings remained in `iconv` and `regex`; no warning came from the edited detector.

## Post benchmark

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass174-mask-bench-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass174-mask-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strlen_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Log: `/data/tmp/frankenlibc-pass174-strlen-mask-post.log`

Log SHA-256: `56bf5ebebd4958018eb4c117a5ee7e2b09a5237bd50f1f07a58b811a4d683258`

Rows:

- Candidate FrankenLibC: `26.893 ns` p50, `31.125 ns` mean
- Host glibc: `20.540 ns` p50, `22.939 ns` mean

## Verdict

Rejected and restored. The explicit mask certificate regressed FrankenLibC by `5.6%` p50 and `4.2%` mean against the pass173 current-source baseline.

Score: `0.0` because Impact is negative.

Restoration proof:

```bash
git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs
sha256sum crates/frankenlibc-core/src/string/str.rs
```

Restored source SHA-256: `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`.

Next route: do not retry slice-position lowering or explicit compare-mask accumulation for `strlen_4096`. The next `strlen_4096` attempt needs a genuinely different generated/backend primitive, such as disassembly-proven fixed-length no-terminator certification, page-crossing-aware chunk dispatch, or another algorithmic lowering that changes more than the zero-test reduction tree.
