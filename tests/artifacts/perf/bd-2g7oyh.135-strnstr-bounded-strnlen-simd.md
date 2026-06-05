# bd-2g7oyh.135 - strnstr bounded prefix via SIMD strnlen

## Target

`strnstr_bounded_absent_4096` was profile-backed as a residual string hotspot.
The search path already delegated to `memmem`; the remaining pre-search bound
calculation called scalar `strnlen` over the NUL-free bounded haystack prefix.

## Lever

One runtime lever:

```rust
pub fn strnlen(s: &[u8], maxlen: usize) -> usize {
    let limit = maxlen.min(s.len());
    strlen(&s[..limit])
}
```

This reuses the existing SIMD `strlen` kernel on the already-clamped prefix
slice. It cannot observe bytes beyond `min(maxlen, s.len())`.

## RCH Baselines

Focused pre-edit baseline, RCH remote `vmi1156319`:

- `strnstr_bounded_absent_16`: p50 50.656 ns, mean 55.221 ns
- `strnstr_bounded_absent_64`: p50 105.222 ns, mean 108.099 ns
- `strnstr_bounded_absent_256`: p50 340.168 ns, mean 336.212 ns
- `strnstr_bounded_absent_1024`: p50 1203.140 ns, mean 1216.886 ns
- `strnstr_bounded_absent_4096`: p50 4713.913 ns, mean 4710.506 ns

Clean same-worker pre-edit baseline from detached `HEAD` worktree, RCH remote
`ts2`:

- `strnstr_bounded_absent_16`: p50 28.345 ns, mean 31.304 ns
- `strnstr_bounded_absent_64`: p50 73.937 ns, mean 81.691 ns
- `strnstr_bounded_absent_256`: p50 223.854 ns, mean 225.346 ns
- `strnstr_bounded_absent_1024`: p50 817.196 ns, mean 846.324 ns
- `strnstr_bounded_absent_4096`: p50 3195.499 ns, mean 3193.822 ns

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env \
  CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_strnstr135_clean_base_ts2 \
  FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  strnstr_bounded_absent --sample-size 50 --measurement-time 3 \
  --warm-up-time 1 --noplot
```

## RCH Post-Benchmark

Same-worker post-edit run, RCH remote `ts2`:

- `strnstr_bounded_absent_16`: p50 21.809 ns, mean 23.790 ns
- `strnstr_bounded_absent_64`: p50 24.125 ns, mean 25.798 ns
- `strnstr_bounded_absent_256`: p50 27.205 ns, mean 28.784 ns
- `strnstr_bounded_absent_1024`: p50 36.035 ns, mean 39.040 ns
- `strnstr_bounded_absent_4096`: p50 81.630 ns, mean 83.674 ns

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env \
  CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_strnstr135_after \
  FRANKENLIBC_BENCH_PIN=1 \
  cargo bench -p frankenlibc-bench --bench string_bench -- \
  strnstr_bounded_absent --sample-size 50 --measurement-time 3 \
  --warm-up-time 1 --noplot
```

Same-worker p50 speedup at 4096 bytes: `3195.499 / 81.630 = 39.15x`.

## Behavior Proof

Isomorphism:

- Bound clamp is unchanged: `limit = maxlen.min(s.len())`.
- `strlen(&s[..limit])` can only inspect the clamped prefix.
- First-NUL ordering is unchanged: both old and new implementations return the
  first zero byte within the clamped prefix, else `limit`.
- `strnstr` leftmost match semantics are unchanged because the only changed
  value is `hay_end`, and the strengthened property proves it equals the scalar
  bounded first-NUL reference.
- Tie-breaking, floating point, and RNG state are not applicable.

Golden SHA-256:

- `strnstr_golden_corpus_sha256` passed.
- Digest: `84555952f755c0ff071a2b064db484fb74e838c180632c105f9b034f0e9bafa7`.

RCH validation:

- `cargo test -p frankenlibc-core strn -- --nocapture`: passed on remote `ts1`.
  This executed 28 inline strn tests including the new SHA corpus, plus 5
  property/golden tests including `prop_strnlen_bounded`.
- `cargo check -p frankenlibc-core --all-targets`: passed on remote `ts1`.
- `git diff --check` for scoped files: passed.

Known blockers outside this lever:

- `cargo fmt --check --package frankenlibc-core` is blocked by broad pre-existing
  formatting drift in unrelated core files.
- `cargo clippy -p frankenlibc-core --all-targets -- -D warnings` is blocked by
  existing lints in `regex.rs`, `wide.rs`, `sort.rs`, `fnmatch.rs`, and older
  tests in `str.rs`; no diagnostic targets the `strnlen` implementation change
  or the new `strnstr` SHA test.

## Score

Score = `(Impact 5 * Confidence 5) / Effort 1 = 25.0`.

Kept.
