# bd-2g7oyh.463 pass179 strcpy4096 strlen-prefix copy keep

Date: 2026-06-17
Agent: BoldFalcon
Mode: local fallback, `RCH_REQUIRE_REMOTE=0` because `ts1`/remote RCH is offline
Commit base for this patch: `9c7f96bf7` (`chore(perf): route memchr absent pass 178`)

The intervening pass177/pass178 routing commits changed tracker/progress/evidence and f128 code, but no string source. The focused `strcpy_4096` baseline/post evidence below remains valid for the exact string implementation changed here.

## Target

Focused Criterion reproduced `strcpy_4096` as a material residual:

- FrankenLibC baseline: `68.660/73.892 ns` p50/mean, p95 `85.242`, p99 `91.997`
- Host glibc baseline: `50.118/53.324 ns` p50/mean, p95 `60.250`, p99 `65.000`
- Baseline log SHA-256: `615bfa886e302faa3febb5076897f19f77ddb27a51d0cf24b42fe6bd7d4c9b32`

Pass176 routed out the existing backend/source family, but it did not test this alternate source primitive.

## Lever

Replace the exact-4097 `strcpy` path's eight 512-byte NUL-probe blocks plus final full-slice copy with:

1. `strlen(src)` to find the first NUL once.
2. `copy_from_slice(&src[..strlen(src) + 1])` to copy exactly the prefix plus terminator.

This removes the duplicated source read in the old terminal no-NUL case and preserves early-NUL destination-tail behavior.

## Post Benchmark

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 \
  CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass177-strcpy-post-target \
  CRITERION_HOME=/data/tmp/frankenlibc-pass177-strcpy-post-criterion \
  cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
  glibc_baseline_strcpy_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC post: `57.549/61.406 ns` p50/mean, p95 `73.353`, p99 `86.027`
- Host glibc post: `44.848/46.155 ns` p50/mean, p95 `55.441`, p99 `59.686`
- Improvement vs focused FrankenLibC baseline: `1.193x` p50 and `1.203x` mean (`-16.2%` p50, `-16.9%` mean)
- Post log SHA-256: `93f53d3defd041ed3d216dd4a00251429fb691b587761abd58c18254de7cc7f1`

Score: `7.2` (`Impact 8.5 x Confidence 0.85 / Effort 1.0`). Keep threshold `>= 2.0` cleared.

## Behavior Proof

Isomorphism:

- First-NUL ordering is preserved by `strlen(src)`.
- Copied byte order is unchanged; the copied range is exactly `src[..strlen(src) + 1]`.
- Return count remains the inclusive-NUL byte count.
- Destination tail after an early NUL remains untouched.
- Panic behavior for too-small/no-synthetic-NUL-room inputs is unchanged by the outer `strcpy` preconditions.
- Overlap policy remains unchanged: safe core still uses Rust slice copy semantics.
- Allocation, errno, locale, floating-point state, and RNG state are not touched.
- Existing strcpy golden transcript SHA-256 remains `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`.

Validation:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: pass.
- `git diff --check`: pass.
- `cargo check -j 1 -p frankenlibc-core --lib`: pass; existing unrelated warnings in `iconv`.
- `cargo test -j 1 -p frankenlibc-core string::str::tests -- --nocapture`: pass, `141 passed`.
- `cargo fmt -p frankenlibc-core --check`: attempted, exits `1` on pre-existing unrelated core/generated-table formatting drift; touched `str.rs` passes rustfmt.
- `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`: attempted, exits `101` on pre-existing `iconv`/`resolv` lint debt; no finding references touched `str.rs`.

Proof log SHAs:

- Check log: `3ed0e4eaf8e7693b9f203f328cd661d505c58027ee85b6b8dc5b160476d087b4`
- Test log: `b08f3dfdb838c3b10a6894386c43eaf781dab30d32ca3843958299a629c63fd8`
- Quiet fmt log: `d0a57fb966efa3184a3aa9ed72703dbdbe739a51c3d3f23a16ee04c12783f6a6`
- Clippy log: `27f672b7c9804eb8b4226a4df16a2d24daefbf68767f9978494a5155f804f9ac`

## Next Route

Re-profile current head after this keep. Do not re-enter the old eight-block NUL-certificate copy family for `strcpy_4096`.
