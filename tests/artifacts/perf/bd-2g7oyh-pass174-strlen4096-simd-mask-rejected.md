# bd-2g7oyh pass174: strlen4096 SIMD mask candidate rejected

Date: 2026-06-17
Agent: BoldFalcon
Bead: `bd-2g7oyh.458`
Target: `glibc_baseline_strlen_4096`

## Profile-backed target

Pass172 current-head routing selected `strlen_4096` as the next non-recent material residual after `memcmp_4096`, `memmove_4096`, `strcpy_4096`, and `memchr_absent` were already routed out by fresh no-repeat/codegen evidence.

Pre-change baseline reused from pass173 on the restored source:

- FrankenLibC Criterion: `[25.984 ns 26.465 ns 26.961 ns]`
- FrankenLibC p50/mean: `25.466/29.884 ns`
- Host Criterion: `[19.585 ns 19.887 ns 20.253 ns]`
- Host p50/mean: `19.211/21.986 ns`
- Baseline log SHA-256: `7383d14b6b7e0c61222f769732e012f54dd0087d5a18720bb521683b78bef761`
- Restored source SHA-256 before candidate: `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`

## Alien primitive

Graveyard mapping: Swiss-table-style metadata/probe separation, using packed SIMD equality probes plus a mask extraction/reduction. The candidate replaced the 512B folded `vpminub` NUL certificate in `block_has_nul_512` with explicit zero-comparison mask accumulation across eight 64B panels. The exact first-NUL position remained delegated to the existing scalar/word resolver.

EV before implementation:

- Impact: `4` (hot string scan residual, originally 1.274x p50 slower than host in focused pass173)
- Confidence: `3` (codegen should become compare/mask, but prior string micro-levers have been noisy)
- Effort: `2`
- Score: `6.0`, eligible to test

## Candidate change

One source lever only:

- `crates/frankenlibc-core/src/string/str.rs`: `block_has_nul_512` changed from eight-vector `simd_min` folding to `Mask<i8, 64>` OR accumulation of `panel.simd_eq(zero)`.
- A temporary `strlen` golden transcript test was added only while proving the candidate; it was removed when the candidate was rejected.

Candidate source SHA-256 before final restore:

- Runtime-only candidate before temporary test: `aa510f8935737e46687fecc7ed7e755b0f37e7737bf897a7699853c1068b0077`
- Temporary proof-test candidate: `ee252f6295e655f283fffd5e17dc8d63d4f95e9036463c9901d9c94e321caa04`

## Behavior proof

Ordering/tie-breaking:

- Preserved. The candidate only changed the 512B "does this block contain any NUL?" certificate. The existing resolver still scans the same slice range in increasing byte order and returns the first NUL.

Floating point:

- N/A. String scan only.

RNG:

- Unchanged. No random state touched.

Allocation/errno/locale:

- Runtime behavior unchanged. The scan still reads only within the provided slice; no allocation, errno, or locale path was added.

Golden/output proof while candidate was present:

- `cargo test -j 1 -p frankenlibc-core --lib strlen -- --nocapture --test-threads=1`: 7/7 passed after adding the temporary `test_strlen_golden_transcript_sha256`.
- Temporary `strlen` golden transcript SHA-256: `9a8f09e4777ff293c1c18ca46baa6e3c7fb07762f0dcb94321d2c4cc7476617b`
- `cargo test -j 1 -p frankenlibc-core --lib strcpy -- --nocapture --test-threads=1`: 7/7 passed, including `test_strcpy_golden_transcript_sha256`.
- `strcpy` golden transcript SHA-256: `fe05ef410f204902cd5f53586645647b8ce5db87e49b840752b24d2b11995401`
- `PROPTEST_CASES=512 cargo test -j 1 -p frankenlibc-core --test property_tests prop_strlen_finds_first_nul -- --nocapture --test-threads=1`: 1/1 passed.

Proof log SHA-256:

- `strlen` focused test: `7aa2666dd7f1d9e68bec137d37ff72c9eb5def569fbd13e322d2cfbecbfa6001`
- `strcpy` focused test: `82bd77d49731fe61f7676a5e5e4e04edd7092c0108791097d50098eaf6584303`
- external property test: `04926f61fb1a810b6537ed76b6871d1302d3fdeb8ceb01d817964fb6724af341`

## Codegen screen

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 CARGO_BUILD_JOBS=1 \
  CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass174-strlen-codegen-target \
  RUSTFLAGS='-Ctarget-feature=+avx2,+fma --emit=llvm-ir,asm' \
  cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Hashes:

- codegen log SHA-256: `f11efe269183187e6b82a4df6f22807b19ce63eea39681ce5b01bfb6da83a8fa`
- LLVM IR SHA-256: `d2c81ee916ee1f67b4f9bed7d717c475583f6ebc0bcad2193d3bfa12640693c0`
- assembly SHA-256: `4f25683ed42ede10d1d9e40d34708e75b04b5161d1b18c0a2d32ef2c4e61bc42`

Relevant assembly excerpt confirmed the candidate generated a 512B compare/mask tree:

```asm
vpcmpeqb	(%r14,%rcx), %ymm0, %ymm1
vpcmpeqb	32(%r14,%rcx), %ymm0, %ymm2
...
vpcmpeqb	480(%r14,%rcx), %ymm0, %ymm4
vpor	%ymm2, %ymm1, %ymm1
vpsllw	$7, %ymm1, %ymm1
vpmovmskb	%ymm1, %edx
```

The remaining `vpminub` hits in the generated file are from the separate 256B helper, which this pass intentionally did not change.

## Benchmark result

Focused local Criterion commands used `RCH_REQUIRE_REMOTE=0`, `FRANKENLIBC_BENCH_PIN=1`, crate-scoped `cargo bench -p frankenlibc-bench --bench glibc_baseline_bench`, sample size 100, warm-up 1s, measurement 3s.

Final-source post run:

- FrankenLibC Criterion: `[27.484 ns 28.095 ns 28.785 ns]`
- FrankenLibC p50/mean: `27.354/33.059 ns`
- Host Criterion: `[20.649 ns 21.050 ns 21.465 ns]`
- Host p50/mean: `19.987/28.415 ns`
- Log SHA-256: `ff179c2fb9519d1b6cbab5f2f0518fe000f172eff25e23eeb6455d00bcab6e33`

Repeat post run:

- FrankenLibC Criterion: `[27.706 ns 28.269 ns 28.876 ns]`
- FrankenLibC p50/mean: `27.760/30.302 ns`
- Host Criterion: `[19.752 ns 20.080 ns 20.458 ns]`
- Host p50/mean: `19.701/21.359 ns`
- Log SHA-256: `acca8eadf19cae45e75808d8ec0b1397f484ce84308389c103475c8a3d0990c7`

There was one earlier fast post-run while the candidate was present, but it did not reproduce after final-source reruns. Per the keep rule, non-reproducible wins do not ship.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed after final restore.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed.
- `cargo check -j 1 -p frankenlibc-core --lib`: passed with pre-existing warnings. Log SHA-256 `a2379fa1de76b52bd2659bc7448c3bf219304f8e7f4a1dcc3dc8c8c479dd786f`.
- `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`: attempted and failed on pre-existing `iconv`/`resolv` lint debt, not the candidate. Log SHA-256 `89d147de38e3c0e9417267feb06f4216e73a1c8facb8f4e32e18b4fac2ad9301`.

Final restore:

- `str.rs` restored manually to SHA-256 `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`
- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs`: passed

## Verdict

Rejected and restored.

The final two post-runs regressed versus the pass173 baseline:

- p50: `25.466 ns` baseline -> `27.354 ns` and `27.760 ns`
- mean: `29.884 ns` baseline -> `33.059 ns` and `30.302 ns`

Score after measurement: `0.0`. Do not retry explicit 512B zero-mask accumulation for `strlen_4096` without a fundamentally different dispatch/codegen primitive.

Next route: reprofile current head locally and move to the next profile-backed residual. If `strlen_4096` remains material, avoid slice-position and explicit-mask accumulation; target a deeper generated/backend dispatch primitive or a different string workload.
