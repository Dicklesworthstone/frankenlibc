# bd-2g7oyh.457 pass173 strlen_4096 slice-position rejected

## Target

- Bead: `bd-2g7oyh.457`
- Parent: `bd-2g7oyh`
- Profile: `glibc_baseline_strlen_4096`
- Reason: pass172 current-head routing showed a material non-recent residual: FrankenLibC `28.259/30.459 ns` p50/mean vs host `20.478/22.857 ns`.
- Constraint: `ts1`/remote RCH is offline, so this pass used local crate-scoped Cargo/Criterion with isolated target directories and `-j 1`.

## Baseline

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass173-strlen-baseline-target CRITERION_HOME=/data/tmp/frankenlibc-pass173-strlen-baseline-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion interval: `[25.984 ns 26.465 ns 26.961 ns]`
- FrankenLibC p50/mean: `25.466/29.884 ns`
- Host glibc Criterion interval: `[19.585 ns 19.887 ns 20.253 ns]`
- Host glibc p50/mean: `19.211/21.986 ns`
- Ratio: `1.326x` p50, `1.359x` mean
- Log SHA-256: `7383d14b6b7e0c61222f769732e012f54dd0087d5a18720bb521683b78bef761`
- Source SHA-256 before lever (`str.rs`): `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`

## Codegen Screen

Command:

```bash
env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass173-strlen-codegen-target RUSTFLAGS='-Ctarget-feature=+avx2,+fma --emit=llvm-ir,asm' cargo build -j 1 -p frankenlibc-core --lib --profile bench
```

Result:

- Codegen log SHA-256: `10e6e7f96a9068fe6d12a39f6aa043d9de7f888ab481097b1857c41b39b8f571`
- LLVM IR SHA-256: `a37d06881cd1407ed23a7cdedb5bfffd7f0c92112f4bbbb326401d22aa62fa98`
- Assembly SHA-256: `7c98f7dcd2625af4afc8eb847e931d3f1ba3dfcf1c4ad60abe3f91f9523c9a5e`
- Existing codegen uses a manual `vpminub` reduction tree for the folded scan, then scalar/word exact-position resolution. No external `strlen`/`memchr` call is present in the hot path.

## Lever

One source lever tested: replace the manual folded `strlen` scan with the compiler-recognizable slice-position byte search:

```rust
s.iter().position(|&byte| byte == 0).unwrap_or(s.len())
```

This is an alien-graveyard-inspired backend/generated probe-family test: delegate the byte-position primitive to compiler/core lowering instead of retuning the current folded SIMD panel tree.

## Behavior Proof

Candidate behavior proof passed before benchmarking:

- Focused unit/golden tests: `cargo test -j 1 -p frankenlibc-core --lib strlen -- --nocapture --test-threads=1`
  - Result: `7 passed`
  - Golden strlen transcript SHA-256: `06d929e45318be61efda62cb4aaddf73228a6eea597db7ba8a4f91d00fd771df`
  - Log SHA-256: `7138864dc62e31f66856141d11664d566f29621a76543dfb47df269977acdf19`
- External property test: `cargo test -j 1 -p frankenlibc-core --test property_tests prop_strlen_finds_first_nul -- --nocapture --test-threads=1`
  - Result: `1 passed`
  - Log SHA-256: `cacc74b7d564320dc45f8d3c38ba36e40d15f3af21b694b1086f65e6fcda5e00`

Isomorphism: slice-position returns the first index whose byte is `0`, or `s.len()` when absent. This preserves first-NUL position, zero-length behavior, no-read-past-slice behavior, allocation behavior, errno/locale state, FP behavior, and RNG behavior.

## Post Benchmark

Command:

```bash
env AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=0 FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-pass173-strlen-post-target CRITERION_HOME=/data/tmp/frankenlibc-pass173-strlen-post-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 100 --warm-up-time 1 --measurement-time 3
```

Result:

- FrankenLibC Criterion interval: `[1.0419 us 1.0612 us 1.0813 us]`
- FrankenLibC p50/mean: `1027.180/1081.701 ns`
- Host glibc Criterion interval: `[20.361 ns 20.666 ns 21.002 ns]`
- Host glibc p50/mean: `20.177/22.489 ns`
- Log SHA-256: `5a674160ca5b247d50754add3b26423aae7840436a8abef2b1ac4885f8d9ed77`

## Verdict

REJECTED and restored. Score `< 0`.

Source restoration proof:

- `str.rs` SHA-256 after restore: `807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd`
- `git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs` passed.

Do not retry the slice-position/compiler-iterator lowering family for `strlen_4096`. Next route: stay on the profile-backed `strlen_4096` residual but attack a deeper generated SIMD mask primitive: a mask-accumulating zero-byte certificate with explicit `vpcmpeqb`/`vpmovmskb` shape, not another iterator lowering or width-only retune.
