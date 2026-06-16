# bd-2g7oyh.426 - strlen_4096 public-inline codegen keep

Date: 2026-06-16
Agent: BoldFalcon
Worker: vmi1227854
Verdict: KEPT
Score: `(Impact 3.5 x Confidence 4.5) / Effort 1.0 = 15.8`

## Route

Current-head broad RCH profile on `vmi1227854` after `c290e5c39` selected
`glibc_baseline_strlen_4096` as a reproduced string residual:

- FrankenLibC broad Criterion center/p50/mean: `24.735/24.763/26.835 ns`
- host glibc broad Criterion center/p50/mean: `19.134/18.754/20.714 ns`

Prior no-retry families for this lane: page-scale and larger folded NUL
certificates, dual-512 loop structure, exact terminal-length and unrolled
512-byte certificates, and 32-byte-lane folded scan reshaping.

## Focused Baseline

RCH worker: `vmi1227854`

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-baseline-20260616T0306-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-baseline-20260616T0306-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC Criterion: `[25.508 ns 25.789 ns 26.080 ns]`
- FrankenLibC p50/mean: `25.961/29.879 ns`
- host glibc Criterion: `[22.235 ns 22.901 ns 23.723 ns]`
- host glibc p50/mean: `22.293/23.461 ns`

The focused gap reproduced.

## Lever

One source lever in `crates/frankenlibc-core/src/string/str.rs`:

```rust
#[inline(always)]
#[allow(unsafe_code)]
pub fn strlen(s: &[u8]) -> usize
```

The function body is unchanged. This is a codegen-boundary lever that exposes
the existing safe-Rust generated scan to the benchmark caller instead of
retuning panel width or adding an exact terminal-length certificate.

## Behavior Proof

Proof commands:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-proof-core-20260616T0311-target cargo test -j 1 -p frankenlibc-core --lib strlen -- --nocapture --test-threads=1
```

Result: passed 6/6 filtered tests.

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-proof-suite-20260616T0320-target cargo test -j 1 -p frankenlibc-core --test property_tests prop_strlen_finds_first_nul -- --nocapture --test-threads=1
```

Result: passed 1/1.

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_MODE=strict CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-proof-abi-20260616T0322-target cargo test -j 1 -p frankenlibc-abi --test conformance_diff_string_mut diff_strlen_cases -- --nocapture --test-threads=1
```

Result: passed 1/1.

Golden fixture SHAs:

```text
27cc53f44e4d83352210d2e7b305cfff2729276ce31e31b03e24116f831b2f89  tests/conformance/fixtures/string_ops.json
b5509edb2fc90403daf10fbef4944369aff58e26569d6a03b77b6317c646667f  tests/conformance/fixtures/strlen_strict.json
```

Candidate source SHA:

```text
807aac872b3bd7b4ec24b3819a59632a15f8abfee521a94613c554084cad6ddd  crates/frankenlibc-core/src/string/str.rs
```

Isomorphism: adding `#[inline(always)]` changes only the caller/codegen
boundary. The 512-byte folded detector, 256-byte fallback, 64-byte fallback,
word fallback, final byte resolver, first-NUL ordering, no-NUL result, panic
surface, floating-point state, RNG state, allocation behavior, errno, and locale
behavior are unchanged.

## Post Benchmark

RCH worker: `vmi1227854`

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 RCH_WORKERS=vmi1227854 RCH_PREFERRED_WORKER=vmi1227854 RCH_BUILD_SLOTS=1 rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-post-20260616T0316-target CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-426-strlen-post-20260616T0316-criterion cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- glibc_baseline_strlen_4096 --noplot --sample-size 70 --warm-up-time 1 --measurement-time 3
```

Results:

- FrankenLibC Criterion: `[20.013 ns 20.342 ns 20.642 ns]`
- FrankenLibC p50/mean: `19.875/23.203 ns`
- host glibc Criterion: `[19.913 ns 20.538 ns 21.185 ns]`
- host glibc p50/mean: `21.630/23.694 ns`

Same-worker self delta:

- Criterion center: `25.789 -> 20.342 ns` (`21.1%` lower)
- p50: `25.961 -> 19.875 ns` (`23.4%` lower)
- mean: `29.879 -> 23.203 ns` (`22.3%` lower)

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs`: passed.
- `git diff --check -- crates/frankenlibc-core/src/string/str.rs`: passed.
- RCH `cargo check -j 1 -p frankenlibc-core --lib`: passed with only the pre-existing missing-SMT-solver warning.
- Strict clippy was attempted twice, but RCH refused remote-required execution because no worker was admissible (`critical_pressure=1,insufficient_slots=1,hard_preflight=8`). No local fallback evidence was used.

## Verdict

Kept. Do not retry public-wrapper inlining for `strlen`; the next `strlen`
route, if still material after reprofile, needs a different
generated/disassembly-backed primitive.
