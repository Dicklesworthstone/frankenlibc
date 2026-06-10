# bd-2g7oyh.320 strlen_4096 dual-512 rejection

Date: 2026-06-10
Agent: BoldFalcon

## Target

Fresh broad RCH profile at `43d172d8` on `vmi1227854` showed `strlen_4096`
as the next unowned residual after excluding peer-owned `pow*` and `strncmp`:

- FrankenLibC p50 `26.172 ns`, mean `33.258 ns`.
- Host glibc p50 `19.323 ns`, mean `24.093 ns`.

Prior `bd-2g7oyh.294` rejected larger folded-NUL/page-certificate families, so
this pass required a structurally different source lever.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-320-strlen4096-baseline-target-20260610T072400Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-320-strlen4096-baseline-criterion-20260610T072400Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_strlen_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Same-worker focused baseline on `vmi1227854`:

- FrankenLibC: Criterion interval `[24.680 ns 24.811 ns 24.947 ns]`; benchmark-line p50 `24.818 ns`, mean `29.898 ns`, p95 `30.000 ns`, p99 `70.000 ns`.
- Host glibc: Criterion interval `[20.444 ns 21.199 ns 21.867 ns]`; benchmark-line p50 `20.135 ns`, mean `23.800 ns`, p95 `28.163 ns`, p99 `75.000 ns`.

Focused gap reproduced at `1.23x` p50 / `1.26x` mean.

## Candidate Lever

Rejected candidate: dual-512 long-span loop in `strlen`.

Shape:

- Keep the existing proven `block_has_nul_512` primitive.
- Probe two independent 512-byte certificates per outer loop.
- If the left half reports NUL, break to the existing left-to-right resolver.
- If the right half reports NUL, advance exactly one 512-byte half, then break to the same resolver.
- If neither half reports NUL, skip 1024 bytes.

This was not the rejected 4096-byte page certificate from `bd-2g7oyh.294`; it
changed loop structure only.

Candidate isomorphism while present:

- First-NUL ordering is preserved because the right half is only considered after the left half reports no NUL.
- Exact NUL index remains resolved by the existing 512/256/64/word/byte left-to-right path.
- No-NUL behavior still returns `s.len()`.
- Floating point and RNG are not involved.

## Candidate Proof

Commands run while the candidate was present:

```text
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
git diff --check -- crates/frankenlibc-core/src/string/str.rs
```

RCH proof on `vmi1227854`:

```text
cargo test -j 1 -p frankenlibc-core --lib test_strlen -- --nocapture --test-threads=1
cargo test -j 1 -p frankenlibc-core --test property_tests prop_strlen_finds_first_nul -- --nocapture --test-threads=1
cargo test -j 1 -p frankenlibc-abi --test conformance_diff_string_mut diff_strlen_cases -- --nocapture --test-threads=1
```

Results:

- Core filtered `strlen` unit tests: 5 passed, including the temporary dual-block boundary case.
- Property test `string_properties::prop_strlen_finds_first_nul`: passed.
- ABI differential `diff_strlen_cases`: passed.
- An earlier probe used `conformance_diff_string diff_strlen_cases`, but that binary contains no such test and ran 0 tests; it is not counted as proof.

## Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854 \
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN' \
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1 \
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-320-strlen4096-post-target-20260610T074100Z \
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-320-strlen4096-post-criterion-20260610T074100Z \
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench -- \
glibc_baseline_strlen_4096 --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Same-worker post on `vmi1227854`:

- FrankenLibC: Criterion interval `[24.376 ns 24.625 ns 24.894 ns]`; benchmark-line p50 `24.362 ns`, mean `26.574 ns`, p95 `26.614 ns`, p99 `45.000 ns`.
- Host glibc: Criterion interval `[19.288 ns 19.732 ns 20.199 ns]`; benchmark-line p50 `19.305 ns`, mean `21.018 ns`, p95 `23.957 ns`, p99 `60.000 ns`.

Absolute FrankenLibC movement was small by p50 (`24.818 -> 24.362 ns`, 1.9%)
and moderate by mean (`29.898 -> 26.574 ns`, 12.5%), but the same-run host
control moved more. Relative gap worsened slightly:

- p50 ratio: `1.233x` baseline to `1.262x` post.
- mean ratio: `1.256x` baseline to `1.264x` post.

## Verdict

REJECTED-RESTORED, Score `0.0`.

No source change is kept. `crates/frankenlibc-core/src/string/str.rs` was
manually restored and verified:

```text
git diff --exit-code -- crates/frankenlibc-core/src/string/str.rs
rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/str.rs
```

Restored `str.rs` SHA-256:

```text
5eb2974530ce7264233c9788e0ded187cd318aeb794ebaf88a4d94ef7fbbe8ef  crates/frankenlibc-core/src/string/str.rs
```

Next route: do not retry `strlen` dual-512 loop structure, larger folded-NUL
blocks, or page-scale NUL-free certificates without disassembly/codegen evidence.
Reprofile and attack a different reproduced unowned residual, or return to
`strlen` only with a materially different primitive such as codegen-backed
rank/select resolution or an ISA/layout route that changes the generated hot
loop rather than outer-loop branch count.
