# bd-2g7oyh.319 - strtol_short focused keep

Date: 2026-06-10
Agent: BoldFalcon
Worker: vmi1227854
Commit base: 0bfcc03a

## Target

Fresh pass-45 broad RCH profile selected `glibc_baseline_strtol_short`
(`b"42\0"`, base 10) as an unowned reproduced stdlib residual.

## Lever

Add a narrow safe-Rust fast path in `strtol_impl` after invalid-base validation
and before whitespace/sign/prefix setup:

- exact `base == 10`
- first byte is an ASCII digit
- return directly only for one- or two-digit runs followed by end or a nondigit
- otherwise fall through to the existing whitespace/sign/base-prefix/SWAR/overflow parser

This keeps invalid-base ordering, whitespace/sign behavior, base-0 inference,
`0x`/`0b` prefix handling, consumed-byte/endptr behavior, overflow/underflow,
FP, and RNG behavior unchanged.

## Focused Baseline

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN'
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-319-strtol-short-baseline-target-20260610T064100Z
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-319-strtol-short-baseline-criterion-20260610T064100Z
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
strtol_short --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Results:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| frankenlibc_core | 11.380 | 12.797 | 15.698 | 45.000 |
| host_glibc | 6.903 | 9.691 | 9.509 | 30.000 |

## Final Post Benchmark

Command:

```text
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=vmi1227854
RCH_ENV_ALLOWLIST='AGENT_NAME CARGO_TARGET_DIR CRITERION_HOME CARGO_BUILD_JOBS FRANKENLIBC_BENCH_PIN'
rch exec -- env AGENT_NAME=BoldFalcon FRANKENLIBC_BENCH_PIN=1 CARGO_BUILD_JOBS=1
CARGO_TARGET_DIR=/data/tmp/frankenlibc-bd-2g7oyh-319-strtol-short-post2-target-20260610T071000Z
CRITERION_HOME=/data/tmp/frankenlibc-bd-2g7oyh-319-strtol-short-post2-criterion-20260610T071000Z
cargo bench -j 1 -p frankenlibc-bench --bench glibc_baseline_bench --
strtol_short --noplot --sample-size 50 --warm-up-time 1 --measurement-time 3
```

Results:

| impl | p50 ns/op | mean ns/op | p95 ns/op | p99 ns/op |
| --- | ---: | ---: | ---: | ---: |
| frankenlibc_core | 5.543 | 7.184 | 7.600 | 40.000 |
| host_glibc | 8.723 | 11.771 | 12.966 | 45.000 |

Delta: FrankenLibC p50 improved `11.380 -> 5.543 ns` (`2.05x`);
mean improved `12.797 -> 7.184 ns` (`1.78x`). The final run is also faster
than host glibc for this focused row (`1.57x` p50, `1.64x` mean).

Score: KEPT, `6.0` (`Impact 3 x Confidence 4 / Effort 2`).

## Proof

Green gates:

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/stdlib/conversion.rs`
- `git diff --check -- crates/frankenlibc-core/src/stdlib/conversion.rs`
- RCH `vmi1227854`: `cargo test -j 1 -p frankenlibc-core --lib strtol -- --nocapture --test-threads=1`
  - final source: `26 passed; 0 failed`
- RCH `vmi1227854`: `cargo test -j 1 -p frankenlibc-abi --test conformance_diff_stdlib_numeric diff_strtol -- --nocapture --test-threads=1`
  - `diff_strtol_cases`, `diff_strtoll_cases`, and `diff_strtol_strtoul_all_bases_fuzz` passed
- RCH `vmi1227854`: `cargo test -j 1 -p frankenlibc-abi --test strtol_family_differential_fuzz -- --nocapture --test-threads=1`
  - `1,000,000 compared, 0 divergences vs host glibc`
- RCH `vmi1227854`: `cargo check -j 1 -p frankenlibc-core --lib`

Broader gates with unrelated existing blockers:

- RCH `vmi1227854`: `cargo check -j 1 -p frankenlibc-core --all-targets`
  failed in untouched `crates/frankenlibc-core/tests/strftime_buffer_differential_probe.rs`
  because `BrokenDownTime` initializers are missing `tm_gmtoff` and `zone`; it also
  reported an untouched `unused_mut` warning in `wcsnlen_fold_isomorphism.rs`.
- RCH `vmi1227854`: `cargo clippy -j 1 -p frankenlibc-core --lib -- -D warnings`
  initially flagged the new collapsible `conversion.rs` branch; that was fixed.
  Remaining failures are unrelated existing lib lints in `math/exp.rs`,
  `stdlib/sort.rs`, `string/fnmatch.rs`, and `string/regex.rs`.

Golden/source sha256 after final source:

```text
1177550d12d64974bc36009cee622695a24483334f6f4c7b22c1d01bdfff41a8  tests/conformance/fixtures/stdlib_numeric.json
f3bb74a46d2b82a78196f2a97e98ef35e5ee13d1438e2e73fdcc8585bdeac783  crates/frankenlibc-abi/tests/conformance_diff_stdlib_numeric.rs
2095322a20aedc8951020e69ccf4c6c878834fad9524e6fd95c23218f381ee84  crates/frankenlibc-abi/tests/strtol_family_differential_fuzz.rs
a014dffd01c4f04d501199f81ef8c6a4e66693431b0b8c72c9e816b1bd8bb935  crates/frankenlibc-core/src/stdlib/conversion.rs
```

## Isomorphism

For inputs covered by the new path, the old scalar loop would execute one or two
iterations with `acc = digit` or `acc = 10 * first + second`, set
`any_digits = true`, never overflow, stop at the same end/nondigit byte, and
return `ConversionStatus::Success`. The new path returns exactly that tuple.

All other inputs fall through to the pre-existing parser. That preserves:

- invalid-base validation before string inspection
- whitespace and sign scanning
- base-0, base-2, and base-16 prefix behavior
- long decimal SWAR parsing and overflow/underflow consumption
- no-digit consumption rules
- endptr offsets at the ABI layer
- FP/RNG: not applicable

