# bd-2g7oyh.145: printf_g_6 rounded-scientific reuse

## Target

Profile-backed target: `glibc_baseline_printf_float/printf_g_6`, formatting
`12345.678901_f64` through `%.6g`.

RCH worker: `ts1`.

## Baseline

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ts1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd145_baseline cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'printf_g_6' --warm-up-time 1 --measurement-time 3 --sample-size 50 --noplot
```

Baseline result:

- FrankenLibC: p50 194.507ns, p95 224.484ns, p99 244.862ns, mean 201.364ns
- host glibc: p50 135.574ns, p95 148.252ns, p99 165.377ns, mean 139.653ns

## Lever

`format_g` already renders `value` once as rounded scientific notation to get
the post-rounding decimal exponent. The old path then rendered the value again
as fixed or exponent output.

This lever reuses the rounded scientific mantissa for both `%g` output styles:

- fixed style moves the decimal point through the rounded mantissa digits;
- exponent style normalizes the exponent sign/minimum width from the same
  rounded mantissa;
- the parse-failure fallback keeps the previous double-format behavior.

## Isomorphism Proof

- Ordering/tie-breaking: unchanged; digit rounding is still delegated to
  Rust's existing correctly-rounded scientific formatter at `p - 1` fractional
  digits, which was already used to determine the C `%g` post-rounding exponent.
- `%g` style choice: unchanged; still uses C11 rule `exp < -4 || exp >= p` for
  exponent style, where `exp` is the post-rounding decimal exponent.
- Alternate form: preserved; `#` keeps the decimal point and trailing zeros.
- Trailing zeros: preserved; non-`#` paths strip only fractional trailing zeros.
- Floating-point arithmetic: no new arithmetic in the hot path; the lever only
  repositions already-rounded decimal digits.
- RNG: not applicable.

## Verification

Commands:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ts1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd145_tests_g cargo test -p frankenlibc-core test_g_ -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ts1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd145_diff_final cargo test -p frankenlibc-core --test printf_float_differential_probe -- --nocapture --test-threads=1
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ts1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd145_check cargo check -p frankenlibc-core --all-targets
rustfmt --edition 2024 --check crates/frankenlibc-core/src/stdio/printf.rs
git diff --check -- crates/frankenlibc-core/src/stdio/printf.rs
```

Results:

- `test_g_`: passed 2 tests.
- `printf_float_differential_probe`: passed 1 glibc differential battery.
- `cargo check -p frankenlibc-core --all-targets`: passed.
- `rustfmt --check` on `printf.rs`: passed.
- `git diff --check` on `printf.rs`: passed.

`cargo clippy -p frankenlibc-core --all-targets -- -D warnings` was rerun after
fixing the only new `printf.rs` lint. It still fails on pre-existing unrelated
lints in `crates/frankenlibc-core/src/string/regex.rs` and
`crates/frankenlibc-core/src/string/wide.rs`.

Golden/reference files unchanged:

- `tests/conformance/fixtures/printf_conformance.json`
  `b8657a70042071e59636fe167d7ffdfb6ae25dab77a173056cec1465ae27c6ad`
- `tests/conformance/printf_float_precision_completion_contract.v1.json`
  `898394fd0601cbfb7ab265770d7a5995a025221b0767efa47b13323321987eb6`
- `crates/frankenlibc-core/tests/printf_float_differential_probe.rs`
  `153c94c5f1d7b5abf9ebaaa8547ec9e0c9e914ac94cd1712a809aaa0c3e13958`

`git diff --name-status` for those files was empty.

## Final Benchmark

Command:

```bash
RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary RCH_WORKER=ts1 rch exec -- env CARGO_TARGET_DIR=/tmp/rch_target_frankenlibc_bd145_post_final cargo bench -p frankenlibc-bench --bench glibc_baseline_bench -- 'printf_g_6' --warm-up-time 1 --measurement-time 3 --sample-size 50 --noplot
```

Final result:

- FrankenLibC: p50 136.080ns, p95 167.344ns, p99 210.500ns, mean 145.716ns
- host glibc: p50 139.321ns, p95 179.085ns, p99 184.454ns, mean 148.448ns

Improvement: 194.507ns -> 136.080ns p50, 1.43x faster on the same worker.

Score: Impact 3 x Confidence 3 / Effort 1 = 9.0. Kept.
