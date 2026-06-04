# bd-2g7oyh.121 wcsncasecmp 64-wide repeated casefold certificate

## Profile target

- Source: clean RCH reprofile after `bd-lip5k8` on worker `ts2`.
- Target row: `wcsncasecmp_simd_4096`, p50 `405.869 ns/op`, mean `411.167 ns/op`.
- Focused pre-edit baseline on unmodified `bf5371e6`, worker `ts2`:
  - `wcsncasecmp_simd_4096`: p50 `423.877 ns/op`, p95 `522.648`, p99 `633.276`, mean `436.199`.

## Lever

One safe-Rust lever in `crates/frankenlibc-core/src/string/wide.rs`:

- Add a 64-wide repeated casefold run certificate before the existing 32-wide certificate.
- The certificate advances only when both panels are one repeated non-NUL code unit and `simple_towlower(first_a) == simple_towlower(first_b)`.
- The first uncertain panel still falls through to the existing fold-equal panel scan and scalar resolver.

## Behavior proof

- Ordering/tie-breaking: unchanged; any non-certified panel is resolved by the existing left-to-right scalar tail.
- NUL semantics: unchanged; the 64-wide certificate rejects `first_a == 0`, and repeated equality to a non-NUL first value proves the panel has no NUL.
- Casefold semantics: unchanged; the certificate uses the same `simple_towlower` relation as the scalar resolver.
- Floating point/RNG: not involved.
- Golden SHA: `golden_wide_casefold_compare_corpus_sha256 = e3cef37478ec7090a742821c4489a19cfba9e9d1f23b7237517847ad78b785ac`.

## RCH validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`: pass.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs .beads/issues.jsonl`: pass.
- RCH `ts1`: `cargo test -p frankenlibc-core --lib golden_wide_casefold_compare_corpus_sha256 -- --nocapture`: pass.
- RCH `ts2`: `cargo test -p frankenlibc-core --lib casecmp -- --nocapture`: pass, 7 tests.
- RCH `vmi1153651`: `cargo check -p frankenlibc-core --all-targets`: pass.
- RCH `ts2`: `cargo clippy -p frankenlibc-core --all-targets -- -D warnings` with pre-existing unrelated lint-family allowances: pass.

## RCH postbench

Cross-worker postbench on `vmi1227854`:

- `wcsncasecmp_simd_4096`: p50 `195.284 ns/op`, p95 `232.799`, p99 `265.694`, mean `199.505`.

Same-worker confirmation on `ts2`:

- Baseline `wcsncasecmp_simd_4096`: p50 `423.877 ns/op`, mean `436.199`.
- Post `wcsncasecmp_simd_4096`: p50 `341.875 ns/op`, p95 `358.014`, p99 `460.344`, mean `347.179`.
- Speedup: p50 `1.24x`, mean `1.26x`.
- Score: `(Impact 3 * Confidence 4) / Effort 2 = 6.0`, kept.
