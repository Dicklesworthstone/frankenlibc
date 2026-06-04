# bd-lip5k8 — wcsstr absent-first prefilter

## Target

Profile-backed pass 5 after `bd-2g7oyh.117`:

- Reprofile worker `ts2`: `wcsstr_absent_4096` p50 `526.566ns`, p95 `565.433ns`, p99 `651.000ns`, mean `532.286ns`.
- Focused RCH baseline worker `vmi1156319`: `wcsstr_absent_4096` p50 `563.941ns`, p95 `709.785ns`, p99 `1162.000ns`, mean `578.677ns`.

Benchmark corpus: haystack is all `L'A'`, needle is `L"ZQ"`, so the first needle code unit is absent before the terminating NUL.

## Lever

One lever: probe `haystack` for `needle[0]` or NUL before computing full haystack length.

- If the probe reaches slice end or NUL without seeing `needle[0]`, no match is possible and `wcsstr` returns `None`.
- If the probe finds `needle[0]`, `wcsstr` computes the NUL-bounded haystack length from that first candidate and starts the existing candidate loop there.
- The existing exact candidate check and Two-Way fallback remain unchanged.

## Isomorphism Proof

- Ordering/leftmost: positions before the first `needle[0]` cannot start a match, so starting at `first_pos` preserves leftmost match ordering.
- NUL semantics: if NUL appears before `needle[0]`, the C wide string ends before any possible match; returning `None` matches the old NUL-bounded path.
- Unterminated slices: if neither NUL nor `needle[0]` exists, the old path bounded the haystack at `haystack.len()` and returned `None`; the new path does the same.
- Candidate/tie behavior: once a first-character candidate exists, the existing exact slice comparison and Two-Way fallback are unchanged.
- Floating point/RNG: not applicable; this is integer wide-code-unit search only.

Golden output SHA:

- `golden_wcsstr_corpus_sha256`: `ab630f290976e1203e3d24cef20b2269486b92ce1ca4e1949cdaf4d3f38a4837`.

## Validation

- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`: pass.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs crates/frankenlibc-core/tests/property_tests.rs`: pass.
- RCH `ts2`: `cargo test -p frankenlibc-core --lib wcsstr -- --nocapture`: pass, 15/15.
- RCH `ts2`: `cargo check -p frankenlibc-core --all-targets`: pass.
- RCH `ts2`: `cargo clippy -p frankenlibc-core --all-targets -- -D warnings ...`: pass with unrelated existing lint families allowed.

## Rebench

Post RCH worker `ts2`:

- `wcsstr_absent_16`: p50 `21.463ns`, mean `24.004ns`.
- `wcsstr_absent_64`: p50 `12.302ns`, mean `16.730ns`.
- `wcsstr_absent_256`: p50 `28.389ns`, mean `30.825ns`.
- `wcsstr_absent_1024`: p50 `91.530ns`, mean `94.258ns`.
- `wcsstr_absent_4096`: p50 `359.310ns`, p95 `385.099ns`, p99 `465.725ns`, mean `363.896ns`.

Same-worker `ts2` comparison vs reprofile:

- p50 `526.566ns -> 359.310ns` (`1.47x`).
- mean `532.286ns -> 363.896ns` (`1.46x`).

Focused baseline comparison:

- p50 `563.941ns -> 359.310ns` (`1.57x`, cross-worker).
- mean `578.677ns -> 363.896ns` (`1.59x`, cross-worker).

Score: `(Impact 3 * Confidence 4) / Effort 2 = 6.0`, kept.
