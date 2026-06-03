# bd-2g7oyh.62 - wcsrchr long-panel scan

## Target

- Bead: `bd-2g7oyh.62`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wcsrchr`
- Final lever kept: add a 64-lane long-input panel filter for `wcsrchr` only.
- Rejected during exploration: applying the 64-lane panel to shared `find_wide_or_nul` regressed `wcsstr_absent_4096`, so that form was not kept.
- Alien primitive: hierarchical grouped vector probing with exact scalar candidate resolution.

## Baseline

Focused RCH baseline on worker `vmi1227854`:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcsrchr_absent|wcschr_absent|wcsstr_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Baseline target row:

| Benchmark | p50 | p95 | p99 | mean |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | `213.914` | `262.249` | `350.000` | `214.293` |

Baseline source hash:

```text
e9e94a1c03458a08ba3651e8fa353dfdc7ca0e559450aab63dcaa599c6c94226
```

## Final Benchmark

Final target-only RCH benchmark on the same worker `vmi1227854`:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcsrchr_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

| Benchmark | p50 | p95 | p99 | mean |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_16` | `14.703` | `37.377` | `411.000` | `24.538` |
| `wcsrchr_absent_64` | `5.985` | `17.500` | `60.000` | `8.133` |
| `wcsrchr_absent_256` | `14.230` | `22.250` | `101.000` | `16.675` |
| `wcsrchr_absent_1024` | `47.692` | `55.468` | `251.147` | `52.972` |
| `wcsrchr_absent_4096` | `171.739` | `198.678` | `220.000` | `171.863` |

Target-row speedup:

- p50: `213.914 -> 171.739` (`1.25x`)
- mean: `214.293 -> 171.863` (`1.25x`)

Post-change source hash:

```text
6a64c1852aeaeef240bc113df050bf2f82c6a90b9cd969ba5ffd2d8958e1c873
```

## Isomorphism Proof

- The NUL and needle predicate stayed exactly `ch == 0 || ch == c`.
- Clean 64-lane panel skips are equivalent to two adjacent clean 32-lane skips for the same predicate.
- Candidate panels still resolve scalar left-to-right, so last-match-before-NUL semantics are unchanged.
- The first NUL still returns the last match seen before the terminator.
- The unterminated case still returns the last match over the whole slice.
- `c == 0` behavior is unchanged and still uses the existing terminator path.
- `wcschr`, `wcsstr`, and `wmemcmp` were left on their prior code paths.
- Floating-point and RNG behavior are not involved.
- Golden fixture sha256 verification passed before and after.

Golden check:

```text
fixture_verify_strict_hardened.v1.md: OK
fixture_verify_strict_hardened.v1.json: OK
```

## Validation

- RCH `cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture` passed 73/73 on `vmi1227854`.
- RCH `cargo check -p frankenlibc-core --all-targets` passed on `vmi1149989`.
- RCH strict `cargo clippy -p frankenlibc-core --all-targets -- -D warnings` was blocked by unrelated existing lints:
  - `crates/frankenlibc-core/src/malloc/allocator.rs:72` `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/malloc/allocator.rs:78` `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/stdlib/sort.rs:1000` `clippy::unnecessary_cast`
- RCH `cargo clippy -p frankenlibc-core --lib -- -D warnings -A clippy::cmp_owned -A clippy::unnecessary_cast` passed on `vmi1227854`.
- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs` passed.
- Local `git diff --check -- crates/frankenlibc-core/src/string/wide.rs` passed.

## Score

Score: `(Impact 1.6 * Confidence 2.0) / Effort 1.0 = 3.2`, keep.

The target-row p50 and mean both improved by `1.25x` on the same RCH worker while preserving exact `wcsrchr` ordering semantics.
