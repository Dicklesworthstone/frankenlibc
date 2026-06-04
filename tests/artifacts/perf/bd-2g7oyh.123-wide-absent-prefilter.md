# bd-2g7oyh.123 wide absent prefilter

## Target

`crates/frankenlibc-core/src/string/wide.rs::{wcschr,wcsrchr,wcsstr}`.

Fresh RCH reprofile after `170813dc` showed a peer-free wide-string residual
cluster where the absent C-string scans paid both the SIMD target search and
the NUL sentinel search:

| bench | p50 ns/op | mean ns/op |
| --- | ---: | ---: |
| `wcsstr_absent_4096` | 356.427 | 364.577 |
| `wcsrchr_absent_4096` | 353.993 | 355.593 |
| `wcschr_absent_4096` | 353.000 | 364.071 |

The same profile showed the one-target bounded wide-memory scans were already
materially faster:

| bench | p50 ns/op | mean ns/op |
| --- | ---: | ---: |
| `wmemchr_absent_4096` | 204.795 | 245.865 |
| `wmemrchr_absent_4096` | 205.414 | 210.622 |

## Baseline

Focused baseline before the edit:

```text
RCH_PREFERRED_WORKER=ts2 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pass8_wide_absent_baseline FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench string_bench -- 'wcschr_absent|wcsrchr_absent|wcsstr_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `ts2`.

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 343.218 | 350.651 | 410.414 | 345.132 |
| `wcsstr_absent_4096` | 351.963 | 372.616 | 437.022 | 354.719 |
| `wcschr_absent_4096` | 339.587 | 351.450 | 442.624 | 343.024 |

## Alien Primitive

Primitive: zero-copy bounded-memory prefilter in front of sentinel-aware C-string
resolution.

For nonzero needles, the lever first asks the existing bounded wide-memory
kernel whether the target value is present anywhere in the whole slice. A
whole-slice absence certificate proves the C-string result is `None` without
paying a second target-or-NUL scan. Any possible occurrence falls through to the
old C-string resolver.

## Isomorphism Proof

- `wcschr(s, 0)` and `wcsrchr(s, 0)` keep their previous NUL-specific paths.
- For `wcschr(s, c != 0)`, `wmemchr(s, c, s.len()).is_none()` means no element
  of the entire slice equals `c`; therefore no prefix before the first NUL can
  contain `c`, and returning `None` matches the old target-or-NUL resolver.
- If `wmemchr` finds any `c`, `wcschr` falls through to the old
  `find_wide_or_nul_long` path, preserving first-NUL cutoff and first-match
  tie-breaking.
- For `wcsrchr(s, c != 0)`, `wmemrchr(s, c, s.len()).is_none()` similarly
  proves no element of the entire slice equals `c`; therefore no last match can
  exist before the first NUL.
- If `wmemrchr` finds any `c`, `wcsrchr` falls through to the old forward
  sentinel-aware resolver, preserving last-before-NUL tie-breaking even when a
  later match appears after the first NUL.
- For `wcsstr`, the prefilter is only on the first non-NUL needle element. If
  that value is absent from the whole haystack, no substring match can exist
  before the haystack NUL. If it is present anywhere, the old
  `find_wide_or_nul_long`, `wcslen`, and two-way search path runs unchanged,
  preserving leftmost match ordering and all NUL cutoff behavior.
- Floating-point and RNG behavior are not involved.

Golden output SHA-256:
`5386e6e132c041340e2310b6c14834333ff391547e60e92f96a4da5b28f582ec`.

The golden corpus covers empty slices, NUL-only slices, present-before-NUL,
present-after-NUL, NUL-before-needle, no-NUL, repeated matches, long absent,
long present, and high `u32` values for `wcschr`, `wcsrchr`, and `wcsstr`.

## Post Benchmark

Same-worker postbench:

```text
RCH_PREFERRED_WORKER=ts2 RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pass8_wide_absent_post FRANKENLIBC_BENCH_PIN=1 cargo bench -p frankenlibc-bench --bench string_bench -- 'wcschr_absent|wcsrchr_absent|wcsstr_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot
```

Worker: `ts2`.

| bench | pre p50 | post p50 | pre mean | post mean | p50 speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 343.218 | 202.513 | 345.132 | 203.914 | 1.69x |
| `wcsstr_absent_4096` | 351.963 | 213.288 | 354.719 | 220.466 | 1.65x |
| `wcschr_absent_4096` | 339.587 | 211.672 | 343.024 | 214.446 | 1.60x |

Score: `(Impact 4.0 * Confidence 4.0) / Effort 2.0 = 8.0`, keep.

## Validation

- `rustfmt --edition 2024 crates/frankenlibc-core/src/string/wide.rs`: passed.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`:
  passed.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs tests/artifacts/perf/bd-2g7oyh.123-wide-absent-prefilter.md .beads/issues.jsonl`:
  passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pass8_golden_fixed cargo test -p frankenlibc-core --lib golden_wide_absent_prefilter_corpus_sha256 -- --nocapture`:
  passed on `ts2`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pass8_wcs_tests cargo test -p frankenlibc-core --lib wcs -- --nocapture`:
  passed on `ts2`, 90 tests.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pass8_check cargo check -p frankenlibc-core --all-targets`:
  passed on `ts2`.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env CARGO_TARGET_DIR=/data/tmp/rch_target_frankenlibc_pass8_clippy cargo clippy -p frankenlibc-core --all-targets -- -D warnings -A clippy::question_mark -A clippy::too_many_arguments -A clippy::collapsible_if -A clippy::unnecessary_cast -A clippy::type_complexity -A clippy::byte_char_slices -A clippy::manual_repeat_n -A clippy::approx_constant -A clippy::unnecessary_min_or_max -A clippy::manual_memcpy -A clippy::needless_range_loop`:
  passed on `ts2`.
