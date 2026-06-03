# bd-2g7oyh.56 wide char-or-NUL 16-lane panels

## Target

`crates/frankenlibc-core/src/string/wide.rs::{find_wide_or_nul,wcsrchr}`.

After `bd-2g7oyh.54`, allocator and `str.rs` were still owned by peer agents,
so this pass re-profiled unowned wide-string surfaces only.

## Baseline

RCH profile command before edit:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemchr_absent|wmemrchr_absent|wcslen|wcschr_absent|wcsrchr_absent|wcsstr_absent|wmemcmp_equal' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1149989`.

Top unowned 4096-wide rows:

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 316.732 | 896.375 | 3191.984 | 484.455 |
| `wmemchr_absent_4096` | 310.078 | 410.509 | 701.000 | 317.802 |
| `wcschr_absent_4096` | 288.502 | 345.500 | 2018.188 | 332.377 |
| `wcslen_4096` | 262.720 | 326.750 | 791.000 | 279.141 |
| `wcsstr_absent_4096` | 258.984 | 508.298 | 577.919 | 288.175 |

## Alien Primitive

Primitive: Swiss-table-style SIMD group probing / vectorized control-plane
scans from the alien graveyard. The data-plane invariant is that a widened
candidate filter may only skip a panel when no lane contains either the search
character or a terminator; exact position resolution stays scalar.

## Implementation

- Added `WIDE_FIND_SIMD_LANES = 16`.
- Switched only `has_wide_or_nul_simd`, `find_wide_or_nul`, and the non-NUL
  `wcsrchr` candidate scan from 8-lane to 16-lane panels.
- Left `wcslen`, `wmemchr`, `wmemrchr`, and `wmemcmp` panel widths unchanged.

## Isomorphism Proof

- `find_wide_or_nul` still returns the first index where `ch == needle || ch == 0`.
- A 16-lane clean skip is equivalent to two adjacent 8-lane clean skips because
  `none(A ++ B) == none(A) && none(B)` for the exact same predicate.
- Candidate panels still resolve left-to-right with the unchanged scalar loop,
  preserving first-match and NUL-before-match ordering for `wcschr` and `wcsstr`.
- The non-NUL `wcsrchr` path still records matches left-to-right within each
  candidate panel and stops immediately on the first NUL, preserving last match
  before terminator and unterminated-slice behavior.
- `c == 0` branches are unchanged: `wcschr` still delegates to `wcslen`, and
  `wcsrchr` still uses its existing scalar terminator branch.
- Bounded length behavior for `wmemchr`/`wmemrchr` is unchanged because those
  functions were not modified.
- Floating-point and RNG behavior are not involved.

## Post Benchmark

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcsrchr_absent|wcschr_absent|wcsstr_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1227854`. `rch exec` did not expose a worker pin; this post worker
differed from the baseline worker, so the keep decision records that caveat.

| bench | pre p50 | post p50 | pre p95 | post p95 | pre mean | post mean |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `wcsrchr_absent_4096` | 316.732 | 296.702 | 896.375 | 356.669 | 484.455 | 304.648 |
| `wcschr_absent_4096` | 288.502 | 272.522 | 345.500 | 327.693 | 332.377 | 275.554 |
| `wcsstr_absent_4096` | 258.984 | 263.840 | 508.298 | 330.500 | 288.175 | 270.957 |

Target `wcsrchr_absent_4096` improved on p50, p95, p99, and mean. `wcschr`
also improved on p50 and mean. `wcsstr` had a small p50 regression but improved
mean and tail rows.

Score: `(Impact 1.5 * Confidence 2.0) / Effort 1.0 = 3.0`, keep.

## Validation

- Pre source hash: `2ca7c9edb1ffdc907236064e59cca02c51fb5b0df9ac6de42ff6792f043f87dd`.
- Post source hash: `e107ee4df8c5390b9ed14f84899814ba3de469b8a4fbc7913421eb71f5712c8d`.
- `cd tests/conformance/golden && sha256sum -c sha256sums.txt`: passed before
  and after the edit.
- `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`:
  passed.
- `git diff --check -- crates/frankenlibc-core/src/string/wide.rs`: passed.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture`:
  passed, 73/73 wide tests.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets`:
  passed.
- `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings`:
  blocked by unrelated existing lints in
  `crates/frankenlibc-core/src/malloc/allocator.rs:72`, `:78`, and
  `crates/frankenlibc-core/src/stdlib/sort.rs:1000`; no `wide.rs` lint was
  reported before the external failure.
- `cargo fmt --check`: blocked by unrelated peer-dirty formatting in
  `crates/frankenlibc-abi/tests/conformance_diff_mb_utf8_rfc2279.rs`,
  `crates/frankenlibc-core/src/stdlib/sort.rs`,
  `crates/frankenlibc-core/src/string/mem.rs`, and several
  `crates/frankenlibc-harness/tests/*` files.
