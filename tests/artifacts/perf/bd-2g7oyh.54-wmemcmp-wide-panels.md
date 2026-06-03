# bd-2g7oyh.54 wmemcmp 16-lane equality panels

## Target

`crates/frankenlibc-core/src/string/wide.rs::wmemcmp`.

After `bd-2g7oyh.53`, no unclaimed perf child beads were ready. Allocator work
was owned by MossyFern and `str.rs` strlen work was owned by BlackThrush, so the
next pass re-profiled unowned wide-string surfaces only.

## Baseline

RCH profile command before edit:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemcmp_equal|wmemchr_absent|wmemrchr_absent|wcslen|wcschr_absent|wcsrchr_absent|wcsstr_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1153651`.

Top unowned rows:

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wmemcmp_equal_4096` | 648.137 | 1436.853 | 1710.792 | 723.135 |
| `wcsrchr_absent_4096` | 629.831 | 922.000 | 1747.784 | 676.066 |
| `wcsstr_absent_4096` | 582.355 | 712.578 | 792.000 | 573.072 |
| `wmemrchr_absent_4096` | 444.682 | 876.598 | 1710.992 | 542.306 |
| `wmemchr_absent_4096` | 421.000 | 774.053 | 1383.236 | 479.404 |
| `wcslen_4096` | 402.136 | 502.469 | 702.000 | 420.728 |

Focused baseline rows used for this bead:

| bench | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wmemcmp_equal_16` | 6.080 | 34.398 | 141.000 | 12.561 |
| `wmemcmp_equal_64` | 14.560 | 34.007 | 260.000 | 22.025 |
| `wmemcmp_equal_256` | 46.079 | 85.000 | 241.000 | 52.882 |
| `wmemcmp_equal_1024` | 192.030 | 428.750 | 771.000 | 236.973 |
| `wmemcmp_equal_4096` | 648.137 | 1436.853 | 1710.792 | 723.135 |

## Alien Primitive

Primitive: vectorized execution / blocked equality kernel amortization.

The prior `wmemcmp` loop filtered equality eight `u32` lanes at a time. This
lever widens only the equality filter to sixteen `u32` lanes, then preserves the
unchanged scalar resolver inside the first mismatching panel. The proof
obligation is the equality monoid identity:

```text
all_equal(A ++ B, C ++ D) == all_equal(A, C) && all_equal(B, D)
```

Because the widened filter only skips panels where every lane is equal, the
first non-equal lane is still found by the same left-to-right scalar scan inside
the first non-equal chunk.

## Implementation

- Added `WIDE_COMPARE_SIMD_LANES = 16`.
- Switched only `wmemcmp` chunking and `Simd<u32, _>` construction from
  `WIDE_SIMD_LANES` to `WIDE_COMPARE_SIMD_LANES`.
- Left `wcschr`, `wcsrchr`, `wcsstr`, `wmemchr`, and `wmemrchr` on the existing
  8-lane panel size.

## Isomorphism Proof

- `count = n.min(s1.len()).min(s2.len())` is unchanged, so truncation and empty
  cases are unchanged.
- Equal 16-lane chunks are skipped only when all sixteen pairwise comparisons
  are equal. This is equivalent to skipping two equal 8-lane chunks.
- The first mismatching widened chunk is still scanned left-to-right with the
  existing scalar `i32` cast and `if a < b { -1 } else { 1 }` return.
- Signed Linux `wchar_t` ordering is unchanged because the scalar resolver is
  unchanged.
- Remainder handling is unchanged except the remainder is now modulo 16 instead
  of modulo 8; it still scans left-to-right over the exact remaining prefix.
- Equality return remains `0` only after every compared element was equal.
- Floating-point and RNG behavior are not involved.

## Post Benchmark

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench wmemcmp_equal -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Worker: `vmi1156319`. `rch exec` did not expose a worker pin; this post worker
differed from the baseline worker, so the keep decision uses the full size
curve and records the worker caveat.

| bench | pre p50 | post p50 | pre mean | post mean | p50 speedup |
| --- | ---: | ---: | ---: | ---: | ---: |
| `wmemcmp_equal_16` | 6.080 | 6.843 | 12.561 | 9.816 | 0.89x |
| `wmemcmp_equal_64` | 14.560 | 11.423 | 22.025 | 15.958 | 1.27x |
| `wmemcmp_equal_256` | 46.079 | 27.531 | 52.882 | 32.826 | 1.67x |
| `wmemcmp_equal_1024` | 192.030 | 85.908 | 236.973 | 89.267 | 2.24x |
| `wmemcmp_equal_4096` | 648.137 | 383.507 | 723.135 | 395.594 | 1.69x |

The 16-element p50 row is noisy and slightly slower, but p95, p99, and mean
improved there; every size >=64 improved on p50 and mean. Target row
`wmemcmp_equal_4096` improved materially.

Score: `(Impact 2.0 * Confidence 3.0) / Effort 1.0 = 6.0`, keep.

## Validation

- Pre source hash: `b82f2feb8929df40630579ab6a3f50ceecfbda8d044c95c2174a7052e7f0535f`.
- Post source hash: `2ca7c9edb1ffdc907236064e59cca02c51fb5b0df9ac6de42ff6792f043f87dd`.
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
  `crates/frankenlibc-core/src/stdlib/sort.rs:1002`; no `wide.rs` lint was
  reported before the external failure.
- `cargo fmt --check`: blocked by unrelated dirty formatting in peer-touched
  files, including `crates/frankenlibc-abi/tests/conformance_diff_mb_utf8_rfc2279.rs`,
  `crates/frankenlibc-core/src/stdlib/sort.rs`,
  `crates/frankenlibc-core/src/string/mem.rs`, and several
  `crates/frankenlibc-harness/tests/*` files; touched `wide.rs` passed direct
  rustfmt.
