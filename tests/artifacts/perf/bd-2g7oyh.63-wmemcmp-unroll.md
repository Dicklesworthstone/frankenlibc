# bd-2g7oyh.63 - wmemcmp equal-prefix unrolled SIMD panels

Agent: BoldFalcon
Date: 2026-06-03
Skill loop: `/repeatedly-apply-skill` applying `/extreme-software-optimization`, pass 5
Bead: `bd-2g7oyh.63`

## Profile-backed target

Target: `crates/frankenlibc-core/src/string/wide.rs::wmemcmp`

Selection basis: re-profile after `bd-2g7oyh.62` on RCH worker `vmi1227854` showed `wmemcmp_equal_4096` as the top wide-string row:

| row | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wmemcmp_equal_4096` | 211.016 | 269.218 | 1110.492 | 237.592 |

Peer-owned surfaces avoided:

- allocator/malloc files reserved by MossyFern for `bd-2g7oyh.51`
- `crates/frankenlibc-core/src/string/str.rs` reserved by BlackThrush

## Lever

One lever only: keep the existing 16-lane `Simd<u32, 16>` comparison primitive, but unroll the equal-prefix scan to test two adjacent panels per loop iteration before entering scalar mismatch resolution.

This is a different primitive from the rejected `bd-2g7oyh.61` lane-width lever. The kept change does not widen the SIMD element count to 32 lanes; it uses two legal 16-lane panel checks and only reduces loop/control overhead on clean equal-prefix panels.

Source hashes:

- before: `6a64c1852aeaeef240bc113df050bf2f82c6a90b9cd969ba5ffd2d8958e1c873`
- after: `4be247b288d181f837c67c0d1b3bd67c2c14c217249f678bb0d2fe895500a4d9`

## Baseline

RCH command:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemcmp_equal' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Baseline rows from the post-`bd-2g7oyh.62` RCH profile:

| row | p50 ns/op | mean ns/op |
| --- | ---: | ---: |
| `wmemcmp_equal_16` | 4.095 | 6.130 |
| `wmemcmp_equal_64` | 6.859 | 9.048 |
| `wmemcmp_equal_256` | 17.007 | 20.549 |
| `wmemcmp_equal_1024` | 53.341 | 57.859 |
| `wmemcmp_equal_4096` | 211.016 | 237.592 |

## Re-benchmark

Final-source RCH benchmark on worker `vmi1227854`:

| row | p50 ns/op | p95 ns/op | p99 ns/op | mean ns/op |
| --- | ---: | ---: | ---: | ---: |
| `wmemcmp_equal_16` | 3.413 | 15.000 | 131.000 | 6.813 |
| `wmemcmp_equal_64` | 6.235 | 20.000 | 100.000 | 8.808 |
| `wmemcmp_equal_256` | 13.229 | 17.500 | 100.000 | 15.318 |
| `wmemcmp_equal_1024` | 47.843 | 62.750 | 221.000 | 52.917 |
| `wmemcmp_equal_4096` | 181.238 | 214.125 | 380.000 | 188.499 |

Speedups:

| row | p50 speedup | mean speedup |
| --- | ---: | ---: |
| `wmemcmp_equal_64` | 1.10x | 1.01x |
| `wmemcmp_equal_256` | 1.29x | 1.34x |
| `wmemcmp_equal_1024` | 1.11x | 1.09x |
| `wmemcmp_equal_4096` | 1.16x | 1.26x |

Small-row note: `wmemcmp_equal_16` p50 improved from `4.095` to `3.413`; mean increased from `6.130` to `6.813` under high-tail measurement noise. The target profile row and medium/large rows improved, so this lever is kept.

## Isomorphism proof

- Length bound is unchanged: `count = min(n, s1.len(), s2.len())`.
- A clean unrolled 32-element step is exactly two adjacent clean 16-element equality panels. Skipping both is equivalent to the old loop executing `continue` twice.
- If the first panel differs, `resolve_wmemcmp_panel(a_first, b_first)` scans scalar left-to-right before inspecting the second panel. This preserves first-difference ordering and tie-breaking.
- If the first panel is equal and the second differs, `resolve_wmemcmp_panel(a_second, b_second)` scans the second panel scalar left-to-right. This is equivalent to the old second loop iteration.
- Signed ordering is unchanged: each `u32` wide character is cast to `i32`, then returns `-1` if `a < b` and `1` otherwise.
- Remainder handling is unchanged in behavior: the pair remainder is fed through the existing 16-lane panel loop, then the scalar tail.
- Floating-point behavior is not involved.
- RNG behavior is not involved.

Golden-output sha256 verification:

- `fixture_verify_strict_hardened.v1.md`: OK before and after
- `fixture_verify_strict_hardened.v1.json`: OK before and after

## Validation

- RCH `cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture`: passed, 73/73 wide tests.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed.
- RCH strict `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked only by unrelated existing lint debt:
  - `crates/frankenlibc-core/src/malloc/allocator.rs:72` `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/malloc/allocator.rs:78` `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/stdlib/sort.rs:1000` `clippy::unnecessary_cast`
- RCH `cargo clippy -p frankenlibc-core --lib -- -D warnings -A clippy::cmp_owned -A clippy::unnecessary_cast`: passed.

## Keep decision

Score: `(Impact 1.5 * Confidence 2.0) / Effort 1.0 = 3.0`

Decision: keep and ship.

Next profile direction after commit: re-run the wide/byte string profile because the top target can move after the `wmemcmp` unroll. Candidate families to reassess are `wcsstr_absent_4096`, `wcschr_absent_4096`, `wcslen_4096`, and byte `strrchr`/`strchr` rows, but no next change should proceed without the new RCH profile.
