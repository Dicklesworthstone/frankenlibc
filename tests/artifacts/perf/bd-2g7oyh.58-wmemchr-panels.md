# bd-2g7oyh.58 - wmemchr forward SIMD panels

## Target

- Bead: `bd-2g7oyh.58`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wmemchr`
- Profile source: RCH post-commit re-profile after `9be62578`
- Baseline command:
  `AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemchr_absent|wmemrchr_absent|wcslen|wcschr_absent|wcsrchr_absent|wcsstr_absent|wmemcmp_equal|memchr_absent|memcmp|strlen|strchr_absent|strrchr_absent|strstr_absent|strnstr_bounded_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot`
- Baseline worker: `vmi1227854`

Top post-profile rows before this lever:

| bench | p50 ns/op | mean ns/op |
| --- | ---: | ---: |
| `wcsrchr_absent_4096` | 303.446 | 304.395 |
| `wmemchr_absent_4096` | 298.126 | 285.620 |
| `wcsstr_absent_4096` | 244.052 | 257.594 |
| `wcschr_absent_4096` | 236.387 | 244.351 |
| `wmemcmp_equal_4096` | 229.515 | 231.945 |
| `wcslen_4096` | 208.085 | 209.257 |
| `wmemrchr_absent_4096` | 142.257 | 149.976 |

The top row was `wcsrchr`, but `wmemchr` was the highest unoptimized equality-scan surface: it still used 8-lane panels while the reverse `wmemrchr` path had just proven 16-lane panels profitable.

## Lever

Widen only the forward `wmemchr` equality filter from `Simd<u32,8>` panels to `Simd<u32,16>` panels via a dedicated `WIDE_MEMCHR_SIMD_LANES` constant.

The scalar resolver for the first candidate panel stays left-to-right and unchanged.

Alien primitive: vectorized execution / blocked kernel amortization and SIMD group probing from `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` sections 7.7 and 8.2.

## Isomorphism Proof

- Bounded prefix is unchanged: both versions search exactly `s[..n.min(s.len())]`.
- Clean 16-lane panel skip is equivalent to two adjacent clean 8-lane skips for the exact predicate `x == c`.
- Candidate resolution is unchanged: the first positive SIMD panel is still scanned scalar left-to-right, preserving first-match ordering and leftmost-match tie-breaking.
- Remainder handling is unchanged apart from a smaller front/rear split: `chunks.remainder()` still covers the exact suffix after all full panels and scans left-to-right.
- No-match behavior is unchanged because every element in the bounded prefix is either inside one full panel or the exact remainder.
- Floating-point and RNG behavior are not involved.

## Golden Sha256

Baseline source hash:

```text
0812c45a421b6ccc67bc75436db80861051a93c731a145b67a43d520636e5d5f  crates/frankenlibc-core/src/string/wide.rs
```

Post source hash:

```text
942caa1d266331a3ea8667b18bb250f12b5831c13fe93b1d54401b1f666f0cf0  crates/frankenlibc-core/src/string/wide.rs
```

Golden verification, before and after:

```text
fixture_verify_strict_hardened.v1.md: OK
fixture_verify_strict_hardened.v1.json: OK
```

## Benchmark

Post command:
`AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemchr_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot`

Post worker: `vmi1149989`

| bench | baseline p50 | post p50 | p50 speedup | baseline mean | post mean |
| --- | ---: | ---: | ---: | ---: | ---: |
| `wmemchr_absent_16` | 2.203 | 1.670 | 1.32x | 5.726 | 9.924 |
| `wmemchr_absent_64` | 5.893 | 3.648 | 1.62x | 11.817 | 8.392 |
| `wmemchr_absent_256` | 15.899 | 8.750 | 1.82x | 23.126 | 13.961 |
| `wmemchr_absent_1024` | 55.042 | 36.227 | 1.52x | 65.884 | 42.926 |
| `wmemchr_absent_4096` | 298.126 | 157.586 | 1.89x | 285.620 | 164.494 |

The post run used a different RCH worker than the baseline, so confidence is discounted. The size curve still shows consistent p50 wins across all lengths and a 4096-element mean win.

Score: `(Impact 2.0 * Confidence 2.0) / Effort 1.0 = 4.0`, keep.

## Validation

- Direct `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`: passed.
- Direct `git diff --check -- crates/frankenlibc-core/src/string/wide.rs`: passed.
- RCH `cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture`: passed, 73/73.
- RCH `cargo check -p frankenlibc-core --all-targets`: passed.
- RCH `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated peer changes:
  - `crates/frankenlibc-core/src/malloc/allocator.rs:72` `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/malloc/allocator.rs:78` `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/stdlib/sort.rs:1000` `clippy::unnecessary_cast`
- Workspace `cargo fmt --check`: blocked by unrelated peer formatting in ABI/core/harness files; `wide.rs` itself passed direct rustfmt.
