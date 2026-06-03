# bd-2g7oyh.19 wmemcmp bounded wide-char SIMD equality panels

## Profile target

- Bead: `bd-2g7oyh.19`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wmemcmp` (bounded wide-char compare).
- Scenario: equal inputs, both slices filled with the same wide char, `n == len`
  (full traversal — worst case for a compare that returns on first mismatch).
- Command: `rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- wmemcmp_equal`

## Baseline p50 (scalar element-by-element)

| Bench | p50 ns/op |
| --- | ---: |
| `wmemcmp_equal_16` | 11.783 |
| `wmemcmp_equal_64` | 46.840 |
| `wmemcmp_equal_256` | 174.605 |
| `wmemcmp_equal_1024` | 677.478 |
| `wmemcmp_equal_4096` | 2627.354 |

Root cause: `for i in 0..count { if s1[i] != s2[i] { ... } }` compared one `u32`
wide character per iteration, paying a scalar compare per code point on equal scans.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7,
Swiss Tables SIMD group probes (packed equality probe over a 256-bit lane group).

- Primitive: panel equality probe over 8 contiguous `u32` lanes per operand.
- Runtime artifact: safe-Rust `Simd<u32, 8>` `simd_eq().all()` panel compare (reuses the
  `WIDE_SIMD_LANES = 8` idiom shared with `wcslen` / `wcschr` / `wmemchr`).
- Fallback: exact scalar signed resolution on the first mismatching panel; revert if the
  golden oracle changes or p50 regresses.
- EV score: Impact 4 x Confidence 5 / Effort 1 = 20.0.

## One lever

Rewrote `wmemcmp` from the scalar loop to a `Simd<u32, 8>` equality panel scan over
`s1[..count]` / `s2[..count]` (`count = n.min(s1.len()).min(s2.len())`, unchanged bound):
`av.simd_eq(bv).all()` skips equal panels; the first mismatching panel resolves
left-to-right with the original signed (`u32 as i32`) comparison; scalar remainder.
`#![forbid(unsafe_code)]` holds — portable `std::simd` only, no `unsafe`.

## Isomorphism proof

- Equivalence: equal panels are skipped only when every lane is proven equal, so the first
  mismatch the SIMD path resolves is the same index/ordering the scalar loop returned.
- Signedness preserved: the SIMD probe only detects (in)equality; the sign-sensitive verdict
  is still `if a < b { -1 } else { 1 }` on `i32`-cast operands. A wide char with the high bit
  set (`0x8000_0000`) sorts below a small positive one, identical to the scalar path
  (covered by `test_wmemcmp_simd_panel_boundary_and_signedness`).
- Bound preserved: scanning `s1[..count]`/`s2[..count]` keeps the exact `n`/shorter-slice
  clamp; a mismatch beyond `n` is never read (covered by the `n=8` sub-bound assertion).
- High code points: `u32` lanes compare full 32-bit wide characters
  (covered by `prop_wmemcmp_matches_scalar_oracle` over `any::<u32>()`).
- Floating-point: N/A. RNG: N/A.

## Golden behavior proof

- Added `prop_wmemcmp_matches_scalar_oracle` (asserts `wmemcmp` == scalar signed
  element-by-element compare over the common bound, for arbitrary `u32` slices and `n`).
- Added `test_wmemcmp_simd_panel_boundary_and_signedness` covering multi-panel equality,
  mismatch in first/later panel and remainder, signed ordering, and the `n` bound.
- `rch exec -- cargo test -p frankenlibc-core --lib string::wide`: 70/70 passed
  (68 prior + 2 new).

## Post benchmark

| Bench | Baseline p50 ns/op | Post p50 ns/op | Speedup |
| --- | ---: | ---: | ---: |
| `wmemcmp_equal_16` | 11.783 | 6.099 | 1.93x |
| `wmemcmp_equal_64` | 46.840 | 20.669 | 2.27x |
| `wmemcmp_equal_256` | 174.605 | 74.589 | 2.34x |
| `wmemcmp_equal_1024` | 677.478 | 339.996 | 1.99x |
| `wmemcmp_equal_4096` | 2627.354 | 1221.500 | 2.15x |

Score: dominant 4096 case 2.15x (>= 2.0); 256 2.34x, 64 2.27x.

## Validation

- `rch exec -- cargo test -p frankenlibc-core --lib string::wide` passed 70/70.
- `cargo fmt --check -p frankenlibc-core -p frankenlibc-bench` passed; `git diff --check` clean.

## Source

- Pre `wide.rs` sha256: `fe9e9a06f7e9598196135a5ccf414ff8129ff12b454c4d4fe15f007b5e4d6b43`
- Post `wide.rs` sha256: `775bdf27582ececd732f61513eb4fb807da0b82781283af9d536d97bc2210f1a`
- Post `string_bench.rs` sha256: `dc90aff35479a64945a5804937eed0bf72cd676917af7ef84079591abea61b8c`
