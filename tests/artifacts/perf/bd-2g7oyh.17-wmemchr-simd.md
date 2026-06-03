# bd-2g7oyh.17 wmemchr bounded wide-char SIMD equality panels

## Profile target

- Bead: `bd-2g7oyh.17`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wmemchr` (bounded wide-char equality scan).
- Scenario: absent wide character, `s` filled with a non-matching wide char, `n == s.len()` (full traversal — worst case).
- Command: `rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- wmemchr_absent`
- Workers: `vmi1149989` (baseline), re-run post-change on the rch pool.

## Baseline p50 (scalar `.position`)

| Bench | p50 ns/op |
| --- | ---: |
| `wmemchr_absent_16` | 6.025 |
| `wmemchr_absent_64` | 20.898 |
| `wmemchr_absent_256` | 82.180 |
| `wmemchr_absent_1024` | 316.203 |
| `wmemchr_absent_4096` | 1216.607 |

Root cause: `s[..count].iter().position(|&x| x == c)` walked the `u32` slice one wide
character at a time, paying a scalar compare per code point on absent scans.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7,
Swiss Tables SIMD group probes.

- Primitive: packed group probe over 8 contiguous `u32` wide characters (256-bit panel),
  adapting hash-map control-byte probes to the wide slice as its own control plane.
- Runtime artifact: safe-Rust `Simd<u32, 8>` equality probe (reuses the existing
  `WIDE_SIMD_LANES = 8` idiom shared with `wcslen` / `wcschr` / `find_wide_or_nul`).
- Fallback: exact scalar left-to-right resolution on every candidate panel; revert if the
  golden oracle test changes or p50 regresses.
- EV score: Impact 4 x Confidence 5 / Effort 1 = 20.0.

## One lever

Rewrote `wmemchr` from the scalar `.position` scan to a `Simd<u32, 8>` equality panel scan:
`chunks_exact(8)`, `lanes.simd_eq(splat(c)).any()` panel filter, exact left-to-right
resolution within the first matching panel, scalar remainder. No NUL semantics — `wmemchr`
is a pure bounded equality search, simpler than the NUL-stopping `wcschr`.
`#![forbid(unsafe_code)]` holds — portable `std::simd` only, no `unsafe`.

## Isomorphism proof

- Equivalence: the scan operates on `&s[..n.min(s.len())]`, identical bound to the original
  `count = n.min(s.len())`. The SIMD probe only skips panels where every lane is proven not
  equal to `c`; candidate panels resolve left-to-right at the first `x == c`, returning the
  same index the scalar `.position` would. No match anywhere returns `None`.
- Bound preserved: an in-range match beyond `n` is never seen because the slice is truncated
  to `count` before scanning (covered by the `n=10` sub-bound assertion).
- High code points: `u32` lanes compare full 32-bit wide characters, so non-ASCII / astral
  code points match exactly as before (covered by `prop_wmemchr_matches_slice_position` over
  `any::<u32>()`).
- Floating-point: N/A. RNG: N/A.

## Golden behavior proof

- Pre-existing oracle test `prop_wmemchr_matches_slice_position` (asserts `wmemchr` ==
  `haystack[..n.min(len)].position(|&x| x == needle)` over arbitrary `u32` needles and `n`)
  is unchanged and passes against the new SIMD body.
- Added `test_wmemchr_simd_panel_boundary_and_remainder` covering the panel loop, panel
  boundary, scalar remainder, sub-panel `n`, and the `n`-below-len bound.
- `rch exec -- cargo test -p frankenlibc-core --lib string::wide`: 68/68 passed
  (67 prior + 1 new).

## Post benchmark

| Bench | Baseline p50 ns/op | Post p50 ns/op | Speedup |
| --- | ---: | ---: | ---: |
| `wmemchr_absent_16` | 6.025 | 2.576 | 2.34x |
| `wmemchr_absent_64` | 20.898 | 7.461 | 2.80x |
| `wmemchr_absent_256` | 82.180 | 23.681 | 3.47x |
| `wmemchr_absent_1024` | 316.203 | 92.532 | 3.42x |
| `wmemchr_absent_4096` | 1216.607 | 352.931 | 3.45x |

Score: dominant 4096 case 3.45x (>= 2.0); every size >= 2.34x.

## Validation

- `rch exec -- cargo test -p frankenlibc-core --lib string::wide` passed 68/68.
- `rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings` clean
  (exit 0; only an unrelated build-script "no SMT solver" note).

## Source

- Pre `wide.rs` sha256: `52a358eaa4e609ed5b937b583874036161343cac6034e457ba53f71cc2019bc1`
- Post `wide.rs` sha256: `fe9e9a06f7e9598196135a5ccf414ff8129ff12b454c4d4fe15f007b5e4d6b43`
- Post `string_bench.rs` sha256: `bed2ec613c573b32423ebac49ebc0ab89f6c41fcbe0aebc50faeab274535c7c3`
