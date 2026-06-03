# bd-2g7oyh.20 wmemrchr bounded wide-char SIMD reverse equality panels

## Profile target

- Bead: `bd-2g7oyh.20`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wmemrchr` (bounded reverse wide-char search).
- Scenario: absent wide char, `s` filled with a non-matching wide char, `n == s.len()`
  (full reverse traversal — worst case).
- Command: `rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- wmemrchr_absent`

## Baseline p50 (scalar `(0..count).rev().find`)

| Bench | p50 ns/op |
| --- | ---: |
| `wmemrchr_absent_16` | 21.215 |
| `wmemrchr_absent_64` | 79.816 |
| `wmemrchr_absent_256` | 312.478 |
| `wmemrchr_absent_1024` | 1336.624 |
| `wmemrchr_absent_4096` | 4892.860 |

Root cause: the scalar reverse iterator `(0..count).rev().find(|&i| s[i] == c)` does not
autovectorize — each `u32` is compared one at a time walking backwards, the slowest of the
wide scan family (e.g. ~4x the forward `wmemchr` scalar at 4096).

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7,
Swiss Tables SIMD group probes (packed equality probe over a 256-bit lane group), applied
in reverse panel order.

- Primitive: rear-to-front panel equality probe over 8 contiguous `u32` lanes.
- Runtime artifact: safe-Rust `Simd<u32, 8>` `simd_eq().any()` probe over `rchunks_exact(8)`
  (reuses the `WIDE_SIMD_LANES = 8` idiom shared with `wcslen`/`wcschr`/`wmemchr`/`wmemcmp`).
- Fallback: exact scalar right-to-left resolution within the first candidate panel and over
  the front remainder; revert if the golden oracle changes or p50 regresses.
- EV score: Impact 4 x Confidence 5 / Effort 1 = 20.0.

## One lever

Rewrote `wmemrchr` from the scalar reverse iterator to a `Simd<u32, 8>` reverse equality
panel scan: `rchunks_exact(8)` walks panels from the end; `lanes.simd_eq(splat(c)).any()`
filters; the first (rear-most) candidate panel resolves its last match right-to-left; the
front remainder (`[0, end)`) is scanned scalar in reverse. `#![forbid(unsafe_code)]` holds —
portable `std::simd` only, no `unsafe`.

## Isomorphism proof

- Last-match semantics preserved: panels are visited rear-first; the first candidate panel is
  the rear-most one containing `c`, and it is resolved right-to-left, so the returned index is
  the greatest `i < count` with `s[i] == c` — identical to the scalar `.rev().find`.
- Bound preserved: scanning `s[..count]` (`count = n.min(s.len())`) keeps the exact clamp; a
  match at or beyond `n` is never read (covered by the `n`-bound assertions).
- Remainder correctness: `rchunks_exact` leaves the partial chunk at the front; `end` tracks
  its length and the scalar reverse loop covers `[0, end)` exactly once, no overlap with panels.
- High code points: `u32` lanes compare full 32-bit wide characters
  (covered by `prop_wmemrchr_matches_slice_rposition` over `any::<u32>()`).
- Floating-point: N/A. RNG: N/A.

## Golden behavior proof

- Added `prop_wmemrchr_matches_slice_rposition` (asserts `wmemrchr` ==
  `(0..n.min(len)).rev().find(|&i| s[i] == needle)` over arbitrary `u32` slices and `n`).
- Added `test_wmemrchr_simd_panel_boundary_and_remainder` covering last-match across rear
  panel / middle panel / front remainder, the `n` bound, and absent scans.
- `rch exec -- cargo test -p frankenlibc-core --lib string::wide`: 72/72 passed
  (70 prior + 2 new).

## Post benchmark

| Bench | Baseline p50 ns/op | Post p50 ns/op | Speedup |
| --- | ---: | ---: | ---: |
| `wmemrchr_absent_16` | 21.215 | 5.072 | 4.18x |
| `wmemrchr_absent_64` | 79.816 | 12.220 | 6.53x |
| `wmemrchr_absent_256` | 312.478 | 37.876 | 8.25x |
| `wmemrchr_absent_1024` | 1336.624 | 149.896 | 8.92x |
| `wmemrchr_absent_4096` | 4892.860 | 592.614 | 8.26x |

Score: dominant 4096 case 8.26x (>= 2.0); every size >= 4.18x.

## Validation

- `rch exec -- cargo test -p frankenlibc-core --lib string::wide` passed 72/72.
- `cargo fmt --check -p frankenlibc-core -p frankenlibc-bench` passed; `git diff --check` clean.

## Source

- Pre `wide.rs` sha256: `775bdf27582ececd732f61513eb4fb807da0b82781283af9d536d97bc2210f1a`
- Post `wide.rs` sha256: `a0e047e421aeeccef81b9e49d450e50f3da8f66d9674ee5e9d2417966301f7b1`
- Post `string_bench.rs` sha256: `6159ddbe8de4d63213f3624063886b30917451183fdc4f6c7751b03b5a158648`
