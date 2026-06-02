# bd-2g7oyh.7 wcsstr absent first-wide-char SIMD probe

## Profile target

- Bead: `bd-2g7oyh.7`
- Target: `crates/frankenlibc-core/src/string/wide.rs::wcsstr` (first-wide-char candidate scan).
- Scenario: absent wide needle, haystack filled with a non-matching wide char.
- Baseline command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'wcsstr_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Worker: `vmi1153651`

## Baseline p50 (same-worker clean tree)

| Bench | p50 ns/op |
| --- | ---: |
| `wcsstr_absent_16` | 15.702 |
| `wcsstr_absent_64` | 55.208 |
| `wcsstr_absent_256` | 234.872 |
| `wcsstr_absent_1024` | 902.823 |
| `wcsstr_absent_4096` | 3589.903 |

Root cause: the first-wide-character scan walked the `u32` haystack one element at a time
(`for i in 0..haystack.len()`), so absent-needle scans paid a scalar compare per code point.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7, Swiss Tables SIMD group probes.

Recommendation card:

- Primitive: packed group probe over 8 contiguous `u32` wide characters (256-bit panel), adapted from hash-map control-byte probes to the wide string itself as its own control plane.
- Runtime artifact: private safe-Rust `Simd<u32, 8>` first-wide-char-or-NUL candidate finder (`find_wide_or_nul`).
- Fallback: exact scalar full-needle verification on every candidate panel; revert if golden output hash changes or p50 target regresses.
- EV score: Impact 4 x Confidence 5 / Effort 2 = 10.0.

## One lever

Added a safe `Simd<u32, 8>` first-wide-char-or-NUL panel filter (`has_wide_or_nul_simd` /
`find_wide_or_nul`) and rewrote the `wcsstr` first-character scan to jump panel-at-a-time to the
next candidate, keeping the exact scalar full-needle comparison untouched. `#![forbid(unsafe_code)]`
holds — portable `std::simd` only, no `unsafe`.

## Isomorphism proof

- Ordering preserved: the SIMD helper only skips panels where every element is proven neither NUL nor equal to the first needle character. Candidate panels resolve left-to-right at the first matching index — identical to the original linear scan.
- NUL ordering preserved: NUL (`0u32`) is part of the SIMD predicate and the scalar resolution tests `ch == 0` before `ch == needle`, so a NUL wins over any later first-char hit in the same panel, exactly as the original `if ch == 0 { return None; }` did. `first` is guaranteed non-zero (needles with a leading NUL take the `needle_len == 0` early return), so the two splat targets are distinct.
- First-full-match tie-break unchanged: a failed first-char candidate still runs the original scalar full-needle comparison and resumes the search at `i + 1`, preserving the first full match.
- Unterminated slices preserved: when the remainder holds neither the first char nor a NUL, `find_wide_or_nul` returns `s.len()` and the loop returns `None`; exact matches at the slice end still succeed; too-short candidates still return `None` without reads past `haystack.len()`.
- High code points: `u32` lanes compare full 32-bit wide characters, so non-ASCII / astral code points (e.g. `0x1_F600`) match exactly as before.
- Floating-point: N/A. RNG: N/A.

## Golden behavior proof

- Pre-existing `wcsstr` test source (4 functions) sha256 unchanged HEAD vs working tree: `e40630074c5e0f909bc4b7b5eb580375d0dae8a2009d53657e9b0cdc1b719cb5` — existing assertions byte-identical.
- Post full `wcsstr` test-line sha256 (existing + 5 new SIMD tests): `0087855eb3424ea521796ce886914d224881db68328e0ea0eac056f28b407eb6`.
- `cargo test -p frankenlibc-core --lib string::wide` passed 62/62 (includes new NUL-precedence, panel-boundary, tie-break, and high-code-point tests).

## Post benchmark

- Command: same as baseline. Worker: `vmi1153651`.

| Bench | Baseline p50 ns/op | Post p50 ns/op | Delta |
| --- | ---: | ---: | ---: |
| `wcsstr_absent_16` | 15.702 | 4.594 | 3.42x faster |
| `wcsstr_absent_64` | 55.208 | 9.114 | 6.06x faster |
| `wcsstr_absent_256` | 234.872 | 29.367 | 8.00x faster |
| `wcsstr_absent_1024` | 902.823 | 108.215 | 8.34x faster |
| `wcsstr_absent_4096` | 3589.903 | 418.849 | 8.57x faster |

Score: the dominant 4096 case is 8.57x (>= 2.0); every size >= 64 is >= 6x.

## Validation

- `rch exec -- cargo test -p frankenlibc-core --lib string::wide` passed 62/62.
- `rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings` passed (exit 0; only an unrelated build-script "no SMT solver" note).
- `cargo fmt --check -p frankenlibc-core` passed locally.
- `git diff --check` passed.

## Source

- Pre `wide.rs` sha256: `b871479e75c4c0f8b0fb4afdaf438bcc3bbb3542dd080103699420f7aa403965`
- Post `wide.rs` sha256: `652de4347be0c6aee9be0098d6221b5cdeb0e9c7abdb075eaea9e472f9585138`
