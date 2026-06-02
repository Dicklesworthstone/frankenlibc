# bd-2g7oyh.6 strcasestr absent first-byte SIMD probe

## Profile target

- Bead: `bd-2g7oyh.6`
- Target: `crates/frankenlibc-core/src/string/str.rs::strcasestr`
- Scenario: absent ASCII case-insensitive needle, `needle = b"zq\0"`, haystack filled with `b'A'`.
- Baseline command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'strstr_absent|strnstr_bounded_absent|strcasestr_absent|wcsstr_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Baseline worker: `vmi1153651`

## Baseline p50

| Bench | p50 ns/op |
| --- | ---: |
| `strcasestr_absent_16` | 29.623 |
| `strcasestr_absent_64` | 95.585 |
| `strcasestr_absent_256` | 375.066 |
| `strcasestr_absent_1024` | 1404.287 |
| `strcasestr_absent_4096` | 6288.487 |

Sibling profile context on the same run: `strstr_absent_4096=4720.812`, `wcsstr_absent_4096=3044.435`, `strnstr_bounded_absent_4096=2889.390`.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7, Swiss Tables SIMD group probes.

Recommendation card:

- Primitive: packed group probe over 32 contiguous bytes, adapted from hash-map control-byte probes to the string itself.
- Runtime artifact: private safe-Rust `Simd<u8, 32>` first-byte-or-NUL candidate finder.
- Fallback: exact scalar verification on every candidate panel; revert if golden output hash changes or p50 target regresses.
- EV score: Impact 4 x Confidence 5 / Effort 2 = 10.0.

## Isomorphism proof

- Ordering preserved: the SIMD helper only skips panels where every byte is proven neither NUL nor ASCII-case-equal to the first needle byte. Candidate panels resolve left-to-right.
- Tie-breaking unchanged: false first-byte candidates still run the original scalar full-needle comparison, then search resumes at the next byte, preserving first full match.
- NUL ordering preserved: NUL is part of the SIMD predicate and wins over any later folded first-byte hit in the same panel.
- Unterminated slices preserved: exact matches at the slice end still succeed; too-short candidates still return `None` without synthetic reads past `haystack.len()`.
- Case folding preserved: only ASCII upper/lower pairs are folded; non-ASCII first bytes match exactly as before.
- Floating-point: N/A.
- RNG: N/A.

## Golden behavior proof

- Pre command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core strcasestr -- --nocapture --test-threads=1`
- Pre existing 7-test line sha256: `1c2254be74fa7e1a7cf6dd68001290fe83e8f2097a703967c48300fcc33c2b1c`
- Post command: same as pre.
- Post existing 7-test line sha256: `1c2254be74fa7e1a7cf6dd68001290fe83e8f2097a703967c48300fcc33c2b1c`
- Post full 11-test line sha256: `187c904c52d44834a3cef6f514c4455c096681323cd5a3d8ed3431e11340d877`

## Post benchmark

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- strcasestr_absent --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Worker: `vmi1153651`

| Bench | Baseline p50 ns/op | Post p50 ns/op | Delta |
| --- | ---: | ---: | ---: |
| `strcasestr_absent_16` | 29.623 | 30.425 | +2.7% noise |
| `strcasestr_absent_64` | 95.585 | 26.544 | 3.60x faster |
| `strcasestr_absent_256` | 375.066 | 66.875 | 5.61x faster |
| `strcasestr_absent_1024` | 1404.287 | 217.227 | 6.46x faster |
| `strcasestr_absent_4096` | 6288.487 | 845.828 | 7.44x faster |

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo test -p frankenlibc-core strcasestr -- --nocapture --test-threads=1` passed 11/11.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets` passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings` passed.
- `TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core` passed locally.
- `git diff --check` passed.

## Source

- Pre `str.rs` sha256: `b8916a39c9447328dbd20cbef14d7054362572683f2bba13c5ffc75fac2eac81`
- Post `str.rs` sha256: `fa9ca8c3716de18535ece65fde46ad9bc262672dfb8b123a960db547a4ba9003`
