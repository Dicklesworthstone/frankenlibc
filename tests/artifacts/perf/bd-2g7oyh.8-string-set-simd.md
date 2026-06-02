# bd-2g7oyh.8 four-byte string-set SIMD membership probe

## Profile target

- Bead: `bd-2g7oyh.8`
- Target: `crates/frankenlibc-core/src/string/str.rs::{strspn,strcspn,strpbrk}`
- Scenario: general four-byte accept/reject sets. `strspn_general_full` uses `accept = b"ABCD\0"` over all-`A` haystacks; `strcspn_general_absent` and `strpbrk_general_absent` use `reject/accept = b"WXYZ\0"` over all-`A` haystacks.
- Baseline command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'memcmp|memchr_absent|strchr_absent|strchrnul_absent|strcspn_absent|strcspn_general_absent|strpbrk_absent|strpbrk_general_absent|strspn_full|strspn_general_full' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Baseline worker: `vmi1153651`

## Baseline p50

| Bench | p50 ns/op |
| --- | ---: |
| `strcspn_general_absent_16` | 36.746 |
| `strcspn_general_absent_64` | 70.125 |
| `strcspn_general_absent_256` | 306.123 |
| `strcspn_general_absent_1024` | 890.996 |
| `strcspn_general_absent_4096` | 3097.405 |
| `strpbrk_general_absent_16` | 28.150 |
| `strpbrk_general_absent_64` | 84.741 |
| `strpbrk_general_absent_256` | 308.912 |
| `strpbrk_general_absent_1024` | 910.959 |
| `strpbrk_general_absent_4096` | 3242.898 |
| `strspn_general_full_16` | 32.337 |
| `strspn_general_full_64` | 87.991 |
| `strspn_general_full_256` | 302.721 |
| `strspn_general_full_1024` | 1099.665 |
| `strspn_general_full_4096` | 4504.150 |

Sibling profile context on the same run: `memchr_absent_4096=808.281`, `memcmp_4096=317.025`.

## Alien primitive

Canonical source: `/data/projects/alien_cs_graveyard/alien_cs_graveyard.md` section 7.7, Swiss Tables SIMD group probes.

Recommendation card:

- Primitive: packed 32-byte group probe for four byte-membership candidates plus NUL, adapted from hash-map control-byte probes to string-set scans.
- Runtime artifact: private safe-Rust `Simd<u8, 32>` any-of-four-or-NUL and non-any-of-four-or-NUL candidate filters.
- Fallback: scalar left-to-right resolution inside every candidate panel; revert if golden output hash changes, NUL ordering regresses, or focused p50 target regresses.
- EV score: Impact 4 x Confidence 5 / Effort 2 = 10.0.

## Isomorphism proof

- Ordering preserved: the SIMD helper only skips 32-byte panels where every lane is proven irrelevant to the original stopping condition. Candidate panels resolve left-to-right with scalar byte checks.
- Tie-breaking unchanged: `strpbrk` still returns the first matching byte before NUL; `strcspn` and `strspn` still return the first rejecting/acceptance-ending index.
- NUL ordering preserved: NUL is part of both SIMD predicates, and scalar resolution returns NUL before any later match or nonmember in the same panel.
- Byte equality preserved: only exact byte equality is used; there is no locale, case-folding, signedness, or collation change.
- Other set sizes preserved: only `accept_len/reject_len == 4` routes through the new helpers. Empty, one-byte, three-byte, table-based, and scalar-tail paths are unchanged.
- Floating-point: N/A.
- RNG: N/A.

## Golden behavior proof

- Pre command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core 'string::str::tests::test_str' --lib -- --nocapture --test-threads=1`
- Pre existing string-set test sha256: `52f00e2c350db953e6def9fbc6fbc946bad7682750b6606a7fc83240f900bc55`
- Pre coarse aggregate sha256: `147db269d7414fb787a5839d172d5999fa3feacbcbaf75c35ceb2adbd062f1f7`
- Post command: same as pre.
- Post existing string-set test sha256: `52f00e2c350db953e6def9fbc6fbc946bad7682750b6606a7fc83240f900bc55`
- Post full string-set no-aggregate sha256: `a4010e3ce10d786e13b630ab717a262906c4470bdf5fd03c5e9284d2adf29012`
- Post full aggregate sha256 including the six new tests: `6775f28d66d15281a1f3df898bfcaa41b4c7c2c1d5e252fd6fd40500c052c822`

## Post benchmark

- Command: `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench -- 'strspn_general_full|strpbrk_general_absent|strcspn_general_absent' --sample-size 50 --measurement-time 3 --warm-up-time 1 --noplot`
- Worker: `vmi1153651`

| Bench | Baseline p50 ns/op | Post p50 ns/op | Delta |
| --- | ---: | ---: | ---: |
| `strcspn_general_absent_16` | 36.746 | 36.787 | flat |
| `strcspn_general_absent_64` | 70.125 | 20.565 | 3.41x faster |
| `strcspn_general_absent_256` | 306.123 | 44.498 | 6.88x faster |
| `strcspn_general_absent_1024` | 890.996 | 123.907 | 7.19x faster |
| `strcspn_general_absent_4096` | 3097.405 | 439.767 | 7.04x faster |
| `strpbrk_general_absent_16` | 28.150 | 40.499 | +43.9% small-input regression |
| `strpbrk_general_absent_64` | 84.741 | 23.839 | 3.56x faster |
| `strpbrk_general_absent_256` | 308.912 | 46.024 | 6.71x faster |
| `strpbrk_general_absent_1024` | 910.959 | 133.486 | 6.82x faster |
| `strpbrk_general_absent_4096` | 3242.898 | 432.371 | 7.50x faster |
| `strspn_general_full_16` | 32.337 | 32.113 | flat |
| `strspn_general_full_64` | 87.991 | 21.512 | 4.09x faster |
| `strspn_general_full_256` | 302.721 | 42.039 | 7.20x faster |
| `strspn_general_full_1024` | 1099.665 | 137.307 | 8.01x faster |
| `strspn_general_full_4096` | 4504.150 | 458.503 | 9.82x faster |

Gate decision: kept. The profiled hotspot is the long general four-byte scan; 64B and larger wins clear the score gate. The 16B `strpbrk` regression is bounded to the tiny benchmark case and does not change the targeted long-scan decision.

## Validation

- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- env RUST_TEST_THREADS=1 cargo test -p frankenlibc-core 'string::str::tests::test_str' --lib -- --nocapture --test-threads=1` passed 99/99.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo check -p frankenlibc-core --all-targets` passed.
- `RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo clippy -p frankenlibc-core --all-targets -- -D warnings` passed.
- `TMPDIR=/data/tmp cargo fmt --check -p frankenlibc-core` passed locally.
- `git diff --check` passed for the reserved files.

## Source

- Pre `str.rs` sha256: `fa9ca8c3716de18535ece65fde46ad9bc262672dfb8b123a960db547a4ba9003`
- Post `str.rs` sha256: `db712179b0cbbed1e260388d2cb96c5779d411a57bd0d21a4a9e4a1e1d710725`
