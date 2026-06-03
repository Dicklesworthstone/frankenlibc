# bd-2g7oyh.59 - wcslen 16-lane NUL panels

## Target

- Bead: `bd-2g7oyh.59`
- Surface: `crates/frankenlibc-core/src/string/wide.rs::wcslen`
- Profile-backed baseline: RCH re-profile after commit `f0151c78` on `vmi1227854`
- Baseline row: `wcslen_4096` p50 `259.167 ns/op`, p95 `348.159`, p99 `5487.500`, mean `376.807`
- Peer-owned surfaces avoided: allocator/malloc for `bd-2g7oyh.51`; `str.rs` for `bd-2g7oyh.25`

## Lever

Widen only the `wcslen` NUL-only portable-SIMD panel from 8 `u32` lanes to a dedicated 16 `u32` lanes. The exact scalar resolver inside the first matching panel is unchanged.

Alien-graveyard primitive: vectorized execution plus SIMD group probing/block amortization. The wider panel halves horizontal reduction frequency on long absent-NUL scans while preserving the same exact predicate.

## Isomorphism Proof

- The SIMD probe predicate remains exactly `ch == 0`.
- A clean 16-lane panel skip is equivalent to two adjacent clean 8-lane skips for the same predicate.
- The first candidate panel still resolves with scalar left-to-right iteration, preserving first-NUL ordering and tie-breaking.
- Remainder handling still scans the exact suffix left-to-right from the same accumulated `base`.
- Floating-point behavior is not involved.
- RNG behavior is not involved.
- Error behavior and unterminated-slice return are unchanged: if no NUL is found, the function returns `s.len()`.

## Golden And Hash Proof

- Source before: `942caa1d266331a3ea8667b18bb250f12b5831c13fe93b1d54401b1f666f0cf0`
- Source after: `d15df1aea419aed7b33f8b0a64056699c9990175cd6f4e6483262ea45299482a`
- Golden command: `sha256sum -c sha256sums.txt` in `tests/conformance/golden`
- Golden before: `fixture_verify_strict_hardened.v1.md: OK`; `fixture_verify_strict_hardened.v1.json: OK`
- Golden after: `fixture_verify_strict_hardened.v1.md: OK`; `fixture_verify_strict_hardened.v1.json: OK`

## Benchmarks

Baseline command:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wmemchr_absent|wmemrchr_absent|wcslen|wcschr_absent|wcsrchr_absent|wcsstr_absent|wmemcmp_equal|memchr_absent|memcmp|strlen|strchr_absent|strrchr_absent|strstr_absent|strnstr_bounded_absent' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Final benchmark command:

```text
AGENT_NAME=BoldFalcon RCH_REQUIRE_REMOTE=1 RCH_VISIBILITY=summary rch exec -- cargo bench -p frankenlibc-bench --bench string_bench 'wcslen' -- --sample-size 20 --measurement-time 2 --warm-up-time 1 --noplot
```

Final run: RCH remote `vmi1227854`, exit 0.

| Bench | Baseline p50 | Final p50 | Baseline mean | Final mean |
| --- | ---: | ---: | ---: | ---: |
| `wcslen_16` | `1.484` | `1.893` | `4.391` | `4.251` |
| `wcslen_64` | `4.014` | `4.125` | `7.399` | `8.529` |
| `wcslen_256` | `16.891` | `11.519` | `20.415` | `15.651` |
| `wcslen_1024` | `60.057` | `41.161` | `60.555` | `45.422` |
| `wcslen_4096` | `259.167` | `175.188` | `376.807` | `205.655` |

Keep decision: keep. The target row improves p50 by `1.48x` and mean by `1.83x`.

Score: `(Impact 2.0 * Confidence 2.5) / Effort 1.0 = 5.0`.

## Validation

- Local `rustfmt --edition 2024 --check crates/frankenlibc-core/src/string/wide.rs`: pass
- Local `git diff --check -- crates/frankenlibc-core/src/string/wide.rs`: pass
- RCH `cargo test -p frankenlibc-core string::wide::tests:: -- --nocapture`: pass, 73 passed
- RCH `cargo check -p frankenlibc-core --all-targets`: pass
- RCH strict `cargo clippy -p frankenlibc-core --all-targets -- -D warnings`: blocked by unrelated peer-owned surfaces:
  - `crates/frankenlibc-core/src/malloc/allocator.rs:72`: `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/malloc/allocator.rs:78`: `clippy::cmp_owned`
  - `crates/frankenlibc-core/src/stdlib/sort.rs:1000`: `clippy::unnecessary_cast`
- RCH all-targets clippy with only those unrelated lints allowed: blocked by unrelated `crates/frankenlibc-core/tests/property_tests.rs:267` compile error for `format!("{:x}", hasher.finalize())`
- RCH lib-only clippy with only the unrelated lint classes allowed: pass
